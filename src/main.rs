mod encryption;
mod hostname;
mod serveraddr;

use std::{
    env,
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use clap::Parser;
pub(crate) use hostname::Hostname;
use serveraddr::ServerAddr;

use mcproto::net::{
    handler_from_stream,
    state::{LoginState, StatusState},
};
use mcproto::packet::handshaking::Handshake;
use uuid::Uuid;

use color_eyre::{eyre::eyre, Result};
use tracing::{debug, info, info_span, trace, warn};

use num_bigint::BigInt;
use sha1::{Digest, Sha1};

use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address the Minecraft server should bind to
    server_address: ServerAddr,

    /// Url to forward status and login requests to
    destination_url: Url,
}

fn main() -> Result<()> {
    let args = setup()?;

    info!("Starting relay on {}...", args.server_address);
    let listener = TcpListener::bind(args.server_address)?;

    let key_pair = Arc::new(encryption::McKeyPair::generate()?);

    loop {
        let (stream, client_address) = listener.accept()?;

        let destination_url = args.destination_url.clone();
        let key_pair = key_pair.clone();

        thread::Builder::new()
            .name(format!("client({client_address})"))
            .spawn(move || {
                let span = info_span!("client", address = %client_address);
                let _enter = span.enter();

                handle_client(stream, &key_pair, destination_url).unwrap();
            })?;
    }
}

fn setup() -> Result<Args> {
    color_eyre::install()?;

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    Ok(Args::parse())
}

pub type NetworkHandler<S> = mcproto::net::NetworkHandler<mcproto::net::side::Server, S>;

fn handle_client(
    stream: TcpStream,
    key_pair: &encryption::McKeyPair,
    destination_url: Url,
) -> Result<()> {
    use mcproto::packet::handshaking::NextState;

    debug!("Connection accepted");

    stream.set_nodelay(true)?;
    let mut handler: NetworkHandler<_> = handler_from_stream(stream)?;

    let handshake: Handshake = handler.read()?;
    trace!(?handshake, "Recieved handshake packet");

    info!(next_state = ?handshake.next_state, "Client connected");

    match handshake.next_state {
        NextState::Status => handle_status(handler.status(), destination_url, handshake),
        NextState::Login => handle_login(handler.login(), key_pair, destination_url, handshake),

        NextState::Unknown(other) => Err(eyre!("client requested unknown next state: {other}")),
    }
}

fn handle_status(
    mut handler: NetworkHandler<StatusState>,
    destination_url: Url,
    handshake: Handshake,
) -> Result<()> {
    use mcproto::packet::status::{PingRequest, PingResponse, StatusRequest, StatusResponse};

    handler.read::<StatusRequest>()?;
    handler.write(StatusResponse {
        response: "\"todo\"".to_string(),
    })?;

    let ping: PingRequest = handler.read()?;
    handler.write(PingResponse {
        payload: ping.payload,
    })?;

    Ok(handler.close()?)
}

const MOJANG_HAS_JOINED_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined";

fn handle_login(
    mut handler: NetworkHandler<LoginState>,
    key_pair: &encryption::McKeyPair,
    destination_url: Url,
    handshake: Handshake,
) -> Result<()> {
    use mcproto::packet::login::{Disconnect, LoginStart};

    let login_start: LoginStart = handler.read()?;

    // technically the client part of the authentication is done in the middle
    // of encryption negotiations but this includes from the EncryptionRequest packet
    // to actually enabling encryption and the server auth comes after.
    let shared_secret = encryption::negotiate_encryption(key_pair, &mut handler)?;

    // generate the server hash
    let mut hasher = Sha1::new();
    hasher.update(b""); // server id, empty in "notchian" servers but kept for posterity/reference
    hasher.update(&shared_secret);
    hasher.update(key_pair.public_key_der());
    let server_hash = BigInt::from_signed_bytes_be(&hasher.finalize()).to_str_radix(16);

    // authenticate client with mojang
    let has_joined_url = Url::parse_with_params(
        MOJANG_HAS_JOINED_URL,
        &[
            ("username", &login_start.username),
            ("serverId", &server_hash),
        ],
    )?;

    let res = reqwest::blocking::get(has_joined_url)?.error_for_status()?;

    // client not authenticated (204) (or some other unexpected status code)
    if res.status() != 200 {
        warn!(username = %login_start.username, "client not authenticated");

        // maybe reply with something, look at what the offical server does?
        // but also maybe not
        return Ok(handler.close()?);
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct HasJoinedResponse {
        id: Uuid,
        name: String,
    }

    let res = res.json::<HasJoinedResponse>()?;
    info!(username = %res.name, "client authenticated");

    let response = "\"todo\"".to_string();
    handler.write(Disconnect { reason: response })?;

    Ok(handler.close()?)
}
