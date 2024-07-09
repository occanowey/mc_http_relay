mod encryption;
mod hostname;
mod serveraddr;

use std::{
    env,
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use color_eyre::{eyre::eyre, Result};
use tracing::{debug, error, info, info_span, trace, warn};

use clap::Parser;

pub(crate) use mcproto::versions::latest as proto;
use mcproto::{handshake::Handshake, role, sio};
use proto::states::{LoginState, StatusState};

pub(crate) use hostname::Hostname;
use num_bigint::BigInt;
use serveraddr::ServerAddr;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use reqwest::{blocking::RequestBuilder, Url};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address the Minecraft server should bind to
    server_address: ServerAddr,

    /// Url to forward status and login requests to
    destination_url: Url,

    /// Bearer token to be send to the destination
    bearer_token: Option<String>,
}

fn main() -> Result<()> {
    let args = setup()?;

    info!("Starting relay on {}...", args.server_address);
    let listener = TcpListener::bind(args.server_address)?;

    let key_pair = Arc::new(encryption::McKeyPair::generate()?);

    let client = reqwest::blocking::Client::new();
    let request = client
        .post(args.destination_url)
        .header(reqwest::header::ACCEPT, "application/json");

    let request = if let Some(token) = args.bearer_token {
        request.bearer_auth(token)
    } else {
        request
    };

    loop {
        let (stream, client_address) = listener.accept()?;

        // not body attached, unwrap is safe
        let request = request.try_clone().unwrap();
        let key_pair = key_pair.clone();

        thread::Builder::new()
            .name(format!("client({client_address})"))
            .spawn(move || {
                let span = info_span!("client", address = %client_address);
                let _enter = span.enter();

                match handle_client(stream, &key_pair, request) {
                    Ok(_) => {}
                    Err(err) => match err.downcast_ref::<mcproto::error::Error>() {
                        Some(mcproto::error::Error::StreamShutdown) => {}
                        Some(mcproto::error::Error::UnexpectedDisconect(err)) => {
                            info!("Connection unexpectedly closed: {}", err.kind());
                        }
                        _other => {
                            error!(%err, "Error while handling connection");
                        }
                    },
                }
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

pub type Connection<S> = sio::StdIoConnection<role::Server, S>;

fn handle_client(
    stream: TcpStream,
    key_pair: &encryption::McKeyPair,
    request: RequestBuilder,
) -> Result<()> {
    use mcproto::handshake::NextState;

    debug!("Connection accepted");
    let mut conn = sio::accept_stdio_stream(stream)?;

    let handshake: Handshake = conn.expect_next_packet()?;
    trace!(?handshake, "Recieved handshake packet");

    info!(next_state = ?handshake.next_state, "Client connected");

    match handshake.next_state {
        NextState::Status => handle_status(conn.next_state(), handshake, request),
        NextState::Login => handle_login(conn.next_state(), handshake, key_pair, request),

        NextState::Transfer => todo!(),

        NextState::Unknown(other) => Err(eyre!("client requested unknown next state: {other}")),
    }
}

fn handle_status(
    mut connection: Connection<StatusState>,
    handshake: Handshake,
    request: RequestBuilder,
) -> Result<()> {
    use proto::packets::status::{
        c2s::{PingRequest, StatusRequest},
        s2c::{PingResponse, StatusResponse},
    };

    #[derive(Serialize)]
    struct StatusData {
        protocol_version: i32,
        server_address: String,
        server_port: u16,
    }

    let response = request
        .query(&[("state", "status")])
        .json(&StatusData {
            protocol_version: handshake.protocol_version,
            server_address: handshake.server_address,
            server_port: handshake.server_port,
        })
        .send()?
        .error_for_status()?
        .text()?;

    let request: StatusRequest = connection.expect_next_packet()?;
    trace!(?request, "Recieved status request packet");
    connection.write_packet(StatusResponse { response })?;
    info!("Forwarded status");

    let ping: PingRequest = connection.expect_next_packet()?;
    trace!(?ping, "Recieved ping request packet");
    connection.write_packet(PingResponse {
        payload: ping.payload,
    })?;
    trace!("Sent ping response packet");

    connection.shutdown(Shutdown::Both)?;
    Ok(())
}

const MOJANG_HAS_JOINED_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined";

fn handle_login(
    mut connection: Connection<LoginState>,
    handshake: Handshake,
    key_pair: &encryption::McKeyPair,
    request: RequestBuilder,
) -> Result<()> {
    use proto::packets::login::{c2s::LoginStart, s2c::Disconnect};

    let login_start: LoginStart = connection.expect_next_packet()?;
    trace!(?login_start, "Recieved login start packet");

    // technically the client part of the authentication is done in the middle
    // of encryption negotiations but this includes from the EncryptionRequest packet
    // to actually enabling encryption and the server auth comes after.
    let shared_secret = encryption::negotiate_encryption(key_pair, &mut connection)?;

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
        connection.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct HasJoinedResponse {
        id: Uuid,
        name: String,
    }

    let res = res.json::<HasJoinedResponse>()?;
    info!(username = %res.name, "client authenticated");

    #[derive(Serialize)]
    struct LoginData {
        protocol_version: i32,
        server_address: String,
        server_port: u16,
        username: String,
        uuid: Uuid,
    }

    let response = request
        .query(&[("state", "login")])
        .json(&LoginData {
            protocol_version: handshake.protocol_version,
            server_address: handshake.server_address,
            server_port: handshake.server_port,
            username: res.name,
            uuid: res.id,
        })
        .send()?
        .error_for_status()?
        .text()?;

    connection.write_packet(Disconnect { reason: response })?;
    trace!("Sent disconnect packet");

    connection.shutdown(Shutdown::Both)?;
    Ok(())
}
