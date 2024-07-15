use color_eyre::{eyre::eyre, Result};
use tracing::{debug, error, info, info_span, trace, warn};

use clap::Parser;
use reqwest::{blocking::RequestBuilder, Url};
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use mcproto::handshake::{Handshake, HandshakingState};
use mcproto::{role, sio};

pub(crate) use hostname::Hostname;
use multi_version::Protocol;
use serveraddr::ServerAddr;

use num_bigint::BigInt;
use sha1::{Digest, Sha1};
use uuid::Uuid;

mod encryption;
mod hostname;
mod multi_version;
mod serveraddr;
mod version_impls;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address the Minecraft server should bind to
    #[arg(env)]
    server_address: ServerAddr,

    /// Url to forward status and login requests to
    #[arg(env)]
    destination_url: Url,

    /// Bearer token to be send to the destination
    #[arg(env)]
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

                match handshake_client(stream, &key_pair, request) {
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

fn handshake_client(
    stream: TcpStream,
    key_pair: &encryption::McKeyPair,
    request: RequestBuilder,
) -> Result<()> {
    debug!("Connection accepted");
    let mut conn = sio::accept_stdio_stream(stream)?;

    let handshake: Handshake = conn.expect_next_packet()?;
    trace!(?handshake, "Recieved handshake packet");

    info!(next_state = ?handshake.next_state, "Client connected");

    match handshake.protocol_version {
        // 3 => handle_client::<version_impls::ProtocolV3>(conn, handshake, key_pair, request),
        4 => handle_client::<version_impls::ProtocolV4>(conn, handshake, key_pair, request),
        5 => handle_client::<version_impls::ProtocolV5>(conn, handshake, key_pair, request),
        47 => handle_client::<version_impls::ProtocolV47>(conn, handshake, key_pair, request),
        107 => handle_client::<version_impls::ProtocolV107>(conn, handshake, key_pair, request),
        108 => handle_client::<version_impls::ProtocolV108>(conn, handshake, key_pair, request),
        109 => handle_client::<version_impls::ProtocolV109>(conn, handshake, key_pair, request),
        110 => handle_client::<version_impls::ProtocolV110>(conn, handshake, key_pair, request),
        210 => handle_client::<version_impls::ProtocolV210>(conn, handshake, key_pair, request),
        315 => handle_client::<version_impls::ProtocolV315>(conn, handshake, key_pair, request),
        316 => handle_client::<version_impls::ProtocolV316>(conn, handshake, key_pair, request),
        335 => handle_client::<version_impls::ProtocolV335>(conn, handshake, key_pair, request),
        338 => handle_client::<version_impls::ProtocolV338>(conn, handshake, key_pair, request),
        340 => handle_client::<version_impls::ProtocolV340>(conn, handshake, key_pair, request),
        393 => handle_client::<version_impls::ProtocolV393>(conn, handshake, key_pair, request),
        401 => handle_client::<version_impls::ProtocolV401>(conn, handshake, key_pair, request),
        404 => handle_client::<version_impls::ProtocolV404>(conn, handshake, key_pair, request),
        477 => handle_client::<version_impls::ProtocolV477>(conn, handshake, key_pair, request),
        480 => handle_client::<version_impls::ProtocolV480>(conn, handshake, key_pair, request),
        485 => handle_client::<version_impls::ProtocolV485>(conn, handshake, key_pair, request),
        490 => handle_client::<version_impls::ProtocolV490>(conn, handshake, key_pair, request),
        498 => handle_client::<version_impls::ProtocolV498>(conn, handshake, key_pair, request),
        573 => handle_client::<version_impls::ProtocolV573>(conn, handshake, key_pair, request),
        575 => handle_client::<version_impls::ProtocolV575>(conn, handshake, key_pair, request),
        578 => handle_client::<version_impls::ProtocolV578>(conn, handshake, key_pair, request),
        735 => handle_client::<version_impls::ProtocolV735>(conn, handshake, key_pair, request),
        736 => handle_client::<version_impls::ProtocolV736>(conn, handshake, key_pair, request),
        751 => handle_client::<version_impls::ProtocolV751>(conn, handshake, key_pair, request),
        753 => handle_client::<version_impls::ProtocolV753>(conn, handshake, key_pair, request),
        754 => handle_client::<version_impls::ProtocolV754>(conn, handshake, key_pair, request),
        755 => handle_client::<version_impls::ProtocolV755>(conn, handshake, key_pair, request),
        756 => handle_client::<version_impls::ProtocolV756>(conn, handshake, key_pair, request),
        757 => handle_client::<version_impls::ProtocolV757>(conn, handshake, key_pair, request),
        758 => handle_client::<version_impls::ProtocolV758>(conn, handshake, key_pair, request),
        // 1.19 has weird authentication/encryption, cba
        // 759 => handle_client::<version_impls::ProtocolV759>(conn, handshake, key_pair, request),
        760 => handle_client::<version_impls::ProtocolV760>(conn, handshake, key_pair, request),
        761 => handle_client::<version_impls::ProtocolV761>(conn, handshake, key_pair, request),
        762 => handle_client::<version_impls::ProtocolV762>(conn, handshake, key_pair, request),
        763 => handle_client::<version_impls::ProtocolV763>(conn, handshake, key_pair, request),
        764 => handle_client::<version_impls::ProtocolV764>(conn, handshake, key_pair, request),
        765 => handle_client::<version_impls::ProtocolV765>(conn, handshake, key_pair, request),
        766 => handle_client::<version_impls::ProtocolV766>(conn, handshake, key_pair, request),
        767 => handle_client::<version_impls::ProtocolV767>(conn, handshake, key_pair, request),

        other => {
            warn!("unknown protocol version: {}, rejecting.", other);
            handle_unknown_client_version::<version_impls::ProtocolV767>(conn, handshake)
        }
    }
}

fn handle_unknown_client_version<P: Protocol>(
    connection: Connection<HandshakingState>,
    handshake: Handshake,
) -> Result<()>
where
    P::StatusState: multi_version::StatusState,
    <P::StatusState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
    P::LoginState: multi_version::LoginState,
    <P::LoginState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
{
    use mcproto::handshake::NextState;

    match handshake.next_state {
        NextState::Status => {
            let mut connection = connection.next_state();

            P::write_status_response(
                &mut connection,
                multi_version::StatusResponse {
                    response: r#"{{
                        "version": {{
                            "name": "",
                            "protocol": -1
                        }},
                        "players": {{
                            "max": 0,
                            "online": 0
                        }},
                        "description": {{
                            "text": "Your Minecraft version is unsupported."
                        }}
                    }}"#
                    .into(),
                },
            )?;
            connection.shutdown(Shutdown::Both)?;

            Ok(())
        }
        NextState::Login => {
            let mut connection = connection.next_state();

            P::write_disconnect(
                &mut connection,
                multi_version::Disconnect {
                    reason: "\"Your Minecraft version is unsupported.\"".into(),
                },
            )?;
            connection.shutdown(Shutdown::Both)?;

            Ok(())
        }

        // not yet clear on what this does
        NextState::Transfer => todo!(),

        NextState::Unknown(other) => Err(eyre!("client requested unknown next state: {other}")),
    }
}

fn handle_client<P: Protocol>(
    connection: Connection<HandshakingState>,
    handshake: Handshake,
    key_pair: &encryption::McKeyPair,
    request: RequestBuilder,
) -> Result<()>
where
    P::StatusState: multi_version::StatusState,
    <P::StatusState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
    P::LoginState: multi_version::LoginState,
    <P::LoginState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
{
    use mcproto::handshake::NextState;

    match handshake.next_state {
        NextState::Status => handle_status::<P>(connection.next_state(), handshake, request),
        NextState::Login => {
            handle_login::<P>(connection.next_state(), handshake, key_pair, request)
        }

        // not yet clear on what this does
        NextState::Transfer => todo!(),

        NextState::Unknown(other) => Err(eyre!("client requested unknown next state: {other}")),
    }
}

fn handle_status<P: Protocol>(
    mut connection: Connection<P::StatusState>,
    handshake: Handshake,
    request: RequestBuilder,
) -> Result<()>
where
    P::StatusState: multi_version::StatusState,
    <P::StatusState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
    P::LoginState: multi_version::LoginState,
    <P::LoginState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
{
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

    let request = P::read_status_request(&mut connection)?;
    trace!(?request, "Recieved status request packet");
    P::write_status_response(&mut connection, multi_version::StatusResponse { response })?;
    info!("Forwarded status");

    let ping = P::read_ping_request(&mut connection)?;
    trace!(?ping, "Recieved ping request packet");
    P::write_ping_response(
        &mut connection,
        multi_version::PingResponse {
            payload: ping.payload,
        },
    )?;
    trace!("Sent ping response packet");

    Ok(connection.shutdown(Shutdown::Both)?)
}

const MOJANG_HAS_JOINED_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined";

fn handle_login<P: Protocol>(
    mut connection: Connection<P::LoginState>,
    handshake: Handshake,
    key_pair: &encryption::McKeyPair,
    request: RequestBuilder,
) -> Result<()>
where
    P::StatusState: multi_version::StatusState,
    <P::StatusState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
    P::LoginState: multi_version::LoginState,
    <P::LoginState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
{
    let login_start = P::read_login_start(&mut connection)?;
    trace!(?login_start, "Recieved login start packet");

    // technically the client part of the authentication is done in the middle
    // of encryption negotiations but this includes from the EncryptionRequest packet
    // to actually enabling encryption and the server auth comes after.
    let shared_secret = encryption::negotiate_encryption::<P>(key_pair, &mut connection)?;

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
        return Ok(connection.shutdown(Shutdown::Both)?);
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

    P::write_disconnect(
        &mut connection,
        multi_version::Disconnect { reason: response },
    )?;
    trace!("Sent disconnect packet");

    Ok(connection.shutdown(Shutdown::Both)?)
}
