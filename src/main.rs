mod hostname;
mod serveraddr;

use std::{
    env,
    net::{TcpListener, TcpStream},
    thread,
};

pub(crate) use hostname::Hostname;

use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use mcproto::{
    net::{handler_from_stream, state::StatusState},
    packet::handshaking::{Handshake, NextState},
};
use reqwest::Url;
use serveraddr::ServerAddr;
use tracing::{debug, info, info_span, trace};

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

    loop {
        let (stream, client_address) = listener.accept()?;

        let destination_url = args.destination_url.clone();
        thread::Builder::new()
            .name(format!("client({client_address})"))
            .spawn(move || {
                let span = info_span!("client", address = %client_address);
                let _enter = span.enter();

                handle_client(stream, destination_url).unwrap();
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

fn handle_client(stream: TcpStream, destination_url: Url) -> Result<()> {
    debug!("Connection accepted");

    stream.set_nodelay(true)?;
    let mut handler: NetworkHandler<_> = handler_from_stream(stream)?;

    let handshake: Handshake = handler.read()?;
    trace!(?handshake, "Recieved handshake packet");

    info!(next_state = ?handshake.next_state, "Client connected");

    match handshake.next_state {
        NextState::Status => handle_status(handler.status(), destination_url, handshake),
        NextState::Login => todo!(),

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
