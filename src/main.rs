mod hostname;
mod serveraddr;

use std::env;

pub(crate) use hostname::Hostname;

use clap::Parser;
use color_eyre::Result;
use reqwest::Url;
use serveraddr::ServerAddr;

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

    Ok(())
}

fn setup() -> Result<Args> {
    color_eyre::install()?;

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    Ok(Args::parse())
}
