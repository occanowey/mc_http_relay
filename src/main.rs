use std::env;

use color_eyre::Result;

fn main() -> Result<()> {
    setup()?;

    Ok(())
}

fn setup() -> Result<()> {
    color_eyre::install()?;

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    Ok(())
}
