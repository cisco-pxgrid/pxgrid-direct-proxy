use api_pagination_proxy::{handle, load_config};
use axum::Router;
use std::{env, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::{info, warn};

const DEFAULT_CONFIG_PATH: &str = "/etc/api-proxy/config.yaml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config_path()?;
    tracing_subscriber::fmt::init();
    let config = Arc::new(load_config(&config_path)?);
    info!(listen_address = %config.listen.address, target_base_url = %config.target.base_url, "loaded proxy configuration");
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(path) = &config.target.ca_bundle_path {
        let bundle = std::fs::read(path)?;
        info!(ca_bundle_path = %path, "loading custom CA bundle");
        for certificate in reqwest::Certificate::from_pem_bundle(&bundle)? {
            builder = builder.add_root_certificate(certificate);
        }
    } else {
        warn!("using the built-in public CA roots; no custom CA bundle configured");
    }
    if let Some(seconds) = config.target.timeout_seconds {
        builder = builder.timeout(Duration::from_secs(seconds));
    }
    let client = builder.build()?;
    let listener = TcpListener::bind(&config.listen.address).await?;
    info!(listen_address = %config.listen.address, "proxy listening");
    let app =
        Router::new().fallback(move |request| handle(request, config.clone(), client.clone()));
    axum::serve(listener, app).await?;
    Ok(())
}

fn config_path() -> Result<String, String> {
    let mut args = env::args().skip(1);
    let mut path = DEFAULT_CONFIG_PATH.to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                path = args
                    .next()
                    .ok_or_else(|| "missing path after --config".to_string())?;
            }
            "-h" | "--help" => {
                println!(
                    "Usage: api-pagination-proxy [OPTIONS]\n\nOptions:\n  -c, --config <PATH>  Configuration file (default: {DEFAULT_CONFIG_PATH})\n  -h, --help           Print this help message"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}; use --help for usage")),
        }
    }

    Ok(path)
}
