use api_pagination_proxy::{handle, load_config};
use axum::Router;
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let config = Arc::new(load_config("/etc/api-proxy/config.yaml")?);
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
