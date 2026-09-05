use api_pagination_proxy::crowdstrike::handle_crowdstrike;
use api_pagination_proxy::{handle, load_config, TlsConfig};
use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        return Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "a Rustls crypto provider was already installed",
        )
        .into());
    }
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
    let (ca_path, certificate_path, key_path) = ensure_tls_material(&config.listen.tls)?;
    let tls_config = RustlsConfig::from_pem_file(&certificate_path, &key_path).await?;
    let address: SocketAddr = config.listen.address.parse()?;
    info!(
        listen_address = %address,
        ca_certificate_path = %ca_path.display(),
        server_names = ?config.listen.tls.server_names,
        "proxy listening with HTTPS"
    );
    let crowdstrike_config = config.clone();
    let crowdstrike_client = client.clone();
    let app = Router::new()
        .route(
            "/crowdstrike",
            get(move |request| {
                handle_crowdstrike(
                    request,
                    crowdstrike_config.clone(),
                    crowdstrike_client.clone(),
                )
            }),
        )
        .fallback(move |request| handle(request, config.clone(), client.clone()));
    axum_server::bind_rustls(address, tls_config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn ensure_tls_material(
    tls: &TlsConfig,
) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    if tls.server_names.is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "listen.tls.server_names must not be empty",
        )
        .into());
    }

    let directory = Path::new(&tls.certificate_directory);
    fs::create_dir_all(directory)?;
    let ca_path = directory.join("ca.pem");
    let certificate_path = directory.join("server.pem");
    let key_path = directory.join("server-key.pem");
    let paths = [&ca_path, &certificate_path, &key_path];
    let existing = paths.iter().filter(|path| path.exists()).count();
    if existing == paths.len() {
        info!(certificate_directory = %directory.display(), "reusing generated TLS certificates");
        return Ok((ca_path, certificate_path, key_path));
    }
    if existing != 0 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "incomplete TLS material in {}; remove the partial files before restarting",
                directory.display()
            ),
        )
        .into());
    }

    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "api-pagination-proxy local CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_certificate = ca_params.self_signed(&ca_key)?;

    let mut server_params = CertificateParams::new(tls.server_names.clone())?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, tls.server_names[0].clone());
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server_certificate = server_params.signed_by(&server_key, &ca_certificate, &ca_key)?;

    write_new_file(&ca_path, ca_certificate.pem().as_bytes(), 0o644)?;
    write_new_file(
        &certificate_path,
        server_certificate.pem().as_bytes(),
        0o644,
    )?;
    write_new_file(&key_path, server_key.serialize_pem().as_bytes(), 0o600)?;
    info!(certificate_directory = %directory.display(), "generated a local CA and server certificate");
    Ok((ca_path, certificate_path, key_path))
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents)
}
