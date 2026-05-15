use std::io::Write;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
};
use reqwest::Version;
use tempfile::NamedTempFile;

use crate::helpers;

pub struct CertBundle {
    pub ca_pem: String,
    pub server_pem: String,
    pub server_key_pem: String,
    pub client_pem: String,
    pub client_key_pem: String,
}

pub fn generate_test_certs() -> CertBundle {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv_params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    srv_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let server_cert = srv_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut cli_params = CertificateParams::new(vec!["client".to_string()]).unwrap();
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = cli_params.signed_by(&client_key, &issuer).unwrap();

    CertBundle {
        ca_pem: ca_cert.pem(),
        server_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

fn write_temp(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

fn mtls_client(certs: &CertBundle) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(certs.ca_pem.as_bytes()).unwrap();
    let combined = format!("{}{}", certs.client_pem, certs.client_key_pem);
    let identity = reqwest::Identity::from_pem(combined.as_bytes()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .identity(identity)
        .https_only(true)
        .build()
        .unwrap()
}

async fn start_tls_server(certs: &CertBundle) -> String {
    let env = helpers::test_env();
    let pool = sqlx::PgPool::connect(&env.database_url).await.unwrap();

    let cert_file = write_temp(&certs.server_pem);
    let key_file = write_temp(&certs.server_key_pem);
    let ca_file = write_temp(&certs.ca_pem);

    let tls = (
        cert_file.path().to_str().unwrap().to_string(),
        key_file.path().to_str().unwrap().to_string(),
        ca_file.path().to_str().unwrap().to_string(),
    );

    let url = beyond_auth::test_server::start_tls(pool, tls)
        .await
        .unwrap();

    // Keep temp files alive until the server is up.
    std::mem::forget(cert_file);
    std::mem::forget(key_file);
    std::mem::forget(ca_file);

    tokio::time::sleep(Duration::from_millis(50)).await;
    url
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Valid mTLS client — request succeeds over HTTP/2.
#[tokio::test]
#[cfg(feature = "test-server")]
async fn tls_valid_client_gets_h2() {
    let certs = generate_test_certs();
    let url = start_tls_server(&certs).await;

    let client = mtls_client(&certs);
    let res = client
        .get(format!("{url}/livez"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(res.status(), 200);
    assert_eq!(res.version(), Version::HTTP_2);
}

/// No client certificate — server rejects the TLS handshake.
#[tokio::test]
#[cfg(feature = "test-server")]
async fn tls_no_client_cert_rejected() {
    let certs = generate_test_certs();
    let url = start_tls_server(&certs).await;

    let ca = reqwest::Certificate::from_pem(certs.ca_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .https_only(true)
        .build()
        .unwrap();

    let err = client.get(format!("{url}/livez")).send().await;
    assert!(err.is_err(), "expected TLS rejection, got: {:?}", err);
}

/// Client cert from a different CA — server rejects it.
#[tokio::test]
#[cfg(feature = "test-server")]
async fn tls_wrong_ca_rejected() {
    let certs = generate_test_certs();
    let rogue_certs = generate_test_certs();
    let url = start_tls_server(&certs).await;

    let client = mtls_client(&rogue_certs);
    let err = client.get(format!("{url}/livez")).send().await;
    assert!(err.is_err(), "expected TLS rejection, got: {:?}", err);
}
