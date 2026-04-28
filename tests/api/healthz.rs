use crate::helpers::TestClient;

#[tokio::test]
async fn healthz_returns_ok() {
    let body: serde_json::Value = TestClient::new()
        .get("/healthz")
        .await
        .assert_status(200)
        .json();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn jwks_returns_keys() {
    let body: serde_json::Value = TestClient::new()
        .get("/v1/jwks.json")
        .await
        .assert_status(200)
        .json();
    assert!(
        body["keys"].as_array().is_some_and(|k| !k.is_empty()),
        "expected non-empty keys array, got: {body}"
    );
}
