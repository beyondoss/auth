use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::helpers::{
    TestClient, TotpEnrollment, enroll_totp, exclusive, signup, totp_now, unique_email,
};

// ── Mock OIDC server helpers ───────────────────────────────────────────────────

/// Mount the three OIDC endpoints on `mock_server`.
///
/// `unique_id` is embedded in the mocked `sub` and `email` so parallel test
/// runs never produce duplicate-email conflicts in the DB.
async fn mount_oidc_mocks(mock_server: &MockServer, unique_id: &str) {
    let base = mock_server.uri();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint":         format!("{base}/token"),
            "userinfo_endpoint":      format!("{base}/userinfo"),
        })))
        .mount(mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-access-token",
            "token_type":   "Bearer",
        })))
        .mount(mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub":            format!("mock-subject-{unique_id}"),
            "email":          format!("oauth-{unique_id}@example.com"),
            "email_verified": true,
            "name":           "OAuth Test User",
        })))
        .mount(mock_server)
        .await;
}

/// Configure the server with a fresh OIDC provider whose discovery URL points at
/// `mock_server`. Returns the provider ID.
///
/// Requires the exclusive lock since it mutates global OAuth config.
async fn configure_oidc(mock_server: &MockServer, id: &str) {
    TestClient::new()
        .admin()
        .put(
            "/v1/admin/oauth-providers",
            &serde_json::json!({
                "oidc": [{
                    "id":            id,
                    "discovery_url": format!("{}/.well-known/openid-configuration", mock_server.uri()),
                    "client_id":     "test-client-id",
                    "client_secret": "test-client-secret",
                    "scopes":        ["email", "profile"]
                }]
            }),
        )
        .await
        .assert_status(200);
}

/// Generate a fresh provider ID and set up both mocks and config in one call.
/// Returns the provider ID.
async fn setup_oidc(mock_server: &MockServer) -> String {
    let id = format!("t{}", &uuid::Uuid::now_v7().simple().to_string()[..16]);
    mount_oidc_mocks(mock_server, &id).await;
    configure_oidc(mock_server, &id).await;
    id
}

#[derive(serde::Deserialize)]
struct AuthorizeResponse {
    url: String,
}

#[derive(serde::Deserialize)]
struct CallbackResponse {
    token: String,
}

#[derive(serde::Deserialize)]
struct StepUpResponse {
    step_up_token: String,
}

/// Extract the `state` query parameter from an OAuth authorization URL.
fn state_from_url(url: &str) -> String {
    reqwest::Url::parse(url)
        .expect("valid authorize URL")
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state param must be present in authorize URL")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Requesting authorize for an unconfigured provider returns 400.
#[tokio::test]
async fn authorize_unknown_provider_returns_400() {
    TestClient::new()
        .get("/v1/oauth/no-such-provider?redirect_url=http://localhost/cb")
        .await
        .assert_status(400);
}

/// Authorize returns a URL containing both the PKCE challenge and a signed
/// state JWT; the state JWT is verifiable because the callback accepts it.
#[tokio::test]
async fn authorize_returns_url_with_pkce_and_state() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    let resp = TestClient::new()
        .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
        .await
        .assert_status(200)
        .json::<AuthorizeResponse>();

    assert!(resp.url.contains("state="), "URL must contain state param");
    assert!(
        resp.url.contains("code_challenge="),
        "URL must contain PKCE code_challenge"
    );
}

/// Callback with a tampered/invalid state JWT returns 401 (TokenInvalid).
#[tokio::test]
async fn callback_invalid_state_returns_401() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state=invalid.state.jwt"
        ))
        .await
        .assert_status(401);
}

/// Happy path: OIDC callback creates a new user and returns a usable session token.
#[tokio::test]
async fn callback_creates_session() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    let state = state_from_url(
        &TestClient::new()
            .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
            .await
            .assert_status(200)
            .json::<AuthorizeResponse>()
            .url,
    );

    let resp = TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state={state}"
        ))
        .await
        .assert_status(200)
        .json::<CallbackResponse>();

    assert!(!resp.token.is_empty());

    TestClient::new()
        .bearer(&resp.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}

/// Two logins with the same OAuth identity (same `sub`) resolve to the same user.
#[tokio::test]
async fn callback_idempotent_same_identity_returns_same_user() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    let login = |id: &str| {
        let id = id.to_string();
        async move {
            let state = state_from_url(
                &TestClient::new()
                    .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
                    .await
                    .assert_status(200)
                    .json::<AuthorizeResponse>()
                    .url,
            );
            TestClient::new()
                .get(&format!(
                    "/v1/oauth/{id}/callback?code=test-code&state={state}"
                ))
                .await
                .assert_status(200)
                .json::<CallbackResponse>()
                .token
        }
    };

    let token1 = login(&id).await;
    let token2 = login(&id).await;

    let me1 = TestClient::new()
        .bearer(&token1)
        .get("/v1/users/me")
        .await
        .assert_status(200)
        .json::<beyond_auth::MeResponse>();
    let me2 = TestClient::new()
        .bearer(&token2)
        .get("/v1/users/me")
        .await
        .assert_status(200)
        .json::<beyond_auth::MeResponse>();

    assert_eq!(
        me1.user.id, me2.user.id,
        "both sessions must belong to the same user"
    );
}

/// Authorize with a valid Bearer token embeds `link_user_id` in the state JWT;
/// the callback returns `{"linked": true}` instead of a session token.
#[tokio::test]
async fn callback_links_identity_to_existing_user() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let state = state_from_url(
        &TestClient::new()
            .bearer(&auth.session.token)
            .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
            .await
            .assert_status(200)
            .json::<AuthorizeResponse>()
            .url,
    );

    let resp: serde_json::Value = TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state={state}"
        ))
        .await
        .assert_status(200)
        .json();

    assert_eq!(
        resp["linked"],
        serde_json::Value::Bool(true),
        "account-linking callback must return {{\"linked\": true}}"
    );
}

/// A user who enrolled TOTP and then signs in via OAuth receives a step-up
/// challenge instead of a session token.
#[tokio::test]
async fn callback_with_totp_enrolled_returns_step_up() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    // First callback creates the user and returns a session.
    let state = state_from_url(
        &TestClient::new()
            .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
            .await
            .assert_status(200)
            .json::<AuthorizeResponse>()
            .url,
    );
    let first = TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state={state}"
        ))
        .await
        .assert_status(200)
        .json::<CallbackResponse>();

    // Enroll TOTP on the account created above.
    enroll_totp(&first.token).await;

    // Second OAuth login for the same identity must return a step-up challenge.
    let state = state_from_url(
        &TestClient::new()
            .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
            .await
            .assert_status(200)
            .json::<AuthorizeResponse>()
            .url,
    );
    let resp: serde_json::Value = TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state={state}"
        ))
        .await
        .assert_status(200)
        .json();

    assert_eq!(resp["step_up_required"], "totp");
    assert!(
        resp["step_up_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "step_up_token must be present"
    );
}

/// After receiving a TOTP step-up challenge from the OAuth callback, completing
/// the step-up with a valid code creates a real session.
#[tokio::test]
async fn callback_with_totp_step_up_completes_to_session() {
    let _guard = exclusive().await;
    let mock_server = MockServer::start().await;
    let id = setup_oidc(&mock_server).await;

    // Create user via OAuth and enroll TOTP.
    let state = state_from_url(
        &TestClient::new()
            .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
            .await
            .assert_status(200)
            .json::<AuthorizeResponse>()
            .url,
    );
    let first = TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state={state}"
        ))
        .await
        .assert_status(200)
        .json::<CallbackResponse>();
    let enrollment: TotpEnrollment = enroll_totp(&first.token).await;

    // Second login returns a step-up token.
    let state = state_from_url(
        &TestClient::new()
            .get(&format!("/v1/oauth/{id}?redirect_url=http://localhost/cb"))
            .await
            .assert_status(200)
            .json::<AuthorizeResponse>()
            .url,
    );
    let step_up = TestClient::new()
        .get(&format!(
            "/v1/oauth/{id}/callback?code=test-code&state={state}"
        ))
        .await
        .assert_status(200)
        .json::<StepUpResponse>();

    // Complete the step-up — must create a full session.
    let session = TestClient::new()
        .post(
            "/v1/sessions",
            &serde_json::json!({
                "grant_type": "totp_step_up",
                "step_up_token": step_up.step_up_token,
                "code": totp_now(&enrollment.secret_b32),
            }),
        )
        .await
        .assert_status(201)
        .json::<CallbackResponse>();

    TestClient::new()
        .bearer(&session.token)
        .get("/v1/users/me")
        .await
        .assert_status(200);
}
