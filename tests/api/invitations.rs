use beyond_auth::InvitationResponse;
use uuid::Uuid;

use crate::helpers::{TestClient, signup, unique_email};

#[derive(serde::Deserialize)]
struct InvitationViewResponse {
    id: Uuid,
    org_id: Uuid,
    org_name: String,
    role: String,
}

async fn create_invitation(owner_token: &str, org_id: Uuid) -> InvitationResponse {
    TestClient::new()
        .bearer(owner_token)
        .post(
            &format!("/v1/orgs/{org_id}/invitations"),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>()
}

// ── GET /v1/invitations/{id}?token=... ────────────────────────────────────────

#[tokio::test]
async fn view_invitation_returns_org_details() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let inv = create_invitation(&owner.session.token, owner.org.id).await;
    let token = inv.token.expect("token must be present on creation");

    let view = TestClient::new()
        .get(&format!("/v1/invitations/{}?token={}", inv.id, token))
        .await
        .assert_status(200)
        .json::<InvitationViewResponse>();

    assert_eq!(view.id, inv.id);
    assert_eq!(view.org_id, owner.org.id);
    assert!(!view.org_name.is_empty());
    assert_eq!(view.role, "member");
}

#[tokio::test]
async fn view_invitation_wrong_token_returns_404() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let inv = create_invitation(&owner.session.token, owner.org.id).await;

    TestClient::new()
        .get(&format!("/v1/invitations/{}?token=it_wrongtoken", inv.id))
        .await
        .assert_status(404);
}

// ── POST /v1/invitations/{id}/declinations?token=... ─────────────────────────

#[tokio::test]
async fn decline_invitation_returns_204() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let inv = create_invitation(&owner.session.token, owner.org.id).await;
    let token = inv.token.expect("token must be present on creation");

    TestClient::new()
        .post(
            &format!("/v1/invitations/{}/declinations?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(204);
}

#[tokio::test]
async fn decline_invitation_wrong_token_returns_404() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let inv = create_invitation(&owner.session.token, owner.org.id).await;

    TestClient::new()
        .post(
            &format!(
                "/v1/invitations/{}/declinations?token=it_wrongtoken",
                inv.id
            ),
            &serde_json::json!({}),
        )
        .await
        .assert_status(404);
}

#[tokio::test]
async fn declined_invitation_cannot_be_accepted() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let joiner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let inv = create_invitation(&owner.session.token, owner.org.id).await;
    let token = inv.token.expect("token must be present on creation");

    TestClient::new()
        .post(
            &format!("/v1/invitations/{}/declinations?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&joiner.session.token)
        .post(
            &format!("/v1/invitations/{}/acceptances?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(404);
}

// ── POST /v1/invitations/{id}/acceptances?token=... ──────────────────────────

#[tokio::test]
async fn accept_invitation_requires_auth() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let inv = create_invitation(&owner.session.token, owner.org.id).await;
    let token = inv.token.expect("token must be present on creation");

    TestClient::new()
        .post(
            &format!("/v1/invitations/{}/acceptances?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(401);
}
