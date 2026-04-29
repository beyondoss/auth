use uuid::Uuid;

use beyond_auth::{
    InvitationResponse, InvitationsResponse, MembersResponse, OrgResponse, OrgsResponse,
};

use crate::helpers::{TestClient, signup, unique_email};

// ── Local helpers ─────────────────────────────────────────────────────────────

async fn create_org(token: &str, name: &str) -> OrgResponse {
    TestClient::new()
        .bearer(token)
        .post("/v1/orgs", &serde_json::json!({ "name": name }))
        .await
        .assert_status(201)
        .json::<OrgResponse>()
}

/// Invite `member_token` user to `org_id` with `role` and have them accept.
async fn invite_and_accept(org_id: Uuid, owner_token: &str, member_token: &str, role: &str) {
    let inv = TestClient::new()
        .bearer(owner_token)
        .post(
            &format!("/v1/orgs/{org_id}/invitations"),
            &serde_json::json!({ "role": role }),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>();

    let token = inv
        .token
        .expect("invitation token must be present on creation");

    TestClient::new()
        .bearer(member_token)
        .post(
            &format!("/v1/invitations/{}/acceptances?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(204);
}

// ── POST /v1/orgs ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_org_returns_created_org() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Acme Corp").await;

    assert_eq!(org.name, "Acme Corp");
    assert!(!org.slug.is_empty());
}

#[tokio::test]
async fn create_org_with_explicit_slug() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let slug = format!("explicit-{}", Uuid::now_v7().simple());

    let org = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/orgs",
            &serde_json::json!({ "name": "Acme", "slug": slug }),
        )
        .await
        .assert_status(201)
        .json::<OrgResponse>();

    assert_eq!(org.slug, slug);
}

#[tokio::test]
async fn create_org_slug_conflict_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let slug = format!("conflict-{}", Uuid::now_v7().simple());

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/orgs",
            &serde_json::json!({ "name": "First", "slug": slug }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/orgs",
            &serde_json::json!({ "name": "Second", "slug": slug }),
        )
        .await
        .assert_status(409);
}

#[tokio::test]
async fn create_org_requires_auth() {
    TestClient::new()
        .post("/v1/orgs", &serde_json::json!({ "name": "Acme" }))
        .await
        .assert_status(401);
}

// ── GET /v1/orgs ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_orgs_includes_personal_org() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/orgs")
        .await
        .assert_status(200)
        .json::<OrgsResponse>();

    assert!(
        resp.orgs.iter().any(|o| o.id == auth.org.id),
        "personal org not in list"
    );
}

#[tokio::test]
async fn list_orgs_includes_accepted_orgs() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Shared Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    let resp = TestClient::new()
        .bearer(&member.session.token)
        .get("/v1/orgs")
        .await
        .assert_status(200)
        .json::<OrgsResponse>();

    assert!(
        resp.orgs.iter().any(|o| o.id == org.id),
        "accepted org not in member's list"
    );
}

#[tokio::test]
async fn list_orgs_paginates() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    // personal org already exists; create 2 more = 3 total
    create_org(&auth.session.token, "Org A").await;
    create_org(&auth.session.token, "Org B").await;

    let page1 = TestClient::new()
        .bearer(&auth.session.token)
        .get("/v1/orgs?limit=2")
        .await
        .assert_status(200)
        .json::<OrgsResponse>();

    assert_eq!(page1.orgs.len(), 2);
    assert!(page1.has_more);
    let cursor = page1.next_page.expect("must have next_page");

    let page2 = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs?limit=2&after={cursor}"))
        .await
        .assert_status(200)
        .json::<OrgsResponse>();

    assert!(!page2.orgs.is_empty());
    assert!(!page2.has_more);

    let all_ids: std::collections::HashSet<_> = page1
        .orgs
        .iter()
        .chain(page2.orgs.iter())
        .map(|o| o.id)
        .collect();
    assert_eq!(all_ids.len(), 3, "all orgs must appear across pages");
}

// ── GET /v1/orgs/{id} ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_org_returns_org() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Visible Org").await;

    let fetched = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}", org.id))
        .await
        .assert_status(200)
        .json::<OrgResponse>();

    assert_eq!(fetched.id, org.id);
    assert_eq!(fetched.name, "Visible Org");
}

#[tokio::test]
async fn get_org_as_non_member_returns_403() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let stranger = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Private Org").await;

    TestClient::new()
        .bearer(&stranger.session.token)
        .get(&format!("/v1/orgs/{}", org.id))
        .await
        .assert_status(403);
}

#[tokio::test]
async fn get_org_nonexistent_returns_403() {
    // require_member fires before the fetch — a non-existent org is indistinguishable
    // from one the caller simply doesn't belong to, so both return 403.
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}", Uuid::now_v7()))
        .await
        .assert_status(403);
}

// ── PATCH /v1/orgs/{id} ──────────────────────────────────────────────────────

#[tokio::test]
async fn update_org_returns_updated_fields() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Old Name").await;

    let updated = TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/orgs/{}", org.id),
            &serde_json::json!({ "name": "New Name" }),
        )
        .await
        .assert_status(200)
        .json::<OrgResponse>();

    assert_eq!(updated.id, org.id);
    assert_eq!(updated.name, "New Name");
}

#[tokio::test]
async fn update_org_as_member_returns_403() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Team Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    TestClient::new()
        .bearer(&member.session.token)
        .patch(
            &format!("/v1/orgs/{}", org.id),
            &serde_json::json!({ "name": "Hijacked" }),
        )
        .await
        .assert_status(403);
}

#[tokio::test]
async fn update_org_slug_conflict_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let taken_slug = format!("taken-{}", Uuid::now_v7().simple());

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            "/v1/orgs",
            &serde_json::json!({ "name": "Existing", "slug": taken_slug }),
        )
        .await
        .assert_status(201);

    let other = create_org(&auth.session.token, "Other").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/orgs/{}", other.id),
            &serde_json::json!({ "slug": taken_slug }),
        )
        .await
        .assert_status(409);
}

// ── DELETE /v1/orgs/{id} ─────────────────────────────────────────────────────

#[tokio::test]
async fn delete_org_returns_204() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Disposable Org").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/orgs/{}", org.id))
        .await
        .assert_status(204);

    TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}", org.id))
        .await
        .assert_status(404);
}

#[tokio::test]
async fn delete_personal_org_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/orgs/{}", auth.org.id))
        .await
        .assert_status(409);
}

#[tokio::test]
async fn delete_org_as_member_returns_403() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Protected Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    TestClient::new()
        .bearer(&member.session.token)
        .delete(&format!("/v1/orgs/{}", org.id))
        .await
        .assert_status(403);
}

// ── GET /v1/orgs/{id}/members ────────────────────────────────────────────────

#[tokio::test]
async fn list_members_shows_creator_as_owner() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Listed Org").await;

    let resp = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}/members", org.id))
        .await
        .assert_status(200)
        .json::<MembersResponse>();

    assert_eq!(resp.members.len(), 1);
    assert_eq!(resp.members[0].user_id, auth.user.id);
    assert_eq!(resp.members[0].role, "owner");
}

#[tokio::test]
async fn list_members_as_non_member_returns_403() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let stranger = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Members Org").await;

    TestClient::new()
        .bearer(&stranger.session.token)
        .get(&format!("/v1/orgs/{}/members", org.id))
        .await
        .assert_status(403);
}

#[tokio::test]
async fn list_members_paginates() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Paginated Members Org").await;
    // add 2 more members so we have 3 total (owner + 2)
    for _ in 0..2 {
        let m = signup(&unique_email(), "correct-horse-battery-staple").await;
        invite_and_accept(org.id, &owner.session.token, &m.session.token, "member").await;
    }

    let page1 = TestClient::new()
        .bearer(&owner.session.token)
        .get(&format!("/v1/orgs/{}/members?limit=2", org.id))
        .await
        .assert_status(200)
        .json::<MembersResponse>();

    assert_eq!(page1.members.len(), 2);
    assert!(page1.has_more);
    let cursor = page1.next_page.expect("must have next_page");

    let page2 = TestClient::new()
        .bearer(&owner.session.token)
        .get(&format!(
            "/v1/orgs/{}/members?limit=2&after={cursor}",
            org.id
        ))
        .await
        .assert_status(200)
        .json::<MembersResponse>();

    assert!(!page2.members.is_empty());
    assert!(!page2.has_more);

    let all_ids: std::collections::HashSet<_> = page1
        .members
        .iter()
        .chain(page2.members.iter())
        .map(|m| m.user_id)
        .collect();
    assert_eq!(all_ids.len(), 3, "all members must appear across pages");
}

// ── PATCH /v1/orgs/{id}/members/{member_id} ──────────────────────────────────

#[tokio::test]
async fn update_member_role_returns_204() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Role Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    // Promote to owner (now two owners).
    TestClient::new()
        .bearer(&owner.session.token)
        .patch(
            &format!("/v1/orgs/{}/members/{}", org.id, member.user.id),
            &serde_json::json!({ "role": "owner" }),
        )
        .await
        .assert_status(204);

    // Demote back — still safe because owner remains.
    TestClient::new()
        .bearer(&owner.session.token)
        .patch(
            &format!("/v1/orgs/{}/members/{}", org.id, member.user.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(204);
}

#[tokio::test]
async fn update_sole_owner_role_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Last Owner Org").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .patch(
            &format!("/v1/orgs/{}/members/{}", org.id, auth.user.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(409);
}

#[tokio::test]
async fn update_member_as_non_owner_returns_403() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member_a = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member_b = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Hierarchy Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member_a.session.token,
        "member",
    )
    .await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member_b.session.token,
        "member",
    )
    .await;

    TestClient::new()
        .bearer(&member_a.session.token)
        .patch(
            &format!("/v1/orgs/{}/members/{}", org.id, member_b.user.id),
            &serde_json::json!({ "role": "owner" }),
        )
        .await
        .assert_status(403);
}

// ── DELETE /v1/orgs/{id}/members/{member_id} ─────────────────────────────────

#[tokio::test]
async fn remove_member_returns_204() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Remove Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    TestClient::new()
        .bearer(&owner.session.token)
        .delete(&format!("/v1/orgs/{}/members/{}", org.id, member.user.id))
        .await
        .assert_status(204);

    let resp = TestClient::new()
        .bearer(&owner.session.token)
        .get(&format!("/v1/orgs/{}/members", org.id))
        .await
        .assert_status(200)
        .json::<MembersResponse>();

    assert!(!resp.members.iter().any(|m| m.user_id == member.user.id));
}

#[tokio::test]
async fn remove_sole_owner_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Sole Owner Org").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/orgs/{}/members/{}", org.id, auth.user.id))
        .await
        .assert_status(409);
}

#[tokio::test]
async fn member_can_remove_themselves_without_owner_permission() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Self-Leave Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    TestClient::new()
        .bearer(&member.session.token)
        .delete(&format!("/v1/orgs/{}/members/{}", org.id, member.user.id))
        .await
        .assert_status(204);
}

// ── POST /v1/orgs/{id}/invitations ───────────────────────────────────────────

#[tokio::test]
async fn create_invitation_returns_token_on_creation() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Invite Org").await;

    let inv = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member", "email": unique_email() }),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>();

    assert!(inv.token.is_some(), "token must be present on creation");
    assert_eq!(inv.org_id, org.id);
}

#[tokio::test]
async fn create_invitation_duplicate_email_returns_409() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Dup Invite Org").await;
    let email = unique_email();

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member", "email": email }),
        )
        .await
        .assert_status(201);

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member", "email": email }),
        )
        .await
        .assert_status(409);
}

#[tokio::test]
async fn create_invitation_as_member_returns_403() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let member = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Gated Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &member.session.token,
        "member",
    )
    .await;

    TestClient::new()
        .bearer(&member.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(403);
}

// ── GET /v1/orgs/{id}/invitations ────────────────────────────────────────────

#[tokio::test]
async fn list_invitations_returns_pending_without_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "List Invites Org").await;

    TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(201);

    let list = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}/invitations", org.id))
        .await
        .assert_status(200)
        .json::<InvitationsResponse>();

    assert_eq!(list.invitations.len(), 1);
    assert!(
        list.invitations[0].token.is_none(),
        "token must not appear in list response"
    );
}

#[tokio::test]
async fn list_invitations_paginates() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Paginated Invites Org").await;
    for _ in 0..3 {
        TestClient::new()
            .bearer(&auth.session.token)
            .post(
                &format!("/v1/orgs/{}/invitations", org.id),
                &serde_json::json!({ "role": "member" }),
            )
            .await
            .assert_status(201);
    }

    let page1 = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}/invitations?limit=2", org.id))
        .await
        .assert_status(200)
        .json::<InvitationsResponse>();

    assert_eq!(page1.invitations.len(), 2);
    assert!(page1.has_more);
    let cursor = page1.next_page.expect("must have next_page");

    let page2 = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!(
            "/v1/orgs/{}/invitations?limit=2&after={cursor}",
            org.id
        ))
        .await
        .assert_status(200)
        .json::<InvitationsResponse>();

    assert_eq!(page2.invitations.len(), 1);
    assert!(!page2.has_more);
}

// ── POST /v1/orgs/{id}/invitations/{inv_id}/resends ──────────────────────────

#[tokio::test]
async fn resend_invitation_rotates_token() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Resend Org").await;

    let original = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>();

    let reissued = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations/{}/resends", org.id, original.id),
            &serde_json::json!({}),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>();

    assert_eq!(
        reissued.id, original.id,
        "resend must keep the same invitation id"
    );
    assert!(reissued.token.is_some(), "resend must return a new token");
    assert_ne!(
        reissued.token, original.token,
        "resend must rotate the token"
    );
}

// ── DELETE /v1/orgs/{id}/invitations/{inv_id} ────────────────────────────────

#[tokio::test]
async fn revoke_invitation_returns_204() {
    let auth = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&auth.session.token, "Revoke Org").await;

    let inv = TestClient::new()
        .bearer(&auth.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>();

    TestClient::new()
        .bearer(&auth.session.token)
        .delete(&format!("/v1/orgs/{}/invitations/{}", org.id, inv.id))
        .await
        .assert_status(204);

    let list = TestClient::new()
        .bearer(&auth.session.token)
        .get(&format!("/v1/orgs/{}/invitations", org.id))
        .await
        .assert_status(200)
        .json::<InvitationsResponse>();

    assert!(
        list.invitations.is_empty(),
        "revoked invitation must not appear in list"
    );
}

// ── Invitation accept flow ────────────────────────────────────────────────────

#[tokio::test]
async fn accept_invitation_adds_member_to_org() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let joiner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Join Org").await;
    invite_and_accept(
        org.id,
        &owner.session.token,
        &joiner.session.token,
        "member",
    )
    .await;

    let resp = TestClient::new()
        .bearer(&owner.session.token)
        .get(&format!("/v1/orgs/{}/members", org.id))
        .await
        .assert_status(200)
        .json::<MembersResponse>();

    assert!(
        resp.members.iter().any(|m| m.user_id == joiner.user.id),
        "joiner not in members list after acceptance"
    );
}

#[tokio::test]
async fn accept_invitation_twice_returns_409() {
    let owner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let joiner = signup(&unique_email(), "correct-horse-battery-staple").await;
    let org = create_org(&owner.session.token, "Double Accept Org").await;

    let inv = TestClient::new()
        .bearer(&owner.session.token)
        .post(
            &format!("/v1/orgs/{}/invitations", org.id),
            &serde_json::json!({ "role": "member" }),
        )
        .await
        .assert_status(201)
        .json::<InvitationResponse>();

    let token = inv.token.unwrap();

    // First acceptance succeeds.
    TestClient::new()
        .bearer(&joiner.session.token)
        .post(
            &format!("/v1/invitations/{}/acceptances?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(204);

    // Second acceptance fails — invitation was consumed.
    TestClient::new()
        .bearer(&joiner.session.token)
        .post(
            &format!("/v1/invitations/{}/acceptances?token={}", inv.id, token),
            &serde_json::json!({}),
        )
        .await
        .assert_status(404);
}
