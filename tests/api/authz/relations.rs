use crate::helpers::{TestClient, db_conn};

use super::*;

// ── Write ──────────────────────────────────────────────────────────────────────

/// [x] write_direct_relation_returns_201
#[tokio::test]
async fn write_direct_relation_returns_201() {
    let _guard = with_schema().await;
    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &direct_rel("document", &uid(), "owner", &uid()),
        )
        .await
        .assert_status(201);
}

/// [x] write_subject_set_relation_returns_201
#[tokio::test]
async fn write_subject_set_relation_returns_201() {
    let _guard = with_schema().await;
    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &set_rel("document", &uid(), "editor", &uid(), "group", "member"),
        )
        .await
        .assert_status(201);
}

/// [x] write_direct_relation_is_idempotent
/// ON CONFLICT DO NOTHING: writing the same tuple twice must not insert a second row.
#[tokio::test]
async fn write_direct_relation_is_idempotent() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());
    let body = direct_rel("document", &doc, "owner", &user);

    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);

    let mut conn = db_conn().await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth.authz_relations WHERE object_id = $1 AND subject_id = $2",
    )
    .bind(&doc)
    .bind(&user)
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(count, 1, "duplicate write must not insert a second row");
}

/// [x] write_subject_set_relation_is_idempotent
#[tokio::test]
async fn write_subject_set_relation_is_idempotent() {
    let _guard = with_schema().await;
    let (doc, group) = (uid(), uid());
    let body = set_rel("document", &doc, "editor", &group, "group", "member");

    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);

    let mut conn = db_conn().await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth.authz_relations WHERE object_id = $1 AND subject_id = $2",
    )
    .bind(&doc)
    .bind(&group)
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

/// [x] write_creates_partition_jit
/// The first write for a new object_type must cause a dedicated list partition to be
/// created. Subsequent writes hit the in-memory cache and skip the DDL round-trip.
#[tokio::test]
async fn write_creates_partition_jit() {
    let _guard = with_schema().await;
    // Build a valid identifier: 't' + first 16 hex chars of a v7 UUID.
    let custom_type = format!("t{}", &uid()[..16]);

    TestClient::new()
        .admin()
        .post(
            "/v1/authz/relations",
            &direct_rel(&custom_type, &uid(), "owner", &uid()),
        )
        .await
        .assert_status(201);

    let mut conn = db_conn().await;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM information_schema.tables
              WHERE table_schema = 'auth'
                AND table_name   = $1
         )",
    )
    .bind(format!("authz_relations_{custom_type}"))
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert!(
        exists,
        "partition table must be created on first write for a new object_type"
    );
}

// ── Delete ─────────────────────────────────────────────────────────────────────

/// [x] delete_existing_direct_relation_returns_204
#[tokio::test]
async fn delete_existing_direct_relation_returns_204() {
    let _guard = with_schema().await;
    let body = direct_rel("document", &uid(), "owner", &uid());
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &body)
        .await
        .assert_status(204);
}

/// [x] delete_existing_subject_set_relation_returns_204
#[tokio::test]
async fn delete_existing_subject_set_relation_returns_204() {
    let _guard = with_schema().await;
    let body = set_rel("document", &uid(), "editor", &uid(), "group", "member");
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &body)
        .await
        .assert_status(204);
}

/// [x] delete_nonexistent_returns_404
#[tokio::test]
async fn delete_nonexistent_returns_404() {
    let _guard = with_schema().await;
    let body = direct_rel("document", &uid(), "owner", &uid());
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &body)
        .await
        .assert_status(404);
}

/// [x] delete_direct_body_does_not_match_subject_set_row
/// A subject-set tuple (subject_set_type IS NOT NULL) and a direct tuple with the
/// same subject_id are distinct rows. Deleting with a direct body must not match the
/// subject-set row — the IS NOT DISTINCT FROM NULL semantics keep them separate.
#[tokio::test]
async fn delete_direct_body_does_not_match_subject_set_row() {
    let _guard = with_schema().await;
    let (doc, group) = (uid(), uid());

    let ss_body = set_rel("document", &doc, "editor", &group, "group", "member");
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &ss_body)
        .await
        .assert_status(201);

    // Same subject_id but no type/relation fields — direct body must not match the set row.
    let direct_body = direct_rel("document", &doc, "editor", &group);
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &direct_body)
        .await
        .assert_status(404);
}

/// [x] delete_subject_set_body_does_not_match_direct_row
#[tokio::test]
async fn delete_subject_set_body_does_not_match_direct_row() {
    let _guard = with_schema().await;
    let (doc, user) = (uid(), uid());

    let direct_body = direct_rel("document", &doc, "owner", &user);
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &direct_body)
        .await
        .assert_status(201);

    // Adding type/relation fields to the subject turns it into a subject-set body.
    let ss_body = set_rel("document", &doc, "owner", &user, "user", "self");
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &ss_body)
        .await
        .assert_status(404);
}

/// [x] delete_second_call_returns_404
#[tokio::test]
async fn delete_second_call_returns_404() {
    let _guard = with_schema().await;
    let body = direct_rel("document", &uid(), "owner", &uid());
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &body)
        .await
        .assert_status(201);
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &body)
        .await
        .assert_status(204);
    TestClient::new()
        .admin()
        .delete_json("/v1/authz/relations", &body)
        .await
        .assert_status(404);
}

// ── Batch ──────────────────────────────────────────────────────────────────────

fn batch_body(
    writes: Vec<serde_json::Value>,
    deletes: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({"writes": writes, "deletes": deletes})
}

/// [x] batch_writes_only_returns_correct_count
#[tokio::test]
async fn batch_writes_only_returns_correct_count() {
    let _guard = with_schema().await;
    let body = batch_body(
        vec![
            direct_rel("document", &uid(), "owner", &uid()),
            direct_rel("document", &uid(), "editor", &uid()),
        ],
        vec![],
    );
    let res = TestClient::new()
        .admin()
        .patch("/v1/authz/relations", &body)
        .await
        .assert_status(200)
        .json::<BatchRelationResponse>();
    assert_eq!(res.written, 2);
    assert_eq!(res.deleted, 0);
}

/// [x] batch_deletes_only_returns_correct_count
#[tokio::test]
async fn batch_deletes_only_returns_correct_count() {
    let _guard = with_schema().await;
    let rel = direct_rel("document", &uid(), "owner", &uid());
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &rel)
        .await
        .assert_status(201);

    let res = TestClient::new()
        .admin()
        .patch("/v1/authz/relations", &batch_body(vec![], vec![rel]))
        .await
        .assert_status(200)
        .json::<BatchRelationResponse>();
    assert_eq!(res.written, 0);
    assert_eq!(res.deleted, 1);
}

/// [x] batch_mixed_write_and_delete_atomic
/// Writes and deletes committed in one transaction: both effects must land or neither does.
#[tokio::test]
async fn batch_mixed_write_and_delete_atomic() {
    let _guard = with_schema().await;
    let (doc_a, doc_b, user) = (uid(), uid(), uid());

    let rel_a = direct_rel("document", &doc_a, "owner", &user);
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &rel_a)
        .await
        .assert_status(201);

    let rel_b = direct_rel("document", &doc_b, "editor", &user);
    let res = TestClient::new()
        .admin()
        .patch("/v1/authz/relations", &batch_body(vec![rel_b], vec![rel_a]))
        .await
        .assert_status(200)
        .json::<BatchRelationResponse>();
    assert_eq!(res.written, 1);
    assert_eq!(res.deleted, 1);

    let mut conn = db_conn().await;
    let a_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth.authz_relations WHERE object_id = $1")
            .bind(&doc_a)
            .fetch_one(&mut conn)
            .await
            .unwrap();
    let b_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth.authz_relations WHERE object_id = $1")
            .bind(&doc_b)
            .fetch_one(&mut conn)
            .await
            .unwrap();
    assert_eq!(a_count, 0, "deleted relation must be gone");
    assert_eq!(b_count, 1, "written relation must exist");
}

/// [x] batch_empty_returns_zero_counts
#[tokio::test]
async fn batch_empty_returns_zero_counts() {
    let _guard = with_schema().await;
    let res = TestClient::new()
        .admin()
        .patch("/v1/authz/relations", &batch_body(vec![], vec![]))
        .await
        .assert_status(200)
        .json::<BatchRelationResponse>();
    assert_eq!(res.written, 0);
    assert_eq!(res.deleted, 0);
}

/// [x] batch_idempotent_write_counts_zero
/// ON CONFLICT DO NOTHING: re-writing an existing tuple is silently ignored and
/// reported as written = 0 (rows_affected = 0).
#[tokio::test]
async fn batch_idempotent_write_counts_zero() {
    let _guard = with_schema().await;
    let rel = direct_rel("document", &uid(), "owner", &uid());
    TestClient::new()
        .admin()
        .post("/v1/authz/relations", &rel)
        .await
        .assert_status(201);

    let res = TestClient::new()
        .admin()
        .patch("/v1/authz/relations", &batch_body(vec![rel], vec![]))
        .await
        .assert_status(200)
        .json::<BatchRelationResponse>();
    assert_eq!(
        res.written, 0,
        "duplicate write must count as 0 via ON CONFLICT DO NOTHING"
    );
}

/// [x] batch_delete_nonexistent_counts_zero
/// Deleting a tuple that does not exist is not an error; it simply contributes 0 to
/// the deleted count.
#[tokio::test]
async fn batch_delete_nonexistent_counts_zero() {
    let _guard = with_schema().await;
    let res = TestClient::new()
        .admin()
        .patch(
            "/v1/authz/relations",
            &batch_body(
                vec![],
                vec![direct_rel("document", &uid(), "owner", &uid())],
            ),
        )
        .await
        .assert_status(200)
        .json::<BatchRelationResponse>();
    assert_eq!(res.deleted, 0, "missing delete must count as 0, not error");
}

// ── Partition creation ─────────────────────────────────────────────────────────

/// [x] concurrent_first_write_creates_partition_exactly_once
/// When multiple concurrent requests are the first to write a new object_type,
/// ensure_partition must create exactly one partition table despite the race.
/// All requests must succeed (idempotent ON CONFLICT DO NOTHING on the relation).
#[tokio::test]
async fn concurrent_first_write_creates_partition_exactly_once() {
    let _guard = with_schema().await;
    // Fresh type name not seen by this server process — guarantees a cold partition cache.
    let custom_type = format!("t{}", &uid()[..16]);
    let body = direct_rel(&custom_type, &uid(), "owner", &uid());

    let (r1, r2, r3) = tokio::join!(
        TestClient::new().admin().post("/v1/authz/relations", &body),
        TestClient::new().admin().post("/v1/authz/relations", &body),
        TestClient::new().admin().post("/v1/authz/relations", &body),
    );

    assert_eq!(r1.status(), 201);
    assert_eq!(r2.status(), 201);
    assert_eq!(r3.status(), 201);

    let mut conn = db_conn().await;
    let partition_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = 'auth' AND table_name = $1",
    )
    .bind(format!("authz_relations_{custom_type}"))
    .fetch_one(&mut conn)
    .await
    .unwrap();

    assert_eq!(
        partition_count, 1,
        "exactly one partition must be created despite concurrent first-writes"
    );
}
