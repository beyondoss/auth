use uuid::Uuid;

use crate::helpers::{db_conn, test_env};

// Each test uses a unique run ID so tests can run in parallel without touching
// each other's rows. The testcontainer is ephemeral so accumulated rows are fine.
fn uid() -> String {
    Uuid::now_v7().simple().to_string()
}

// Ensure the named object_type partition exists. The application creates partitions
// JIT via the API, but these tests insert raw SQL and need the partition upfront.
// Tolerates concurrent creation (duplicate_table / 42P07) from parallel tests.
async fn ensure_partition(conn: &mut sqlx::PgConnection, object_type: &str) {
    let table = format!("authz_relations_{object_type}");
    let result = sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS auth.{table} \
         PARTITION OF auth.authz_relations FOR VALUES IN ('{object_type}')"
    ))
    .execute(&mut *conn)
    .await;
    if let Err(sqlx::Error::Database(e)) = &result {
        // 42P07 = duplicate_table: another parallel test won the race — that's fine.
        if e.code().as_deref() != Some("42P07") {
            result.unwrap();
        }
    } else {
        result.unwrap();
    }
}

async fn grant(
    conn: &mut sqlx::PgConnection,
    obj_type: &str,
    obj_id: &str,
    relation: &str,
    subject_id: &str,
) {
    sqlx::query(
        "INSERT INTO auth.authz_relations \
         (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation) \
         VALUES ($1, $2, $3, $4, NULL, NULL)",
    )
    .bind(obj_type)
    .bind(obj_id)
    .bind(relation)
    .bind(subject_id)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn grant_set(
    conn: &mut sqlx::PgConnection,
    obj_type: &str,
    obj_id: &str,
    relation: &str,
    set_type: &str,
    set_id: &str,
    set_rel: &str,
) {
    sqlx::query(
        "INSERT INTO auth.authz_relations \
         (object_type, object_id, relation, subject_id, subject_set_type, subject_set_relation) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(obj_type)
    .bind(obj_id)
    .bind(relation)
    .bind(set_id)
    .bind(set_type)
    .bind(set_rel)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn check(
    conn: &mut sqlx::PgConnection,
    subject: &str,
    relation: &str,
    obj_type: &str,
    obj_id: &str,
) -> bool {
    sqlx::query_scalar("SELECT auth.authz_check($1, $2, $3, $4)")
        .bind(subject)
        .bind(relation)
        .bind(obj_type)
        .bind(obj_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
}

// ── BFS: direct grants ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_bfs_direct_grant_allows() {
    let _ = test_env();
    let id = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    grant(&mut conn, "doc", &id, "viewer", "user:alice").await;
    assert!(check(&mut conn, "user:alice", "viewer", "doc", &id).await);
}

#[tokio::test]
async fn test_bfs_no_grant_denies() {
    let _ = test_env();
    let id = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    assert!(!check(&mut conn, "user:alice", "viewer", "doc", &id).await);
}

#[tokio::test]
async fn test_bfs_wrong_relation_denies() {
    let _ = test_env();
    let id = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    grant(&mut conn, "doc", &id, "editor", "user:alice").await;
    assert!(!check(&mut conn, "user:alice", "viewer", "doc", &id).await);
}

#[tokio::test]
async fn test_bfs_wrong_object_denies() {
    let _ = test_env();
    let id = uid();
    let other = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    grant(&mut conn, "doc", &id, "viewer", "user:alice").await;
    assert!(!check(&mut conn, "user:alice", "viewer", "doc", &other).await);
}

// ── BFS: subject-set expansion ────────────────────────────────────────────────

#[tokio::test]
async fn test_bfs_single_hop_group_membership() {
    let _ = test_env();
    let doc = uid();
    let grp = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    ensure_partition(&mut conn, "group").await;
    // alice is a member of group:grp
    grant(&mut conn, "group", &grp, "member", "user:alice").await;
    // doc:doc grants viewer to group:grp/member
    grant_set(&mut conn, "doc", &doc, "viewer", "group", &grp, "member").await;
    assert!(check(&mut conn, "user:alice", "viewer", "doc", &doc).await);
}

#[tokio::test]
async fn test_bfs_two_hop_group_membership() {
    let _ = test_env();
    let doc = uid();
    let grp_a = uid();
    let grp_b = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    ensure_partition(&mut conn, "group").await;
    // alice → grp_a → grp_b → doc viewer
    grant(&mut conn, "group", &grp_a, "member", "user:alice").await;
    grant_set(
        &mut conn, "group", &grp_b, "member", "group", &grp_a, "member",
    )
    .await;
    grant_set(&mut conn, "doc", &doc, "viewer", "group", &grp_b, "member").await;
    assert!(check(&mut conn, "user:alice", "viewer", "doc", &doc).await);
}

#[tokio::test]
async fn test_bfs_unrelated_group_denied() {
    let _ = test_env();
    let doc = uid();
    let grp_a = uid();
    let grp_b = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    ensure_partition(&mut conn, "group").await;
    // alice is in grp_a, but doc viewer is for grp_b
    grant(&mut conn, "group", &grp_a, "member", "user:alice").await;
    grant_set(&mut conn, "doc", &doc, "viewer", "group", &grp_b, "member").await;
    assert!(!check(&mut conn, "user:alice", "viewer", "doc", &doc).await);
}

// ── BFS: multi-relation OR ────────────────────────────────────────────────────

#[tokio::test]
async fn test_bfs_multi_relation_matches_second() {
    let _ = test_env();
    let id = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    grant(&mut conn, "doc", &id, "editor", "user:alice").await;
    let result: bool =
        sqlx::query_scalar("SELECT auth.authz_check($1, ARRAY['viewer','editor'], $2, $3)")
            .bind("user:alice")
            .bind("doc")
            .bind(&id)
            .fetch_one(&mut conn)
            .await
            .unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_bfs_multi_relation_all_miss_denies() {
    let _ = test_env();
    let id = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    let result: bool =
        sqlx::query_scalar("SELECT auth.authz_check($1, ARRAY['viewer','editor'], $2, $3)")
            .bind("user:alice")
            .bind("doc")
            .bind(&id)
            .fetch_one(&mut conn)
            .await
            .unwrap();
    assert!(!result);
}

// ── Batch: order and correctness ──────────────────────────────────────────────

#[tokio::test]
async fn test_bfs_batch_order_preserved() {
    let _ = test_env();
    let id1 = uid();
    let id2 = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    grant(&mut conn, "doc", &id1, "viewer", "user:alice").await;
    // alice→doc:id1=true, bob→doc:id2=false
    let results: Vec<bool> =
        sqlx::query_scalar("SELECT unnest(auth.authz_check_batch($1, $2, $3, $4))")
            .bind(vec!["user:alice", "user:bob"])
            .bind(vec!["viewer", "viewer"])
            .bind(vec!["doc", "doc"])
            .bind(vec![id1.as_str(), id2.as_str()])
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert_eq!(results, vec![true, false]);
}

#[tokio::test]
async fn test_bfs_parallel_batch_matches_sequential() {
    let _ = test_env();
    let id1 = uid();
    let id2 = uid();
    let grp = uid();
    let mut conn = db_conn().await;
    ensure_partition(&mut conn, "doc").await;
    ensure_partition(&mut conn, "group").await;
    grant(&mut conn, "doc", &id1, "viewer", "user:alice").await;
    grant_set(&mut conn, "doc", &id2, "viewer", "group", &grp, "member").await;
    grant(&mut conn, "group", &grp, "member", "user:bob").await;

    let subjects = vec!["user:alice", "user:bob", "user:carol"];
    let relations = vec!["viewer", "viewer", "viewer"];
    let types = vec!["doc", "doc", "doc"];
    let ids = vec![id1.as_str(), id2.as_str(), id1.as_str()];

    let seq: Vec<bool> =
        sqlx::query_scalar("SELECT unnest(auth.authz_check_batch($1, $2, $3, $4))")
            .bind(&subjects)
            .bind(&relations)
            .bind(&types)
            .bind(&ids)
            .fetch_all(&mut conn)
            .await
            .unwrap();

    let par: Vec<bool> =
        sqlx::query_scalar("SELECT unnest(auth.authz_check_parallel_batch($1, $2, $3, $4))")
            .bind(&subjects)
            .bind(&relations)
            .bind(&types)
            .bind(&ids)
            .fetch_all(&mut conn)
            .await
            .unwrap();

    assert_eq!(seq, vec![true, true, false]);
    assert_eq!(seq, par);
}
