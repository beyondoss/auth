use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use quick_cache::sync::Cache;
use uuid::Uuid;

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct CheckKey {
    pub subject_id: Arc<str>,
    pub resource_type: Arc<str>,
    pub resource_id: Arc<str>,
    pub permission: Arc<str>,
}

#[derive(Clone)]
struct CheckEntry {
    allowed: bool,
    obj_ver: u64,
    subj_ver: u64,
    computed_at: Instant,
}

pub struct AuthzCache {
    checks: Cache<CheckKey, CheckEntry>,
    sessions: Cache<Uuid, Arc<str>>,
    obj_versions: DashMap<(Arc<str>, Arc<str>), u64>,
    subj_versions: DashMap<Arc<str>, u64>,
    max_age: Duration,
}

impl AuthzCache {
    pub fn new(check_capacity: usize, session_capacity: usize, max_age: Duration) -> Self {
        Self {
            checks: Cache::new(check_capacity),
            sessions: Cache::new(session_capacity),
            obj_versions: DashMap::new(),
            subj_versions: DashMap::new(),
            max_age,
        }
    }

    pub fn get_session(&self, token_id: Uuid) -> Option<Arc<str>> {
        self.sessions.get(&token_id)
    }

    pub fn insert_session(&self, token_id: Uuid, subject_id: Arc<str>) {
        self.sessions.insert(token_id, subject_id);
    }

    pub fn invalidate_session(&self, token_id: Uuid) {
        self.sessions.remove(&token_id);
    }

    pub fn get_check(&self, key: &CheckKey) -> Option<bool> {
        let entry = self.checks.get(key)?;
        if entry.computed_at.elapsed() > self.max_age {
            return None;
        }
        let obj_ver = self
            .obj_versions
            .get(&(key.resource_type.clone(), key.resource_id.clone()))
            .map(|v| *v)
            .unwrap_or(0);
        let subj_ver = self
            .subj_versions
            .get(&key.subject_id)
            .map(|v| *v)
            .unwrap_or(0);
        if entry.obj_ver != obj_ver || entry.subj_ver != subj_ver {
            return None;
        }
        Some(entry.allowed)
    }

    pub fn insert_check(&self, key: CheckKey, allowed: bool) {
        let obj_ver = self
            .obj_versions
            .get(&(key.resource_type.clone(), key.resource_id.clone()))
            .map(|v| *v)
            .unwrap_or(0);
        let subj_ver = self
            .subj_versions
            .get(&key.subject_id)
            .map(|v| *v)
            .unwrap_or(0);
        self.checks.insert(
            key,
            CheckEntry {
                allowed,
                obj_ver,
                subj_ver,
                computed_at: Instant::now(),
            },
        );
    }

    pub fn invalidate_for_write(&self, object_type: &str, object_id: &str, subject_id: &str) {
        self.obj_versions
            .entry((Arc::from(object_type), Arc::from(object_id)))
            .and_modify(|v| *v += 1)
            .or_insert(1);
        self.subj_versions
            .entry(Arc::from(subject_id))
            .and_modify(|v| *v += 1)
            .or_insert(1);
    }
}
