use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

struct VersionTable {
    slots: Box<[AtomicU64]>,
    mask: usize,
}

impl VersionTable {
    fn new(size: usize) -> Self {
        let size = size.next_power_of_two();
        let slots = (0..size).map(|_| AtomicU64::new(0)).collect();
        Self {
            slots,
            mask: size - 1,
        }
    }

    fn get(&self, h: u64) -> u64 {
        self.slots[h as usize & self.mask].load(Ordering::Acquire)
    }

    fn bump(&self, h: u64) {
        self.slots[h as usize & self.mask].fetch_add(1, Ordering::Release);
    }
}

fn hash_one(val: impl Hash) -> u64 {
    use std::hash::BuildHasher;
    static HASHER: std::sync::LazyLock<std::hash::RandomState> =
        std::sync::LazyLock::new(std::hash::RandomState::new);
    HASHER.hash_one(val)
}

pub struct AuthzCache {
    checks: Cache<CheckKey, CheckEntry>,
    sessions: Cache<Uuid, Arc<str>>,
    obj_versions: VersionTable,
    subj_versions: VersionTable,
    max_age: Duration,
}

impl AuthzCache {
    pub fn new(check_capacity: usize, session_capacity: usize, max_age: Duration) -> Self {
        Self {
            checks: Cache::new(check_capacity),
            sessions: Cache::new(session_capacity),
            obj_versions: VersionTable::new(4096),
            subj_versions: VersionTable::new(4096),
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
            .get(hash_one((&key.resource_type, &key.resource_id)));
        let subj_ver = self.subj_versions.get(hash_one(&key.subject_id));
        if entry.obj_ver != obj_ver || entry.subj_ver != subj_ver {
            return None;
        }
        Some(entry.allowed)
    }

    pub fn insert_check(&self, key: CheckKey, allowed: bool) {
        let obj_hash = hash_one((&key.resource_type, &key.resource_id));
        let subj_hash = hash_one(&key.subject_id);
        let obj_ver = self.obj_versions.get(obj_hash);
        let subj_ver = self.subj_versions.get(subj_hash);
        self.checks.insert(
            key.clone(),
            CheckEntry {
                allowed,
                obj_ver,
                subj_ver,
                computed_at: Instant::now(),
            },
        );
        // If a write invalidated between our version-read and our insert, evict immediately
        // so we don't serve a stale decision.
        if self.obj_versions.get(obj_hash) != obj_ver
            || self.subj_versions.get(subj_hash) != subj_ver
        {
            self.checks.remove(&key);
        }
    }

    pub fn invalidate_for_write(&self, object_type: &str, object_id: &str, subject_id: &str) {
        self.obj_versions.bump(hash_one((object_type, object_id)));
        self.subj_versions.bump(hash_one(subject_id));
    }
}
