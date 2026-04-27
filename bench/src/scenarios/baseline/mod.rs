use std::sync::Arc;

use crate::harness::Scenario;

pub mod indexed_lookup;
pub mod ping;

pub fn all() -> Vec<Arc<dyn Scenario>> {
    vec![
        Arc::new(ping::Ping),
        Arc::new(indexed_lookup::IndexedLookup),
    ]
}
