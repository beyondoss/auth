use std::sync::Arc;

use crate::harness::Scenario;

pub mod authz;

pub fn all() -> Vec<Arc<dyn Scenario>> {
    let mut v = Vec::new();
    v.extend(authz::all());
    v
}
