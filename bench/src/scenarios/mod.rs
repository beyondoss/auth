use std::sync::Arc;

use crate::harness::Scenario;

pub mod authz;
pub mod baseline;
pub mod http;

pub fn all() -> Vec<Arc<dyn Scenario>> {
    let mut v = Vec::new();
    v.extend(baseline::all());
    v.extend(authz::all());
    v
}
