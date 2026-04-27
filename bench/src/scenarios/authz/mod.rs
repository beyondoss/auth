use std::sync::Arc;

use crate::harness::Scenario;

pub mod bulk_write;
pub mod corpus;
pub mod depth_sweep;
pub mod depth_sweep_cold;
pub mod invalidation_storm;
pub mod multi_decision_serial;
pub mod single_check;

pub fn all() -> Vec<Arc<dyn Scenario>> {
    vec![
        Arc::new(single_check::SingleCheck::new()),
        Arc::new(multi_decision_serial::MultiDecisionSerial::new()),
        Arc::new(depth_sweep::DepthSweep::new(1)),
        Arc::new(depth_sweep::DepthSweep::new(3)),
        Arc::new(depth_sweep::DepthSweep::new(5)),
        Arc::new(depth_sweep::DepthSweep::new(10)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(1)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(3)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(5)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(10)),
        Arc::new(bulk_write::BulkWrite::new(1)),
        Arc::new(bulk_write::BulkWrite::new(10)),
        Arc::new(bulk_write::BulkWrite::new(100)),
        Arc::new(bulk_write::BulkWrite::new(1000)),
        Arc::new(invalidation_storm::InvalidationStorm::new()),
    ]
}
