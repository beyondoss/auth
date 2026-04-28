use std::sync::Arc;

use crate::harness::Scenario;

pub mod batch_check;
pub mod bulk_write;
pub mod native_batch_check;
pub mod corpus;
pub mod depth_sweep;
pub mod depth_sweep_cold;
pub mod early_exit;
pub mod early_exit_v2;
pub mod hierarchy_check;
pub mod multi_decision_serial;
pub mod read_write_mix;
pub mod scale_sweep;
pub mod single_check;

/// Chain depths seeded into the shared corpus. Kept in sync with the depth
/// values used by `depth_sweep` and `depth_sweep_cold` so a single seed pass
/// covers both.
pub const CHAIN_DEPTHS: &[(usize, usize)] = &[(1, 50_000), (3, 50_000), (5, 50_000), (10, 50_000)];

/// Noise depths for the mixed-depth early-exit corpus. Kept in sync with the
/// noise values used by `early_exit` scenarios.
pub const MIXED_NOISE_DEPTHS: &[(usize, usize)] = &[(5, 50_000), (10, 50_000)];

pub fn all() -> Vec<Arc<dyn Scenario>> {
    vec![
        Arc::new(single_check::SingleCheck::new()),
        Arc::new(multi_decision_serial::MultiDecisionSerial::new()),
        Arc::new(hierarchy_check::HierarchyOrChainOld::new()),
        Arc::new(hierarchy_check::HierarchyOrChainNew::new()),
        Arc::new(hierarchy_check::HierarchyMulti::new()),
        Arc::new(batch_check::BatchCheck::new(4)),
        Arc::new(batch_check::BatchCheck::new(16)),
        Arc::new(batch_check::BatchCheck::new(64)),
        Arc::new(native_batch_check::NativeBatchCheck::new(64, false)),
        Arc::new(native_batch_check::NativeBatchCheck::new(64, true)),
        Arc::new(depth_sweep::DepthSweep::new(1)),
        Arc::new(depth_sweep::DepthSweep::new(3)),
        Arc::new(depth_sweep::DepthSweep::new(5)),
        Arc::new(depth_sweep::DepthSweep::new(10)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(1)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(3)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(5)),
        Arc::new(depth_sweep_cold::DepthSweepCold::new(10)),
        Arc::new(early_exit::EarlyExit::new(5)),
        Arc::new(early_exit::EarlyExit::new(10)),
        Arc::new(early_exit_v2::EarlyExitV2::new(5)),
        Arc::new(early_exit_v2::EarlyExitV2::new(10)),
        Arc::new(bulk_write::BulkWrite::new(1)),
        Arc::new(bulk_write::BulkWrite::new(10)),
        Arc::new(bulk_write::BulkWrite::new(100)),
        Arc::new(bulk_write::BulkWrite::new(1000)),
        Arc::new(read_write_mix::ReadWriteMix::new()),
        Arc::new(scale_sweep::ScaleSweep::new(10_000)),
        Arc::new(scale_sweep::ScaleSweep::new(100_000)),
        Arc::new(scale_sweep::ScaleSweep::new(1_000_000)),
    ]
}
