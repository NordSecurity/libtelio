#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod connectivity_check;
pub mod endpoint_providers;
pub mod endpoint_state;
pub mod last_rx_time_provider;
pub mod ping_pong_handler;
pub mod session_keeper;
pub mod upgrade_sync;

pub use connectivity_check::{WireGuardEndpointCandidateChangeEvent, cross_ping_check};
#[cfg(any(test, feature = "mockall"))]
pub use session_keeper::MockSessionKeeperTrait;
pub use session_keeper::{SessionKeeper, SessionKeeperTrait};
#[cfg(any(test, feature = "mockall"))]
pub use upgrade_sync::MockUpgradeSyncTrait;
pub use upgrade_sync::{UpgradeRequest, UpgradeRequestChangeEvent, UpgradeSync, UpgradeSyncTrait};
