#![deny(missing_docs)]
#![allow(unused_imports)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Interface between [WireGuard](https://wireguard.com/) and the telio library

pub(crate) mod adapter;
pub(crate) mod wg;
pub(crate) mod windows;

pub mod uapi;

mod link_detection;

use telio_model::PublicKey;

pub use crate::{
    adapter::{Adapter, AdapterType, Error, FirewallCb, Tun},
    wg::*,
};

/// Event used for triggering connections downgrade
#[derive(Clone, Default)]
pub struct DowngradeEvent {
    /// The list of peers proposed for downgrade
    pub to_be_downgraded: Vec<PublicKey>,
}
