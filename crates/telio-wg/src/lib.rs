// #![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(unused_imports)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Interface between [WireGuard](https://wireguard.com/) and the telio library

pub(crate) mod adapter;
pub(crate) mod link_detection;
pub(crate) mod wg;
pub(crate) mod windows;

pub mod uapi;

pub use crate::{
    adapter::{Adapter, AdapterType, Error, FirewallInboundCb, FirewallOutboundCb, Tun},
    link_detection::LinkDetection,
    wg::*,
};

#[cfg(target_os = "windows")]
pub use crate::windows::link_detection_observer::LinkDetectionObserver;
