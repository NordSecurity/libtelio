#![deny(missing_docs)]

//! Network monitor module
pub mod monitor;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
/// Utility to get monitor network on apple
pub mod mac;

#[cfg(target_os = "linux")]
/// Utility to get monitor network on linux
pub mod linux;

#[cfg(target_os = "windows")]
/// Utility to get monitor network on windows
pub mod windows;
