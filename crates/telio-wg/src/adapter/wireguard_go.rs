#[cfg(windows)]
use wg_go_rust_wrapper::{
    wg_go_free_cmd_res, wg_go_get_adapter_luid, wg_go_get_proxy_listen_port, wg_go_get_wg_socket,
    wg_go_log_cb, wg_go_logger_fn, wg_go_send_uapi_cmd, wg_go_start_named, wg_go_start_with_tun,
    wg_go_stop, CallWindowsStaticGoRuntimeInit,
};

pub struct WireguardGo {
    handle: i32,
}

use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{self, Cmd, Response};

use async_trait::async_trait;
use futures::future::BoxFuture;
use libc::{c_char, c_int};
use std::ffi::{c_void, CStr, CString};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to start wireguard-go with result {0}")]
    FailedToStart(i32),

    #[error("failed to get wireguard-go fd: {0}")]
    FailedToGetWgSocket(String),
}

unsafe extern "C" fn call_log(_ctx: *mut c_void, l: c_int, msg: *const c_char) {
    let c_str: &CStr = CStr::from_ptr(msg);
    #[allow(clippy::unwrap_used)]
    let str_slice: &str = c_str.to_str().unwrap();
    match l {
        1 => telio_log_error!("wg_go: crit {}", str_slice),
        2 => telio_log_error!("wg_go: {}", str_slice),
        3 => telio_log_warn!("wg_go: {}", str_slice),
        4 => telio_log_info!("wg_go: {}", str_slice),
        5 => telio_log_debug!("wg_go: {}", str_slice),
        6 => telio_log_trace!("wg_go: {}", str_slice),
        _ => telio_log_error!("unknown log level"),
    }
}

impl WireguardGo {
    pub fn start(
        name: &str,
        #[allow(unused_variables)] native_tun: Option<NativeTun>,
    ) -> Result<Self, AdapterError> {
        let ctx = std::ptr::null_mut();
        let c_name = CString::new(name).map_err(|_| {
            AdapterError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Name parameter is null",
            ))
        })?;

        unsafe {
            // Workaround for hanging wireguard-go due to missing Go runtime init when building with MSVC toolchain.
            #[cfg(windows)]
            CallWindowsStaticGoRuntimeInit();
        }

        let handle = unsafe {
            match native_tun {
                #[cfg(unix)]
                Some(tun) => wg_go_start_with_tun(tun as i32, wg_go_log_cb { ctx, cb: call_log }),
                #[cfg(windows)]
                Some(_tun) => wg_go_start_with_tun(0, wg_go_log_cb { ctx, cb: call_log }),
                None => wg_go_start_named(
                    c_name.as_ptr() as *const c_char,
                    wg_go_log_cb { ctx, cb: call_log },
                ),
            }
        };

        if handle < 0 {
            return Err(AdapterError::WireguardGo(Error::FailedToStart(handle)));
        }

        Ok(WireguardGo { handle })
    }

    #[allow(clippy::unwrap_used)]
    async fn send_uapi_cmd_str(&self, cmd: &str) -> String {
        let cmd = cmd.to_owned();
        let c_cmd = CString::new(cmd).unwrap();
        let c_buf = unsafe { wg_go_send_uapi_cmd(self.handle, c_cmd.as_ptr() as *const c_char) };
        if c_buf.is_null() {
            return "".to_owned();
        }
        let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
        let str_slice: &str = c_str.to_str().unwrap();
        let str_buf: String = str_slice.to_owned();
        free_cmd_res(c_buf);
        str_buf
    }
}

#[async_trait]
impl Adapter for WireguardGo {
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, AdapterError> {
        let res = self.send_uapi_cmd_str(&cmd.to_string()).await;
        let mut res = uapi::response_from_str(&res)?;

        // Augment interface with aditional info on get
        if matches!(cmd, Cmd::Get) {
            let port = unsafe { wg_go_get_proxy_listen_port(self.handle) };
            if port != 0 {
                if let Some(interface) = &mut res.interface {
                    interface.proxy_listen_port = Some(port);
                }
            }
        }

        Ok(res)
    }

    fn get_adapter_luid(&self) -> u64 {
        unsafe { wg_go_get_adapter_luid(self.handle) }
    }

    async fn stop(&self) {
        unsafe {
            wg_go_stop(self.handle);
        }
    }

    /// On Android returns file descriptor; Other platforms -1
    fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, AdapterError> {
        let c_buf = unsafe { wg_go_get_wg_socket(self.handle, ipv6) };
        if c_buf.is_null() {
            return Ok(None); // Not supported by platform
        }
        let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
        let json: String = c_str.to_str()?.to_owned();
        if json.is_empty() {
            return Ok(None); // Not supported by platform
        }

        #[derive(serde::Deserialize)]
        struct GetWgSocketResult {
            fd: i32,
            err: String,
        }
        let socket_result: GetWgSocketResult = serde_json::from_str(json.as_ref())?;

        if !socket_result.err.is_empty() {
            return Err(AdapterError::WireguardGo(Error::FailedToGetWgSocket(
                socket_result.err,
            )));
        }

        if socket_result.fd >= 0 {
            Ok(Some(socket_result.fd))
        } else {
            Ok(None) // Not supported by platform
        }
    }
}

/// Safety: wg_go_stop is synchronious,
/// after it call_log will never be called again with dangling pointer.
/// As such it is safe to treat adapter as Sync and Send.
unsafe impl Sync for WireguardGo {}
unsafe impl Send for WireguardGo {}

fn free_cmd_res(resp: *const c_char) {
    unsafe { wg_go_free_cmd_res(resp) }
}
