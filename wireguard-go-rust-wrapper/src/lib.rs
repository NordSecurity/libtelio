use libc::{c_char, c_int, int32_t};
use std::ffi::c_void;
use std::sync::Once;

extern "C" {
    pub fn wg_go_start_named(name: *const c_char, log: wg_go_log_cb) -> i32;
    pub fn wg_go_start_with_tun(fd: i32, log: wg_go_log_cb) -> i32;
    pub fn wg_go_send_uapi_cmd(handle: i32, cmd: *const c_char) -> *const c_char;
    pub fn wg_go_get_wg_socket(handle: i32, ipv6: bool) -> *const c_char;
    pub fn wg_go_free_cmd_res(resp: *const c_char);
    pub fn wg_go_stop(handle: i32);
    pub fn wg_go_get_adapter_luid(handle: i32) -> u64;
    /// Get a listen port bound to local uapi port
    pub fn wg_go_get_proxy_listen_port(handle: i32) -> u16;
}

#[allow(non_camel_case_types)]
pub type wg_go_logger_fn = unsafe extern "C" fn(*mut c_void, c_int, *const c_char);

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct wg_go_log_cb {
    pub ctx: *mut c_void,
    pub cb: wg_go_logger_fn,
}

// Workaround for hanging wireguard-go due to missing Go runtime init when building with MSVC toolchain.
extern "C" {
    pub fn CallWindowsStaticGoRuntimeInit();
}
