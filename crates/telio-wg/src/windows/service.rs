#![cfg(windows)]

use std::convert::{TryFrom, TryInto};
use std::time::Duration;
use telio_utils::{telio_log_debug, telio_log_warn, Instant};
use windows::{
    core::{w, Error, Result as WindowsResult, HRESULT, PCWSTR},
    Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_STATUS,
    },
};

pub const DEFAULT_SERVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum WinServiceStatus {
    Stopped = 1,
    Starting = 2,
    Stopping = 3,
    Running = 4,
    Continuing = 5,
    Pausing = 6,
    Paused = 7,
}

impl TryFrom<u32> for WinServiceStatus {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(WinServiceStatus::Stopped),
            2 => Ok(WinServiceStatus::Starting),
            3 => Ok(WinServiceStatus::Stopping),
            4 => Ok(WinServiceStatus::Running),
            5 => Ok(WinServiceStatus::Continuing),
            6 => Ok(WinServiceStatus::Pausing),
            7 => Ok(WinServiceStatus::Paused),
            _ => Err("Unknown service state"),
        }
    }
}

pub fn wait_for_service(service_name: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match is_service_running(service_name) {
            Ok(res) => {
                telio_log_debug!("\"{}\" service is {:?}", service_name, res);
                // TODO: do we need to know, in what exact state is service, or is it enough to know that it is loaded into OS ..?
                return true;
            }
            Err(err) => {
                telio_log_warn!(
                    "Failed to check \"{}\" service status: {:?}",
                    service_name,
                    err
                );
            }
        }
    }

    false
}

fn is_service_running(service_name: &str) -> WindowsResult<WinServiceStatus> {
    let service_name_wide: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let service_name_wide = PCWSTR(service_name_wide.as_ptr());

    unsafe {
        // Open a handle to the Service Control Manager
        let sc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)?;

        // Open a handle to the service
        let service = OpenServiceW(sc_manager, service_name_wide, SERVICE_QUERY_STATUS)?;

        // Query the service status
        let mut status = SERVICE_STATUS::default();
        QueryServiceStatus(service, &mut status)?;

        // Check the current state
        match WinServiceStatus::try_from(status.dwCurrentState.0) {
            Ok(res) => Ok(res),
            Err(e) => Err(Error::new(HRESULT(1), e)),
        }
    }
}
