//! This module is a mock for libmoose API, it logs moose function calls to file.
//!
use std::{fs::File, io::Write};
use telio_utils::telio_log_error;

pub use telio_utils::telio_log_warn;

const LOGFILE_PATH: &str = "events-moose.log";

/// Logs a function call and its arguments to file.
///
/// Parameters:
/// * func_name - Name of the called function.
/// * arg_set   - Contains the arguments passed to the called function, if any.
/// Returns:
/// * The number of bytes written into file or moose::Error otherwise
fn event_log(
    func_name: &str,
    arg_set: Option<Vec<&str>>,
) -> std::result::Result<usize, moose::Error> {
    match get_logfile() {
        Ok(mut file) => {
            let format_string =
                time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] ")
                    .map_err(|_| moose::Error::EventLogError)?;
            let mut buffer = time::OffsetDateTime::now_utc()
                .format(&format_string)
                .map_err(|_| moose::Error::EventLogError)?;
            buffer.push_str(func_name);
            buffer.push('(');
            if let Some(args) = arg_set {
                let mut it = args.iter().peekable();
                while let Some(arg) = it.next() {
                    match it.peek() {
                        Some(_) => buffer.push_str(format!("{}, ", arg).as_str()),
                        None => buffer.push_str(arg),
                    }
                }
            }
            buffer.push_str(")\n");

            Ok(file
                .write(buffer.as_bytes())
                .map_err(|_| moose::Error::EventLogError)?)
        }
        Err(e) => {
            telio_log_error!("Failed to open log file: {}", e);
            Err(moose::Error::EventLogError)
        }
    }
}

fn get_logfile() -> std::io::Result<File> {
    if std::path::Path::new(&LOGFILE_PATH).exists() {
        File::options().append(true).open(LOGFILE_PATH)
    } else {
        let file = File::create(LOGFILE_PATH)?;
        let mut perms = file.metadata()?.permissions();
        // some tests are run by root so we need to set file as world-writable
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        file.set_permissions(perms)?;
        Ok(file)
    }
}

#[allow(missing_docs)]
/// Module that mocks moose items.
pub mod moose {
    use serde::{Deserialize, Serialize};

    /// Mock of moose::LibtelioappLogLevel.
    #[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
    /// value of 'log_level'
    #[serde(rename_all = "lowercase")]
    pub enum LibtelioappLogLevel {
        Info,
        Debug,
        Error,
        Critical,
    }

    /// Logger error
    #[derive(thiserror::Error, Debug)]
    pub enum Error {
        #[error("Logger was not initiated")]
        NotInitiatedError,
        #[error("Failed to log event")]
        EventLogError,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum MooseError {
        Input,
        Version,
        StorageEngine,
        StorageSet,
        StorageGet,
        History,
        Usage,
        Handler,
        QueueDisabled,
        QueueFull,
        ContextNotFound,
        Send,
        NotInitiated,
    }

    /// Logger result
    #[derive(Debug, PartialEq, Eq)]
    pub enum Result {
        Success,
        AlreadyInitiated,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum MooseErrorLevel {
        Warning,
        Error,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum TrackerState {
        Ready,
        AlreadyStarted,
        TrackerDeleted,
        AllTrackersDeleted,
        FileDeleted,
    }

    impl From<TrackerState> for Result {
        fn from(state: TrackerState) -> Result {
            match state {
                TrackerState::Ready => Result::Success,
                TrackerState::AlreadyStarted => Result::AlreadyInitiated,
                _ => unimplemented!("All other cases are not covered by Result enum"),
            }
        }
    }

    impl From<MooseError> for Error {
        fn from(moose_error: MooseError) -> Error {
            match moose_error {
                MooseError::NotInitiated => Error::NotInitiatedError,
                _ => Error::EventLogError,
            }
        }
    }

    pub trait InitCallback: Send {
        fn after_init(&self, result: &std::result::Result<TrackerState, MooseError>);
    }

    pub trait ErrorCallback {
        fn on_error(&self, error_level: MooseErrorLevel, error_code: MooseError, msg: &str);
    }

    /// Initialize logger file with current date and time.
    ///
    /// Parameters:
    /// * event_path    - path of the DB file where events would be stored.
    /// * prod          - whether the events should be sent to production or not
    /// * init_cb       - callback by Moose after succesfull initialization
    /// * error_cb      - callback by Moose to record any errors
    #[allow(unused_variables)]
    pub fn init(
        event_path: String,
        prod: bool,
        init_cb: Box<(dyn InitCallback + 'static)>,
        error_cb: Box<(dyn ErrorCallback + Sync + std::marker::Send + 'static)>,
    ) -> std::result::Result<Result, Error> {
        let result = match super::event_log(
            "init",
            Some(vec![event_path.as_str(), prod.to_string().as_str()]),
        ) {
            Ok(_) => Ok(TrackerState::Ready),
            _ => Err(MooseError::NotInitiated),
        };

        init_cb.after_init(&result);

        match result {
            Ok(r) => Ok(Result::from(r)),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_version(
        app_version: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_version",
            Some(vec![app_version.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_name(
        app_name: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_name",
            Some(vec![app_name.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    /// Mocked moose function.
    pub fn moose_deinit() -> std::result::Result<Result, Error> {
        match super::event_log("moose_deinit", None) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    pub fn set_context_application_libtelioapp_config_currentState_meshnetEnabled(
        val: bool,
    ) -> std::result::Result<Result, Error> {
        let val = val.to_string();
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_meshnetEnabled",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_config_currentState_internalMeshnet_fpNat(
        val: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_internalMeshnet_fpNat",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_config_currentState_internalMeshnet_membersNat(
        val: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_internalMeshnet_membersNat",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_config_currentState_externalLinks(
        val: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_externalLinks",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_config_currentState_internalMeshnet_fp(
        val: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_internalMeshnet_fp",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_config_currentState_internalMeshnet_members(
        val: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_internalMeshnet_members",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn set_context_application_libtelioapp_config_currentState_internalMeshnet_connectivityMatrix(
        val: String,
    ) -> std::result::Result<Result, Error> {
        match super::event_log(
            "set_context_application_libtelioapp_config_currentState_internalMeshnet_connectivityMatrix",
            Some(vec![val.as_str()]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn send_serviceQuality_node_heartbeat(
        connectionDuration: String,
        rtt: String,
        rtt_loss: String,
        rtt6: String,
        rtt6_loss: String,
        sentData: String,
        receivedData: String,
        heartbeatInterval: i32,
        derpConnectionDuration: i32,
        nat_monitoring: String,
        derp_monitoring: String,
    ) -> std::result::Result<Result, Error> {
        let heartbeatIntervalString = heartbeatInterval.to_string();
        let derpConnectionDurationStr = derpConnectionDuration.to_string();
        let args = vec![
            connectionDuration.as_str(),
            rtt.as_str(),
            rtt_loss.as_str(),
            rtt6.as_str(),
            rtt6_loss.as_str(),
            sentData.as_str(),
            receivedData.as_str(),
            heartbeatIntervalString.as_str(),
            derpConnectionDurationStr.as_str(),
            nat_monitoring.as_str(),
            derp_monitoring.as_str(),
        ];

        match super::event_log("send_serviceQuality_node_heartbeat", Some(args)) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn send_serviceQuality_node_disconnect(
        connectionDuration: String,
        rtt: String,
        rtt_loss: String,
        rtt6: String,
        rtt6_loss: String,
        sentData: String,
        receivedData: String,
        heartbeatInterval: i32,
        derpConnectionDuration: i32,
        nat_monitoring: String,
        derp_monitoring: String,
    ) -> std::result::Result<Result, Error> {
        let heartbeatIntervalString = heartbeatInterval.to_string();
        let derpConnectionDurationStr = derpConnectionDuration.to_string();
        let args = vec![
            connectionDuration.as_str(),
            rtt.as_str(),
            rtt_loss.as_str(),
            rtt6.as_str(),
            rtt6_loss.as_str(),
            sentData.as_str(),
            receivedData.as_str(),
            heartbeatIntervalString.as_str(),
            derpConnectionDurationStr.as_str(),
            nat_monitoring.as_str(),
            derp_monitoring.as_str(),
        ];

        match super::event_log("send_serviceQuality_node_disconnect", Some(args)) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }

    /// Mocked moose function.
    pub fn moose_libtelioapp_fetch_context_string(_path: String) -> Option<String> {
        let _ = super::event_log("fetch_context_string", None);
        None
    }

    /// Mocked moose function
    pub fn flush_changes() -> std::result::Result<Result, Error> {
        Ok(Result::Success)
    }

    #[allow(non_snake_case)]
    /// Mocked moose function.
    pub fn send_developer_logging_log(
        arbitraryIntegerValue: i32,
        logLevel: LibtelioappLogLevel,
        message: String,
    ) -> std::result::Result<Result, Error> {
        let arbitraryIntegerValue = arbitraryIntegerValue.to_string();
        let logLevel = format!("{logLevel:?}");

        match super::event_log(
            "send_developer_logging_log",
            Some(vec![
                arbitraryIntegerValue.as_str(),
                logLevel.as_str(),
                message.as_str(),
            ]),
        ) {
            Ok(_) => Ok(Result::Success),
            _ => Err(Error::EventLogError),
        }
    }
}
