//! Config validation checks

use telio_utils::telio_log_debug;

/// Nickname validation checks (RFC #009)
pub fn validate_nickname(name: &str) -> bool {
    if name.len() > 25 {
        telio_log_debug!("Nickname is too long");
        return false;
    }
    if name.is_empty() {
        telio_log_debug!("Nickname is empty");
        return false;
    }
    if name.contains(' ') {
        telio_log_debug!("Nickname contains spaces");
        return false;
    }
    if name.contains("--") {
        telio_log_debug!("Nickname contains double hyphens");
        return false;
    }
    if name.ends_with('-') {
        telio_log_debug!("Nickname ends with a hyphen");
        return false;
    }
    if name.ends_with(".nord") {
        telio_log_debug!("Nickname ends with \'.nord\'");
        return false;
    }
    if name.ends_with('.') {
        telio_log_debug!("Nickname ends with \'.\'");
        return false;
    }
    if name.starts_with('-') {
        telio_log_debug!("Nickname starts with a hyphen");
        return false;
    }
    true
}
