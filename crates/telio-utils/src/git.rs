/// Get the commit sha that was used when building.
/// If not present defaults to "dev".
pub fn commit_sha() -> &'static str {
    option_env!("LIBTELIO_COMMIT_SHA").unwrap_or("dev")
}

/// Get the version placeholder (half of the maximum length of git tag)
/// Will be replaced during build promotions
#[inline(never)]
#[allow(index_access_check)]
pub fn version_tag() -> &'static str {
    const VER: [u8;129] = *b"VERSION_PLACEHOLDER@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0";
    match VER.iter().position(|v| *v == 0) {
        Some(i) => match std::str::from_utf8(&VER[..i]) {
            Ok(s) => s,
            Err(_) => "not_a_utf8_string",
        },
        None => "incorrect_version_string",
    }
}
