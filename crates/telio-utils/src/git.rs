/// Get the commit sha that was used when building.
/// If not present defaults to "dev".
pub fn commit_sha() -> &'static str {
    option_env!("LIBTELIO_COMMIT_SHA").unwrap_or("dev")
}

/// Get the version placeholder (half of the maximum length of git tag)
/// Will be replaced during build promotions
#[inline(never)]
#[allow(clippy::indexing_slicing)]
pub fn version_tag() -> &'static str {
    static VER: [u8;129] = *b"VERSION_PLACEHOLDER@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0";
    let len = (0..VER.len()).find(|&i| {
        // SAFETY: `&VER[i]` is a valid reference to an initialized `u8`
        unsafe { std::ptr::read_volatile(&VER[i]) == 0 }
    });
    match len {
        Some(i) => match std::str::from_utf8(&VER[..i]) {
            Ok(s) => s,
            Err(_) => "not_a_utf8_string",
        },
        None => "incorrect_version_string",
    }
}
