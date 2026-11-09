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
    let ver: &'static [u8; 129] = std::hint::black_box(&VER);
    match ver.iter().position(|v| *v == 0) {
        Some(i) => std::str::from_utf8(&ver[..i]).unwrap_or("not_a_utf8_string"),
        None => "incorrect_version_string",
    }
}
