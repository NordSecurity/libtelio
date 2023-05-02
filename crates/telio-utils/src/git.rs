/// Get the commit sha that was used when building.
/// If not present defaults to "dev".
pub fn commit_sha() -> &'static str {
    option_env!("LIBTELIO_COMMIT_SHA").unwrap_or("dev")
}

/// Get the version tag that was used when building.
/// If not present defaults to "dev".
pub fn version_tag() -> &'static str {
    option_env!("LIBTELIO_COMMIT_TAG")
        .map(|tag| tag.trim())
        .and_then(|tag| if tag.is_empty() { None } else { Some(tag) })
        .unwrap_or("dev")
}
