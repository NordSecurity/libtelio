use std::{
    fs::{self, OpenOptions},
    io::{BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};

use telio_core::{crypto::SecretKey, telio_utils::Hidden};

use crate::{NordVpnLiteError, DEFAULT_FILE_PERMISSIONS};

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "Hidden<String>")]
pub struct NordToken(Hidden<String>);

impl NordToken {
    pub fn new(token: &str) -> Result<Self, NordVpnLiteError> {
        if Self::validate(token) {
            Ok(NordToken(token.to_owned().into()))
        } else {
            Err(NordVpnLiteError::InvalidConfigToken {
                msg: "Invalid authentication token format".to_owned(),
            })
        }
    }

    fn validate(token: &str) -> bool {
        token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl TryFrom<Hidden<String>> for NordToken {
    type Error = NordVpnLiteError;

    fn try_from(token: Hidden<String>) -> Result<Self, Self::Error> {
        NordToken::new(&token.0)
    }
}

impl std::fmt::Display for NordToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for NordToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for NordToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Deserialize)]
pub struct NordlynxKeyResponse {
    pub nordlynx_private_key: String,
}

impl NordlynxKeyResponse {
    pub fn into_secret_key(self) -> Result<SecretKey, NordVpnLiteError> {
        self.nordlynx_private_key.parse::<SecretKey>().map_err(|_| {
            NordVpnLiteError::InvalidResponse("Failed to parse nordlynx private key".to_owned())
        })
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NordVpnLiteAuth {
    authentication_token: NordToken,
}

impl NordVpnLiteAuth {
    /// Create a new NordVpnLiteAuth with the given token
    pub fn new(token: NordToken) -> Self {
        NordVpnLiteAuth {
            authentication_token: token,
        }
    }

    /// Get the authentication token
    pub fn get_token(&self) -> NordToken {
        self.authentication_token.clone()
    }

    /// Deserialize the NordVpnLiteAuth from an existing file at the given path
    pub fn from_existing_file<P: AsRef<Path>>(path: P) -> Result<Self, NordVpnLiteError> {
        let path = path.as_ref();
        println!("Reading auth from: {}", path.display());

        match fs::File::open(path) {
            Ok(file) => {
                let auth: NordVpnLiteAuth = serde_json::from_reader(BufReader::new(file))?;
                Ok(auth)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Serialize the NordVpnLiteAuth and write it to a file at the given path
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), NordVpnLiteError> {
        let path = path.as_ref();

        // Create the file with restrictive permissions set at creation time.
        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(DEFAULT_FILE_PERMISSIONS)
            .open(path)
        {
            Ok(mut file) => {
                // Ensure permissions are correct even if the file already existed
                // (in which case `.mode()` on create is ignored by the OS).
                let mut permissions = file.metadata()?.permissions();
                permissions.set_mode(DEFAULT_FILE_PERMISSIONS);
                fs::set_permissions(path, permissions)?;

                let auth_json: Hidden<String> = serde_json::to_string_pretty(&self)?.into();
                file.write_all(auth_json.as_bytes())?;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Checks if NORD_TOKEN env var is set and contains a valid token
    /// If so, returns a NordVpnLiteAuth, otherwise None
    pub fn resolve_env_token() -> Option<Self> {
        if let Ok(token) = std::env::var("NORD_TOKEN") {
            println!("Overriding token from env");
            match NordToken::new(&token) {
                Ok(nord_token) => {
                    return Some(NordVpnLiteAuth::new(nord_token));
                }
                Err(e) => {
                    eprintln!("Token from env not valid: {}", e);
                }
            };
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{EnvVarHelper, NORD_TOKEN_ENV, VALID_TOKEN};
    use serial_test::serial;
    use temp_file::TempFile;

    #[test]
    fn test_new_rejects_invalid_token() {
        let too_short = "abcd1234";
        assert_matches::assert_matches!(
            NordToken::new(too_short),
            Err(NordVpnLiteError::InvalidConfigToken { .. })
        );

        let non_hex = "g".repeat(64);
        assert_matches::assert_matches!(
            NordToken::new(&non_hex),
            Err(NordVpnLiteError::InvalidConfigToken { .. })
        );

        let one_bad = "a".repeat(63) + "w";
        assert_matches::assert_matches!(
            NordToken::new(&one_bad),
            Err(NordVpnLiteError::InvalidConfigToken { .. })
        );

        let too_short_63 = "a".repeat(63);
        assert_matches::assert_matches!(
            NordToken::new(&too_short_63),
            Err(NordVpnLiteError::InvalidConfigToken { .. })
        );

        let too_long_65 = "a".repeat(65);
        assert_matches::assert_matches!(
            NordToken::new(&too_long_65),
            Err(NordVpnLiteError::InvalidConfigToken { .. })
        );
    }

    #[test]
    fn test_new_accepts_valid_token() {
        assert!(NordToken::new(VALID_TOKEN).is_ok());
    }

    #[test]
    fn test_nord_token_display() {
        let token = NordToken::new(VALID_TOKEN).unwrap();
        assert_eq!(format!("{}", token), VALID_TOKEN);
    }

    #[test]
    fn test_nord_token_deref() {
        let token = NordToken::new(VALID_TOKEN).unwrap();
        let as_str: &str = &token;
        assert_eq!(as_str, VALID_TOKEN);
    }

    #[test]
    fn test_nordlynx_into_secret_key_valid() {
        let hex_key = VALID_TOKEN;
        let expected: SecretKey = hex_key.parse().expect("hex key should parse");
        let response = NordlynxKeyResponse {
            nordlynx_private_key: hex_key.to_owned(),
        };
        let parsed = response
            .into_secret_key()
            .expect("valid nordlynx key should parse");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_nordlynx_into_secret_key_invalid() {
        let response = NordlynxKeyResponse {
            nordlynx_private_key: "not-a-valid-key".to_owned(),
        };
        assert_matches::assert_matches!(
            response.into_secret_key(),
            Err(NordVpnLiteError::InvalidResponse(_))
        );
    }

    #[test]
    fn test_new_and_get_token() {
        let token = NordToken::new(VALID_TOKEN).unwrap();
        let auth = NordVpnLiteAuth::new(token.clone());
        assert_eq!(auth.get_token(), token);
    }

    #[test]
    fn test_to_and_from_file_roundtrip() {
        let file = TempFile::new().expect("failed to create temp file");
        let path = file.path().to_owned();

        let token = NordToken::new(VALID_TOKEN).unwrap();
        let auth = NordVpnLiteAuth::new(token.clone());
        auth.to_file(&path).expect("failed to write auth file");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, DEFAULT_FILE_PERMISSIONS);

        let loaded =
            NordVpnLiteAuth::from_existing_file(&path).expect("failed to read auth file back");
        assert_eq!(loaded, auth);
        assert_eq!(loaded.get_token().as_ref(), VALID_TOKEN);
    }

    #[test]
    fn test_to_file_resets_permissions_on_existing_file() {
        let file = TempFile::new().expect("failed to create temp file");
        let path = file.path().to_owned();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("failed to set initial permissions");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );

        let token = NordToken::new(VALID_TOKEN).unwrap();
        let auth = NordVpnLiteAuth::new(token);
        auth.to_file(&path).expect("failed to write auth file");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, DEFAULT_FILE_PERMISSIONS);
    }

    #[test]
    fn test_from_existing_file_rejects_unknown_fields() {
        let json = format!(
            r#"{{ "authentication_token": "{}", "unexpected_field": "value" }}"#,
            VALID_TOKEN
        );

        let file = TempFile::new()
            .expect("failed to create temp file")
            .with_contents(json.as_bytes())
            .expect("failed to write temp file");

        assert!(NordVpnLiteAuth::from_existing_file(file.path()).is_err());
    }

    #[test]
    fn test_to_file_fails_when_directory_missing() {
        let token = NordToken::new(VALID_TOKEN).unwrap();
        let auth = NordVpnLiteAuth::new(token);

        let path = std::path::Path::new("/nonexistent_dir_for_test/auth.json");
        assert_matches::assert_matches!(auth.to_file(path), Err(NordVpnLiteError::Io(_)));
    }

    #[test]
    fn test_from_existing_file_fails_when_file_missing() {
        let file = TempFile::new().expect("failed to create temp file");
        let path = file.path().to_owned();
        drop(file);

        assert_matches::assert_matches!(
            NordVpnLiteAuth::from_existing_file(&path),
            Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn test_from_existing_file_rejects_invalid_token() {
        let file = TempFile::new()
            .expect("failed to create temp file")
            .with_contents(br#"{ "authentication_token": "invalid-token" }"#)
            .expect("failed to write temp file");

        assert!(NordVpnLiteAuth::from_existing_file(file.path()).is_err());
    }

    #[test]
    #[serial]
    fn test_resolve_env_valid_token() {
        let _env = EnvVarHelper::set(NORD_TOKEN_ENV, VALID_TOKEN);
        let auth = NordVpnLiteAuth::resolve_env_token().expect("env token should resolve");
        assert_eq!(auth.get_token().as_ref(), VALID_TOKEN);
    }

    #[test]
    #[serial]
    fn test_resolve_env_invalid_token() {
        let _env = EnvVarHelper::set(NORD_TOKEN_ENV, "not-a-valid-token");
        assert!(NordVpnLiteAuth::resolve_env_token().is_none());
    }

    #[test]
    #[serial]
    fn test_resolve_env_no_var() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        assert!(NordVpnLiteAuth::resolve_env_token().is_none());
    }
}
