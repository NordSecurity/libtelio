use base64::prelude::{Engine, BASE64_STANDARD};
use reqwest::{
    blocking::{Client, Response},
    header,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use telio::crypto::{KeyDecodeError, PublicKey, SecretKey};
use telio_model::mesh::ExitNode;
use thiserror::Error;

use std::net::{IpAddr, SocketAddr};

const API_BASE: &str = "https://api.nordvpn.com/v1";

#[cfg(windows)]
const OS_NAME: &str = "windows";
#[cfg(target_os = "macos")]
const OS_NAME: &str = "macos";
#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";

trait ApiError {
    fn checked(self) -> Result<Self, Error>
    where
        Self: Sized;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Api reqwest failed, {0} {1}:\n{2}")]
    Api(String, String, String),
    #[error(transparent)]
    Rewquest(#[from] reqwest::Error),
    #[error("Invalid oauth string")]
    InvalidOauthString(std::str::Utf8Error),
    #[error("Missing oauth challange")]
    MissingOauthChallenge,
    #[error("No public key with id {0}")]
    NoPublicKeyWithId(i32),
    #[error("Register has no identifier")]
    RegisterHasNoIdentifier,
}

pub struct Nord {
    pub user: String,
    login: LoginInfo,
    creds: Creds,
}

#[derive(Deserialize)]
pub struct OAuth {
    pub redirect_uri: String,
    pub attempt: String,
    pub chalenge: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct LoginInfo {
    token: String,
}

#[derive(Deserialize)]
struct Creds {
    nordlynx_private_key: String,
}

#[derive(Deserialize)]
struct Server {
    station: IpAddr,
    technologies: Vec<Tech>,
}

#[derive(Deserialize)]
struct Tech {
    id: i32,
    metadata: Vec<Meta>,
}

#[derive(Deserialize)]
struct Meta {
    value: String,
}

#[derive(Default, Serialize, Deserialize)]
struct MeshDev {
    identifier: Option<String>,
    public_key: PublicKey,
    hardware_identifier: Option<String>,
    os: String,
    os_version: String,
    hostname: Option<String>,
}

impl Nord {
    fn format_auth_token(token: &String) -> String {
        let creds = format!("token:{}", token);
        format!("Basic {}", BASE64_STANDARD.encode(creds))
    }

    pub fn start_login() -> Result<OAuth, Error> {
        let chalenge = b"asdfasdf".to_vec();
        let sha256 = hex::encode(Sha256::digest(&chalenge));
        let client = Client::new();

        let mut auth: OAuth = client
            .post(&format!("{}/users/oauth/login", API_BASE))
            .form(&[("challenge", &*sha256), ("preferred_flow", "login")])
            .send()?
            .checked()?
            .json()?;
        auth.chalenge = Some(chalenge);
        Ok(auth)
    }

    pub fn finish_login(auth: OAuth) -> Result<Self, Error> {
        let client = Client::new();
        let verifier =
            std::str::from_utf8(auth.chalenge.as_ref().ok_or(Error::MissingOauthChallenge)?)
                .map_err(Error::InvalidOauthString)?;
        let login: LoginInfo = client
            .get(&format!("{}/users/oauth/token", API_BASE))
            .query(&[("attempt", &*auth.attempt), ("verifier", verifier)])
            .send()?
            .checked()?
            .json()?;
        let creds: Creds = client
            .get(&format!("{}/users/services/credentials", API_BASE))
            .header(header::AUTHORIZATION, Self::format_auth_token(&login.token))
            .send()?
            .checked()?
            .json()?;

        Ok(Nord {
            user: "hard to say".to_owned(),
            login,
            creds,
        })
    }

    pub fn login(user: &str, pass: &str) -> Result<Self, Error> {
        let client = Client::new();
        let login: LoginInfo = client
            .post(&format!("{}/users/tokens", API_BASE))
            .form(&[("username", &user), ("password", &pass)])
            .send()?
            .checked()?
            .json()?;

        let creds: Creds = client
            .get(&format!("{}/users/services/credentials", API_BASE))
            .header(header::AUTHORIZATION, Self::format_auth_token(&login.token))
            .send()?
            .checked()?
            .json()?;

        Ok(Nord {
            user: user.to_owned(),
            login,
            creds,
        })
    }

    pub fn token_login(token: &str) -> Result<Self, Error> {
        let login = LoginInfo {
            token: token.to_string(),
        };

        let client = Client::new();
        let creds: Creds = client
            .get(&format!("{}/users/services/credentials", API_BASE))
            .header(header::AUTHORIZATION, Self::format_auth_token(&login.token))
            .send()?
            .checked()?
            .json()?;

        Ok(Nord {
            user: token.to_owned(),
            login,
            creds,
        })
    }

    pub fn get_private_key(&self) -> Result<SecretKey, KeyDecodeError> {
        self.creds.nordlynx_private_key.parse()
    }

    pub fn find_server(&self) -> Result<ExitNode, Error> {
        let client = Client::new();
        let server: [Server; 1] = client
            .get(&format!("{}/servers/recommendations", API_BASE))
            .query(&[
                ("filters[servers_technologies][identifier]", "wireguard_udp"),
                ("filters[servers_technologies][pivot][status]", "online"),
                ("limit", "1"),
            ])
            .send()?
            .checked()?
            .json()?;
        let endpoint: SocketAddr = (
            server.first().ok_or(Error::NoPublicKeyWithId(35))?.station,
            51820,
        )
            .into();
        let public_key: PublicKey = server
            .first()
            .ok_or(Error::NoPublicKeyWithId(35))?
            .technologies
            .iter()
            .find_map(|t| {
                if t.id == 35 {
                    t.metadata.first().and_then(|m| m.value.parse().ok())
                } else {
                    None
                }
            })
            .ok_or(Error::NoPublicKeyWithId(35))?;
        Ok(ExitNode {
            public_key,
            endpoint: Some(endpoint),
            ..Default::default()
        })
    }

    pub fn register(&self, name: &str, public_key: &PublicKey) -> Result<String, Error> {
        let client = Client::new();
        let register: MeshDev = client
            .post(&format!("{}/meshnet/machines", API_BASE))
            .header(
                header::AUTHORIZATION,
                Self::format_auth_token(&self.login.token),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .json(&MeshDev {
                public_key: *public_key,
                hardware_identifier: Some(format!("{}.{}", public_key, name)),
                os: OS_NAME.to_owned(),
                os_version: format!("{} tcli", OS_NAME),
                ..Default::default()
            })
            .send()?
            .checked()?
            .json()?;

        register.identifier.ok_or(Error::RegisterHasNoIdentifier)
    }

    pub fn get_meshmap(&self, id: &str) -> Result<String, Error> {
        let client = Client::new();
        Ok(client
            .get(&format!("{}/meshnet/machines/{}/map", API_BASE, id))
            .header(
                header::AUTHORIZATION,
                Self::format_auth_token(&self.login.token),
            )
            .header(header::ACCEPT, "application/json")
            .send()?
            .checked()?
            .text()?)
    }
}

impl ApiError for Response {
    fn checked(self) -> Result<Self, Error> {
        if self.status().is_success() {
            Ok(self)
        } else {
            Err(Error::Api(
                self.url().as_str().to_owned(),
                self.status().as_str().to_owned(),
                self.text()?,
            ))
        }
    }
}
