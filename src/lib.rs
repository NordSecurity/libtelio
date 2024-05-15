#![cfg_attr(docsrs, feature(doc_cfg))]
// Telio doc rs documentation pages:
#![doc = include_str!["./doc/introduction.md"]]

pub mod _telio_integration_documentation {
    #![doc = include_str!["./doc/integrating_telio.md"]]
}
pub mod _telio_events_documentation {
    #![doc = include_str!["./doc/telio_events.md"]]
}

pub mod ffi;
pub use crate::ffi::*;
use crate::types::*;
pub use ffi::types as ffi_types;
pub use ffi::TelioTracingSubscriber;

/// cbindgen:ignore
pub mod device;

/// cbindgen:ignore
pub use telio_crypto as crypto;

/// cbindgen:ignore
pub use telio_dns;

/// cbindgen:ignore
pub use telio_proto;

/// cbindgen:ignore
pub use telio_proxy;

/// cbindgen:ignore
pub use telio_nurse;

/// cbindgen:ignore
pub use telio_relay;

/// cbindgen:ignore
pub use telio_traversal;

/// cbindgen:ignore
pub use telio_sockets;

/// cbindgen:ignore
pub use telio_task;

/// cbindgen:ignore
pub use telio_wg;

/// cbindgen:ignore
pub use telio_model;

/// cbindgen:ignore
pub use telio_nat_detect;

/// cbindgen:ignore
pub use telio_utils;

/// cbindgen:ignore
pub use telio_lana;

/// cbindgen:ignore
pub use telio_firewall;

pub use uniffi_libtelio::*;
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, unwrap_check)]
mod uniffi_libtelio {
    use std::convert::TryInto;
    use std::net::IpAddr;

    use super::crypto::{PublicKey, SecretKey};
    use super::*;

    use telio_model::config::*;
    use telio_model::features::*;
    use telio_model::mesh::*;
    use telio_utils::{Hidden, HiddenString};

    impl UniffiCustomTypeConverter for PublicKey {
        type Builtin = Vec<u8>;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(PublicKey::new(
                val.try_into().map_err(|_| TelioError::InvalidKey)?,
            ))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.0.to_vec()
        }
    }

    impl UniffiCustomTypeConverter for SecretKey {
        type Builtin = Vec<u8>;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(SecretKey::new(
                val.try_into().map_err(|_| TelioError::InvalidKey)?,
            ))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.as_bytes().to_vec()
        }
    }

    impl UniffiCustomTypeConverter for IpAddr {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(val.parse().map_err(|_| {
                TelioError::UnknownError(anyhow::anyhow!("Invalid IP address".to_owned()))
            })?)
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    impl UniffiCustomTypeConverter for IpNetwork {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(val.parse().map_err(|_| {
                TelioError::UnknownError(anyhow::anyhow!("Invalid IP address".to_owned()))
            })?)
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    impl UniffiCustomTypeConverter for Ipv4Addr {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            val.parse()
                .map_err(|_| anyhow::anyhow!("Invalid IP address"))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    impl UniffiCustomTypeConverter for SocketAddr {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(val.parse().map_err(|_| {
                TelioError::UnknownError(anyhow::anyhow!("Invalid IP address".to_owned()))
            })?)
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    impl UniffiCustomTypeConverter for HiddenString {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(Hidden(val))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    impl UniffiCustomTypeConverter for EndpointProviders {
        type Builtin = Vec<EndpointProvider>;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(val.iter().copied().collect())
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.iter().copied().collect()
        }
    }

    impl UniffiCustomTypeConverter for FeatureValidateKeys {
        type Builtin = bool;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(FeatureValidateKeys(val))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.0
        }
    }

    impl UniffiCustomTypeConverter for TtlValue {
        type Builtin = u32;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(TtlValue(val))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.0
        }
    }

    impl UniffiCustomTypeConverter for FeatureBoringtunResetConns {
        type Builtin = bool;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            Ok(FeatureBoringtunResetConns(val))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.0
        }
    }

    uniffi::include_scaffolding!("libtelio");

    #[cfg(test)]
    mod tests {
        use ipnetwork::{Ipv4Network, Ipv6Network};
        use std::{collections::HashSet, net::Ipv6Addr};

        use super::*;
        use rstest::*;

        #[rstest]
        #[case(SecretKey::gen().public())]
        #[case(SecretKey::gen().public())]
        fn test_public_key_conversion(#[case] key: PublicKey) {
            let serialized = PublicKey::from_custom(key.clone());
            let deserialized = PublicKey::into_custom(serialized).unwrap();

            assert_eq!(deserialized, key);
        }

        #[rstest]
        #[case(SecretKey::gen())]
        #[case(SecretKey::gen())]
        fn test_secret_key_conversion(#[case] key: SecretKey) {
            let serialized = SecretKey::from_custom(key.clone());
            let deserialized = SecretKey::into_custom(serialized).unwrap();

            assert_eq!(deserialized, key);
        }

        #[rstest]
        #[case("127.0.0.1".to_owned(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), true, false)]
        #[case("10.0.64.1".to_owned(), IpAddr::V4(Ipv4Addr::new(10, 0, 64, 1)), true, false)]
        #[case("::1".to_owned(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), false, true)]
        #[case("fd74:656c:696f::2".to_owned(), IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2)), false, true)]
        fn test_to_ip_addr(
            #[case] ip_str: String,
            #[case] expected: IpAddr,
            #[case] is_v4: bool,
            #[case] is_v6: bool,
        ) {
            let actual = IpAddr::into_custom(ip_str).unwrap();

            assert_eq!(actual, expected);
            assert_eq!(actual.is_ipv4(), is_v4);
            assert_eq!(actual.is_ipv6(), is_v6);
        }

        #[rstest]
        #[case("127.0.0.1".to_owned(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))]
        #[case("10.0.64.1".to_owned(), IpAddr::V4(Ipv4Addr::new(10, 0, 64, 1)))]
        #[case("::1".to_owned(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))]
        #[case("fd74:656c:696f::2".to_owned(), IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2)))]
        fn test_from_ip_addr(#[case] expected: String, #[case] addr: IpAddr) {
            let actual = IpAddr::from_custom(addr);

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("100.64.0.2/32".to_owned(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(100, 64, 0, 2), 32).unwrap()))]
        #[case("100.64.0.3/24".to_owned(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(100, 64, 0, 3), 24).unwrap()))]
        #[case("fd74:656c:696f::2/128".to_owned(), IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2), 128).unwrap()))]
        #[case("fd74:656c:696f::3/16".to_owned(), IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 3), 16).unwrap()))]
        fn test_to_ip_network(#[case] ip_str: String, #[case] expected: IpNetwork) {
            let actual = IpNetwork::into_custom(ip_str).unwrap();

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("100.64.0.2/32".to_owned(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(100, 64, 0, 2), 32).unwrap()))]
        #[case("100.64.0.3/24".to_owned(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(100, 64, 0, 3), 24).unwrap()))]
        #[case("fd74:656c:696f::2/128".to_owned(), IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2), 128).unwrap()))]
        #[case("fd74:656c:696f::3/16".to_owned(), IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 3), 16).unwrap()))]
        fn test_from_ip_network(#[case] expected: String, #[case] network: IpNetwork) {
            let actual = IpNetwork::from_custom(network);

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("10.0.80.80".to_owned(), Ipv4Addr::new(10, 0, 80, 80))]
        #[case("10.0.1.1".to_owned(), Ipv4Addr::new(10, 0, 1, 1))]
        fn test_to_ipv4_addr(#[case] ip_str: String, #[case] expected: Ipv4Addr) {
            let actual = Ipv4Addr::into_custom(ip_str).unwrap();

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("10.0.80.80".to_owned(), Ipv4Addr::new(10, 0, 80, 80))]
        #[case("10.0.1.1".to_owned(), Ipv4Addr::new(10, 0, 1, 1))]
        fn test_from_ipv4_addr(#[case] expected: String, #[case] addr: Ipv4Addr) {
            let actual = Ipv4Addr::from_custom(addr);

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("127.0.0.1:1234".to_owned(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234), 1234, true, false)]
        #[case("10.0.64.1:53".to_owned(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 64, 1)), 53), 53, true, false)]
        #[case("[::1]:1111".to_owned(), SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 1111), 1111, false, true)]
        #[case("[fd74:656c:696f::2]:80".to_owned(), SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2)), 80), 80, false, true)]
        fn test_to_socket_addr(
            #[case] ip_str: String,
            #[case] expected: SocketAddr,
            #[case] port: u16,
            #[case] is_v4: bool,
            #[case] is_v6: bool,
        ) {
            let actual = SocketAddr::into_custom(ip_str).unwrap();

            assert_eq!(actual, expected);
            assert_eq!(actual.port(), port);
            assert_eq!(actual.is_ipv4(), is_v4);
            assert_eq!(actual.is_ipv6(), is_v6);
        }

        #[rstest]
        #[case("127.0.0.1:1234".to_owned(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234))]
        #[case("10.0.64.1:53".to_owned(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 64, 1)), 53))]
        #[case("[::1]:1111".to_owned(), SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 1111))]
        #[case("[fd74:656c:696f::2]:80".to_owned(), SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2)), 80))]
        fn test_from_socket_addr(#[case] expected: String, #[case] addr: SocketAddr) {
            let actual = SocketAddr::from_custom(addr);

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("".to_owned(), Hidden("".to_owned()))]
        #[case("hidden".to_owned(), Hidden("hidden".to_owned()))]
        #[case("hidden sentence".to_owned(), Hidden("hidden sentence".to_owned()))]
        fn test_to_hidden_string(#[case] str_to_hide: String, #[case] expected: HiddenString) {
            let actual = HiddenString::into_custom(str_to_hide).unwrap();

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("".to_owned(), Hidden("".to_owned()))]
        #[case("hidden".to_owned(), Hidden("hidden".to_owned()))]
        #[case("hidden sentence".to_owned(), Hidden("hidden sentence".to_owned()))]
        fn test_from_hidden_string(#[case] expected: String, #[case] hidden: HiddenString) {
            let actual = HiddenString::from_custom(hidden);

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case(vec![], maplit::hashset!{})]
        #[case(vec![EndpointProvider::Stun], maplit::hashset! {EndpointProvider::Stun})]
        #[case(vec![EndpointProvider::Local, EndpointProvider::Stun], maplit::hashset!{EndpointProvider::Stun, EndpointProvider::Local})]
        fn test_to_endpoint_providers(
            #[case] providers: Vec<EndpointProvider>,
            #[case] expected: HashSet<EndpointProvider>,
        ) {
            let actual = EndpointProviders::into_custom(providers).unwrap();

            assert_eq!(actual.len(), expected.len());
            assert!(actual.iter().all(|ep| expected.contains(ep)));
        }

        #[rstest]
        #[case(vec![], maplit::hashset!{})]
        #[case(vec![EndpointProvider::Stun], maplit::hashset! {EndpointProvider::Stun})]
        #[case(vec![EndpointProvider::Local, EndpointProvider::Stun], maplit::hashset!{EndpointProvider::Stun, EndpointProvider::Local})]
        fn test_from_endpoint_providers(
            #[case] expected: Vec<EndpointProvider>,
            #[case] providers: HashSet<EndpointProvider>,
        ) {
            let actual = EndpointProviders::from_custom(providers);

            assert_eq!(actual.len(), expected.len());
            assert!(actual.iter().all(|ep| expected.contains(ep)));
        }

        #[rstest]
        #[case(true)]
        #[case(false)]
        fn test_to_feature_validate_keys(#[case] val: bool) {
            let expected = FeatureValidateKeys(val);
            let actual = FeatureValidateKeys::into_custom(val).unwrap();

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case(true)]
        #[case(false)]
        fn test_from_feature_validate_keys(#[case] val: bool) {
            let expected = val;
            let actual = FeatureValidateKeys::from_custom(FeatureValidateKeys(val));

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case(60)]
        #[case(3600)]
        #[case(0)]
        fn test_to_feature_ttl_value(#[case] val: u32) {
            let expected = TtlValue(val);
            let actual = TtlValue::into_custom(val).unwrap();

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case(60)]
        #[case(3600)]
        #[case(0)]
        fn test_from_feature_ttl_value(#[case] val: u32) {
            let expected = val;
            let actual = TtlValue::from_custom(TtlValue(val));

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case(true)]
        #[case(false)]
        fn test_to_feature_boring_tun_reset_conns(#[case] val: bool) {
            let expected = FeatureBoringtunResetConns(val);
            let actual = FeatureBoringtunResetConns::into_custom(val).unwrap();

            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case(true)]
        #[case(false)]
        fn test_from_feature_boring_tun_reset_conns(#[case] val: bool) {
            let expected = val;
            let actual = FeatureBoringtunResetConns::from_custom(FeatureBoringtunResetConns(val));

            assert_eq!(actual, expected);
        }
    }
}
