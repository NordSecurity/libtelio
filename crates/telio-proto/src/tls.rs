//! TLS certificate verification helpers.

use std::sync::Arc;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};
use telio_utils::{telio_log_info, telio_log_warn};

/// Decorator around a certificate verifier which logs details of the presented server
/// certificate. Verification itself is fully delegated to the inner verifier.
#[derive(Debug)]
pub struct CertLoggingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    context: &'static str,
    log_success: bool,
}

impl CertLoggingVerifier {
    /// Wraps `inner`, prefixing the logged messages with `context` to tell the connection kind
    /// apart. With `log_success` on, the fingerprint and the outcome of every accepted
    /// certificate are logged too, not only the details of the rejected ones.
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        context: &'static str,
        log_success: bool,
    ) -> Self {
        Self {
            inner,
            context,
            log_success,
        }
    }
}

impl ServerCertVerifier for CertLoggingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.log_success {
            telio_log_info!(
                "{} TLS cert sha256={} presented for {server_name:?}",
                self.context,
                fingerprint(end_entity)
            );
        }

        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );

        match &result {
            Ok(_) => {
                if self.log_success {
                    telio_log_info!(
                        "{} TLS cert verification succeeded for {server_name:?}",
                        self.context
                    );
                }
            }
            Err(err) => telio_log_warn!(
                "{}",
                format_failed_cert(self.context, end_entity, intermediates, server_name, err)
            ),
        }

        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

fn fingerprint(cert: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(cert.as_ref()))
}

fn format_failed_cert(
    context: &str,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    err: &rustls::Error,
) -> String {
    let fingerprint = fingerprint(end_entity);
    match x509_parser::parse_x509_certificate(end_entity.as_ref()) {
        Ok((_, cert)) => format!(
            "{} TLS cert verification failed for {:?}: {}. Presented cert: issuer=[{}], subject=[{}], validity=[{} .. {}], sha256={}, intermediates={}",
            context,
            server_name,
            err,
            cert.issuer(),
            cert.subject(),
            cert.validity().not_before,
            cert.validity().not_after,
            fingerprint,
            intermediates.len()
        ),
        Err(parse_err) => format!(
            "{} TLS cert verification failed for {:?}: {}. Presented cert unparsable ({}), sha256={}, intermediates={}",
            context,
            server_name,
            err,
            parse_err,
            fingerprint,
            intermediates.len()
        ),
    }
}

#[cfg(feature = "enable_ens")]
pub(crate) fn make_trusted_root_cert_verifier(
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    root_certificate: &[u8],
) -> std::io::Result<Arc<impl ServerCertVerifier>> {
    use rustls::client::WebPkiServerVerifier;
    use telio_utils::telio_log_debug;

    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) =
        roots.add_parsable_certificates([CertificateDer::from_slice(root_certificate)]);
    if ignored > 0 {
        telio_log_warn!("Added {added} certs to trusted store, ignored: {ignored}");
        return Err(std::io::Error::other(
            "Failed to add root cert to the root certificate store",
        ));
    } else {
        telio_log_debug!("Added {added} certs to trusted store, ignored: {ignored}");
    }

    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider)
        .build()
        .map_err(std::io::Error::other)?;
    Ok(Arc::new(CertLoggingVerifier::new(
        verifier, "ENS gRPC", true,
    )))
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
        KeyPair,
    };
    use rustls::{
        client::WebPkiServerVerifier, crypto::CryptoProvider, CertificateError, RootCertStore,
    };

    use super::*;

    const SERVER_NAME: &str = "derp.example.com";

    // Explicit provider: with both `ring` and `aws-lc-rs` rustls features enabled
    // (workspace-wide test builds), the ambient default is ambiguous and panics
    fn test_crypto_provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn self_signed_ca(common_name: &str) -> (Certificate, Issuer<'static, KeyPair>) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, Issuer::new(params, key))
    }

    fn leaf_signed_by(issuer: &Issuer<'static, KeyPair>) -> Certificate {
        let params = CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        params.signed_by(&key, issuer).unwrap()
    }

    fn self_signed_leaf(common_name: &str) -> Certificate {
        let mut params = CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap()
    }

    // A verifier trusting only `root`, wrapped in the logging decorator
    fn verifier_trusting(root: &Certificate, log_success: bool) -> CertLoggingVerifier {
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), test_crypto_provider())
                .build()
                .unwrap();
        CertLoggingVerifier::new(inner, "DERP", log_success)
    }

    // Simulates a MITM proxy presenting a certificate from an unknown CA: the decorator must
    // return the inner verifier's UnknownIssuer error unchanged
    #[test]
    fn rejects_unknown_issuer() {
        let (trusted_ca, _) = self_signed_ca("Test Root CA");
        let evil_cert = self_signed_leaf("Evil Proxy CA");

        let verifier = verifier_trusting(&trusted_ca, false);
        let server_name = ServerName::try_from(SERVER_NAME).unwrap();

        let result =
            verifier.verify_server_cert(evil_cert.der(), &[], &server_name, &[], UnixTime::now());

        assert!(
            matches!(
                result,
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer
                ))
            ),
            "expected UnknownIssuer for a self-signed cert, got: {result:?}"
        );
    }

    // Happy path: a chain anchored in the trust store passes through the decorator unchanged,
    // whether or not successful verifications are logged
    #[test]
    fn accepts_trusted_chain() {
        let (ca_cert, issuer) = self_signed_ca("Test Root CA");
        let leaf_cert = leaf_signed_by(&issuer);
        let server_name = ServerName::try_from(SERVER_NAME).unwrap();

        for log_success in [false, true] {
            let verifier = verifier_trusting(&ca_cert, log_success);

            let result = verifier.verify_server_cert(
                leaf_cert.der(),
                &[],
                &server_name,
                &[],
                UnixTime::now(),
            );

            assert!(
                result.is_ok(),
                "expected trusted chain to verify with log_success={log_success}, got: {result:?}"
            );
        }
    }

    #[test]
    fn format_failed_cert_describes_the_presented_cert() {
        let evil_cert = self_signed_leaf("Evil Proxy CA");
        let server_name = ServerName::try_from(SERVER_NAME).unwrap();

        let msg = format_failed_cert(
            "DERP",
            evil_cert.der(),
            &[],
            &server_name,
            &rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
        );

        for needle in [
            "DERP TLS cert verification failed",
            SERVER_NAME,
            "UnknownIssuer",
            "issuer=[CN=Evil Proxy CA]",
            "subject=[CN=Evil Proxy CA]",
            &format!("sha256={}", fingerprint(evil_cert.der())),
            "intermediates=0",
        ] {
            assert!(
                msg.contains(needle),
                "expected log message to contain {needle:?}, got: {msg:?}"
            );
        }
    }

    #[test]
    fn format_failed_cert_handles_unparsable_certificate() {
        let garbage = CertificateDer::from(vec![0u8; 16]);
        let server_name = ServerName::try_from(SERVER_NAME).unwrap();
        // Must not panic on a certificate that is not valid X.509
        let msg = format_failed_cert(
            "DERP",
            &garbage,
            &[],
            &server_name,
            &rustls::Error::DecryptError,
        );
        assert!(
            msg.contains("unparsable"),
            "expected log message to mention the cert is unparsable, got: {msg:?}"
        );
    }

    #[cfg(feature = "enable_ens")]
    mod ens {
        use assert_matches::assert_matches;

        use crate::ens::ens_impl::{
            make_crypto_provider,
            tests::{TlsConfig, SUBJECT_ALT_NAMES},
        };

        use super::*;

        #[test]
        fn test_cert_verification_rejects_invalid_request() {
            use rustls::internal::msgs::codec::{Codec, Reader};

            let tls = TlsConfig::new();
            let verifier =
                make_trusted_root_cert_verifier(make_crypto_provider(true), &tls.ca_cert.der())
                    .unwrap();
            let leaf_cert = tls.leaf_cert.der();

            // DigitallySignedStruct with incorrect signature bytes
            // Wire format: 2 bytes scheme (big-endian u16) + 2 bytes length + signature bytes
            let scheme_u16: u16 = SignatureScheme::ECDSA_NISTP256_SHA256.into();
            let garbage_signature = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
            let mut wire_bytes = Vec::new();
            wire_bytes.extend_from_slice(&scheme_u16.to_be_bytes());
            wire_bytes.extend_from_slice(&(garbage_signature.len() as u16).to_be_bytes());
            wire_bytes.extend_from_slice(&garbage_signature);

            let mut reader = Reader::init(&wire_bytes);
            let dss = DigitallySignedStruct::read(&mut reader).expect("Failed to parse DSS");
            assert_eq!(dss.scheme, SignatureScheme::ECDSA_NISTP256_SHA256);

            let message = b"this is a TLS handshake message that was NOT signed by the cert's key";

            let tls12_result = verifier.verify_tls12_signature(message, &leaf_cert, &dss);
            assert_matches!(
                tls12_result,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature
                ))
            );

            let tls13_result = verifier.verify_tls13_signature(message, &leaf_cert, &dss);
            assert_matches!(
                tls13_result,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature
                ))
            );
        }

        #[test]
        fn test_cert_verification_accepts_correct_request() {
            let tls = TlsConfig::new();
            let verifier =
                make_trusted_root_cert_verifier(make_crypto_provider(true), &tls.ca_cert.der())
                    .unwrap();

            assert_matches!(
                verifier.verify_server_cert(
                    tls.leaf_cert.der(),
                    &[tls.ca_cert.der().clone()],
                    &ServerName::DnsName("localhost".try_into().unwrap()),
                    &[],
                    UnixTime::now(),
                ),
                Ok(ServerCertVerified { .. })
            );
        }

        #[test]
        fn test_cert_verification_rejects_incorrect_request() {
            let tls = TlsConfig::new();
            let verifier =
                make_trusted_root_cert_verifier(make_crypto_provider(true), &tls.ca_cert.der())
                    .unwrap();

            assert_matches!(
                verifier.verify_server_cert(
                    tls.leaf_cert.der(),
                    &[tls.ca_cert.der().clone()],
                    &ServerName::DnsName("some-other-name".try_into().unwrap()),
                    &[],
                    UnixTime::now(),
                ),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForNameContext {
                        expected,
                        presented
                    }
                ))
                if
                    expected == ServerName::DnsName("some-other-name".try_into().unwrap()) &&
                    presented == vec![ "DnsName(\"localhost\")", "IpAddress(127.0.0.1)" ]
            );

            let random_leaf_cert =
                rcgen::generate_simple_self_signed(SUBJECT_ALT_NAMES.clone()).unwrap();

            assert_matches!(
                verifier.verify_server_cert(
                    random_leaf_cert.cert.der(),
                    &[tls.ca_cert.der().clone()],
                    &ServerName::DnsName("localhost".try_into().unwrap()),
                    &[],
                    UnixTime::now(),
                ),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            );
        }
    }
}
