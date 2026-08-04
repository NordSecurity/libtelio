//! TLS certificate verification helpers.

use std::sync::Arc;

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};

#[derive(Debug)]
pub(crate) struct CertFingerprintLogger(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for CertFingerprintLogger {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(end_entity).into();
        telio_log_info!(
            "Remote gRPC server ({server_name:?}) sha256 fingerprint: {}",
            hex::encode(hash)
        );

        let verification =
            self.0
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);

        telio_log_info!("Remote gRPC TLS certificate verification result: {verification:?}");

        verification
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

pub(crate) fn make_trusted_root_cert_verifier(
    crypto_provider: Arc<CryptoProvider>,
    root_certificate: &[u8],
) -> std::io::Result<Arc<impl ServerCertVerifier>> {
    let mut roots = RootCertStore::empty();
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
    Ok(Arc::new(CertFingerprintLogger(verifier)))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::ens::ens_impl::{
        make_crypto_provider,
        tests::{TlsConfig, SUBJECT_ALT_NAMES},
    };

    use super::*;

    #[test]
    fn test_cert_verification_rejects_invalid_request() {
        use rustls::{
            client::danger::ServerCertVerifier,
            internal::msgs::codec::{Codec, Reader},
            DigitallySignedStruct, SignatureScheme,
        };

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
        use rustls::{
            client::danger::ServerCertVerified,
            pki_types::{ServerName, UnixTime},
        };

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
        use rustls::pki_types::{ServerName, UnixTime};

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
