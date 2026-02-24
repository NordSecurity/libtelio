use rand::RngExt;
use regex::{Captures, Match, Regex, RegexBuilder};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::atomic::AtomicBool,
};

/// LogCensor can postprocess logs and replace IP addresses and domain names with their hash values.
#[derive(Debug)]
pub struct LogCensor {
    mask_seed: [u8; 32],
    regex: Regex,
    hide_data_regex: Regex,
    is_enabled: AtomicBool,
}

impl Default for LogCensor {
    fn default() -> Self {
        #[allow(clippy::expect_used)]
        let hide_data_re = Regex::new(r#"(\\?['"])?hide_(user_data|thread_id)(\\?['"])?(\s)*:(\s)*(true|false)(\s)*,(\s)*"#)
            .expect("Statically known String for filtering hide_user_data and hide_thread_id is a valid regex");
        #[allow(clippy::expect_used)]
        RegexBuilder::new(
            r"
                (?<IP4>
                    \b
                    (?:
                        (?:
                            25[0-5]
                            |  2[0-4][0-9]
                            |  1[0-9]{2}
                            |  [1-9]?[0-9]
                        )\.
                    ){3}
                    (?:
                        25[0-5]
                        |  2[0-4][0-9]
                        |  1[0-9]{2}
                        |  [1-9]?[0-9]
                    )
                    \b
                )
                |
                (?<IP6>
                    ([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
                    |   :(:[0-9a-fA-F]{1,4}){1,7}
                    |   ([0-9a-fA-F]{1,4}:){1}(:[0-9a-fA-F]{1,4}){1,6}
                    |   ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}
                    |   ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}
                    |   ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}
                    |   ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}
                    |   ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}
                    |   ([0-9a-fA-F]{1,4}:){1,7}:
                )
                |
                (?<DOMAIN>
                    (([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+
                    ([A-Za-z]|[A-Za-z][A-Za-z]*[A-Za-z])\.
                )
                ",
        )
        .ignore_whitespace(true)
        .build()
        .map(|re| LogCensor {
            mask_seed: rand::rng().random::<[u8; 32]>(),
            regex: re,
            hide_data_regex: hide_data_re,
            is_enabled: AtomicBool::new(true),
        })
        .expect("Statically known string for LogCensor is a valid regex")
    }
}

#[allow(unused)]
impl LogCensor {
    /// Enables log censoring via postprocessing
    pub fn set_enabled(&self, enabled: bool) {
        self.is_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    fn should_censor(&self) -> bool {
        self.is_enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn incorret_chars_on_bounds(input: &str, m: &Match) -> bool {
        // wrapping_sub is used here to make the call to nth return None by giving it usize::MAX
        [m.start().wrapping_sub(1), m.end()]
            .iter()
            .flat_map(|pos| input.chars().nth(*pos))
            .any(|c| c.is_alphanumeric() || c == '_' || c == '.')
    }

    fn hash(&self, name: &str, input: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();

        hasher.update(input);
        hasher.update(&self.mask_seed);
        let hash_prefix = &hasher.finalize().to_hex();

        // Blake3 hash is much bigger than 8 bytes / 16 nibbles
        format!("{name}({hash_prefix:.16})")
    }

    /// Replace IPs and domains in `log` by their hash values
    pub fn censor_logs(&self, log: String) -> String {
        let hide_replaced = self.hide_data_regex.replace_all(&log, |_: &Captures| "");
        let ips_replaced = if self.should_censor() {
            self.regex
                .replace_all(&hide_replaced, |captures: &Captures| {
                    let name = "IP4";
                    if let Some(m) = captures.name(name) {
                        if let Ok(ip) = Ipv4Addr::from_str(m.as_str()) {
                            return self.hash(name, ip.octets().as_slice());
                        }
                    }
                    let name = "IP6";
                    if let Some(m) = captures.name(name) {
                        if let Ok(ip) = Ipv6Addr::from_str(m.as_str()) {
                            if Self::incorret_chars_on_bounds(&hide_replaced, &m) {
                                return m.as_str().to_owned();
                            }
                            return self.hash(name, ip.octets().as_slice());
                        }
                    }
                    let name = "DOMAIN";
                    if let Some(m) = captures.name(name) {
                        return self.hash(name, m.as_str().as_bytes());
                    }
                    captures.get(0).map(|s| s.as_str().to_owned()).unwrap_or(
                    "Regex crate guarantees this, too low priority to panic on its fail, though"
                        .to_string(),
                )
                })
        } else {
            std::borrow::Cow::Borrowed("")
        };

        match ips_replaced {
            std::borrow::Cow::Borrowed(_) => match hide_replaced {
                std::borrow::Cow::Borrowed(_) => log,
                std::borrow::Cow::Owned(s) => s,
            },
            std::borrow::Cow::Owned(s) => s,
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;

    const EXAMPLES: [(&str, &str); 15] = [
            (
                "1999-09-09 [INFO] New endpoint (1.2.3.4:1234) created",
                "1999-09-09 [INFO] New endpoint (IP4(959535cab4852bd4):1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoint ([::aabb]:1234) created",
                "1999-09-09 [INFO] New endpoint ([IP6(e64601d879a35ebc)]:1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoint ([aabb:1234::]:1234) created",
                "1999-09-09 [INFO] New endpoint ([IP6(3b50080d1fdc9e80)]:1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoint ([1:2:3:4:5:6:7:8]:1234) created",
                "1999-09-09 [INFO] New endpoint ([IP6(6673d2027ae3aae5)]:1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoints: [1:2::8]:1234 and 4.3.2.1:1234 created",
                "1999-09-09 [INFO] New endpoints: [IP6(dd87bb66675bdace)]:1234 and IP4(89e69e5aeec9ec9b):1234 created",
            ),
            (
                "1999-09-09 [INFO] \"telio::device::wg_controller\":295 peer \"YOla...oFc=\" proxying: true, state: Connected, last handshake: Some(1719486326.132445116s)",
                "1999-09-09 [INFO] \"telio::device::wg_controller\":295 peer \"YOla...oFc=\" proxying: true, state: Connected, last handshake: Some(1719486326.132445116s)",
            ),
            (
                "255.255.255.255 IPv4 at the beginning and at the end 0.0.0.0",
                "IP4(8be193f535e5b88f) IPv4 at the beginning and at the end IP4(245097bfbd7049db)",
            ),
            (
                "255.255.255.255aa we don't count these as IPv4s 0.0.0.0_a",
                "255.255.255.255aa we don't count these as IPv4s 0.0.0.0_a",
            ),
            (
                "::cd IPv6 at the beginning and at the end a:b::c:d",
                "IP6(c3d82cb949013623) IPv6 at the beginning and at the end IP6(0525ccdac7d4904a)",
            ),
            (
                "mace::cdcd no IPv6 addresses here crypto_aead::aead",
                "mace::cdcd no IPv6 addresses here crypto_aead::aead",
            ),
            (
                "A list of IPv6, IPv4 and some strange mix: [a:b:c::d:e:f, 1.2.3.4, 1.2::c:d]",
                "A list of IPv6, IPv4 and some strange mix: [IP6(46ba26199a45b3a1), IP4(959535cab4852bd4), 1.2::c:d]",
            ),
            (
                r#"2024-10-15 09:39:44.161127 TelioLogLevel.DEBUG "telio_dns::forward":220 forwarding lookup: google.com. A"#,
                r#"2024-10-15 09:39:44.161127 TelioLogLevel.DEBUG "telio_dns::forward":220 forwarding lookup: DOMAIN(c6f130761097acd8) A"#
            ),
            (
                r#"2024-10-15 09:39:44.160969 TelioLogLevel.DEBUG "telio_dns::nameserver":221 DNS request: Request { message: MessageRequest { header: Header { id: 43687, message_type: Query, op_code: Query, authoritative: false, truncation: false, recursion_desired: true, recursion_available: false, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 0, name_server_count: 0, additional_count: 0 }, query: WireQuery { query: LowerQuery { name: LowerName(Name("google.com.")), original: Query { name: Name("google.com."), query_type: A, query_class: IN } }, original: [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1] }, answers: [], name_servers: [], additionals: [], sig0: [], edns: None }, src: 100.127.234.27:41983, protocol: UDP }"#,
                r#"2024-10-15 09:39:44.160969 TelioLogLevel.DEBUG "telio_dns::nameserver":221 DNS request: Request { message: MessageRequest { header: Header { id: 43687, message_type: Query, op_code: Query, authoritative: false, truncation: false, recursion_desired: true, recursion_available: false, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 0, name_server_count: 0, additional_count: 0 }, query: WireQuery { query: LowerQuery { name: LowerName(Name("DOMAIN(c6f130761097acd8)")), original: Query { name: Name("DOMAIN(c6f130761097acd8)"), query_type: A, query_class: IN } }, original: [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1] }, answers: [], name_servers: [], additionals: [], sig0: [], edns: None }, src: IP4(5b06ebcfbb9e3791):41983, protocol: UDP }"#
            ),
            (
                r#"2024-10-15 09:38:38.506464 TelioLogLevel.DEBUG "hickory_resolver::name_server::name_server_pool":374 got a request result: Ok(DnsResponse { message: Message { header: Header { id: 7817, message_type: Response, op_code: Query, authoritative: false, truncation: false, recursion_desired: false, recursion_available: true, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 1, name_server_count: 0, additional_count: 0 }, queries: [Query { name: Name("www.google.com."), query_type: A, query_class: IN }], answers: [Record { name_labels: Name("www.google.com."), rr_type: A, dns_class: IN, ttl: 0, rdata: Some(A(A(142.250.179.206))) }], name_servers: [], additionals: [], signature: [], edns: None }, buffer: [30, 137, 128, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 142, 250, 179, 206] })"#,
                r#"2024-10-15 09:38:38.506464 TelioLogLevel.DEBUG "hickory_resolver::name_server::name_server_pool":374 got a request result: Ok(DnsResponse { message: Message { header: Header { id: 7817, message_type: Response, op_code: Query, authoritative: false, truncation: false, recursion_desired: false, recursion_available: true, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 1, name_server_count: 0, additional_count: 0 }, queries: [Query { name: Name("DOMAIN(f30af60341878496)"), query_type: A, query_class: IN }], answers: [Record { name_labels: Name("DOMAIN(f30af60341878496)"), rr_type: A, dns_class: IN, ttl: 0, rdata: Some(A(A(IP4(555b05df3fa71ebb)))) }], name_servers: [], additionals: [], signature: [], edns: None }, buffer: [30, 137, 128, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 142, 250, 179, 206] })"#,
            ),
            (
                r#"2024-10-15 09:39:25.924396 TelioLogLevel.DEBUG "hickory_resolver::name_server::name_server_pool":374 got a request result: Ok(DnsResponse { message: Message { header: Header { id: 2866, message_type: Response, op_code: Query, authoritative: false, truncation: false, recursion_desired: false, recursion_available: true, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 1, name_server_count: 0, additional_count: 0 }, queries: [Query { name: Name("www.microsoft.com."), query_type: CNAME, query_class: IN }], answers: [Record { name_labels: Name("www.microsoft.com."), rr_type: CNAME, dns_class: IN, ttl: 0, rdata: Some(CNAME(CNAME(Name("www.microsoft.com-c-3.edgekey.net.")))) }], name_servers: [], additionals: [], signature: [], edns: None }, buffer: [11, 50, 128, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 5, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 0, 0, 0, 35, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0] })"#,
                r#"2024-10-15 09:39:25.924396 TelioLogLevel.DEBUG "hickory_resolver::name_server::name_server_pool":374 got a request result: Ok(DnsResponse { message: Message { header: Header { id: 2866, message_type: Response, op_code: Query, authoritative: false, truncation: false, recursion_desired: false, recursion_available: true, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 1, name_server_count: 0, additional_count: 0 }, queries: [Query { name: Name("DOMAIN(8b89951f30d3bd35)"), query_type: CNAME, query_class: IN }], answers: [Record { name_labels: Name("DOMAIN(8b89951f30d3bd35)"), rr_type: CNAME, dns_class: IN, ttl: 0, rdata: Some(CNAME(CNAME(Name("DOMAIN(67fab06dc801422c)")))) }], name_servers: [], additionals: [], signature: [], edns: None }, buffer: [11, 50, 128, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 5, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 0, 0, 0, 35, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0] })"#,
            )
    ];

    #[test]
    fn test_log_censor() {
        let censor = LogCensor {
            // For the tests we need it repeatable and seed filled with zeros is good as any other
            mask_seed: [0; 32],
            ..Default::default()
        };

        for (original_log, expected_censored_log) in EXAMPLES {
            assert_eq!(
                expected_censored_log,
                censor.censor_logs(original_log.to_owned())
            );
        }
    }

    #[test]
    fn test_log_censor_makes_no_copies_when_not_needed() {
        let censor = LogCensor::default();

        let input = "this is some text that is going to be censored by the censor by it shouldn't match anything in the regex".to_owned();
        let input_copy = input.clone();
        let input_ptr = input.as_str().as_ptr();
        let censored = censor.censor_logs(input);
        assert_eq!(input_copy, censored);

        // No copies are made when the string doesn't need any modifications
        let censored_ptr = censored.as_str().as_ptr();
        assert_eq!(input_ptr, censored_ptr);
    }

    #[test]
    fn test_disabled_log_censor_makes_no_modifications() {
        let censor = LogCensor::default();
        censor.set_enabled(false);
        for (original_log, _) in EXAMPLES {
            let original_log_copy = original_log.to_owned();
            let original_log_ptr = original_log_copy.as_str().as_ptr();
            let new_log = censor.censor_logs(original_log_copy);
            assert_eq!(original_log, new_log);
            // No copies are made when the string doesn't need any modifications
            let new_log_ptr = new_log.as_str().as_ptr();
            assert_eq!(original_log_ptr, new_log_ptr);
        }
    }

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn test_hide_user_data_and_hide_thread_id_are_filtered_out_when_log_censor_is_enabled_and_disabled(
        #[case] set_enabled: bool,
    ) {
        let original = r#"{hide_user_data:true, "hide_user_data": false, 'hide_user_data' :true,hide_thread_id:false,hide_the_cookies:false,something_else:None, 'some_domain': 'google.com.',IPv4:"255.255.255.255", "IPv6":"::cd"}"#.to_owned();
        let expected = if set_enabled {
            r#"{hide_the_cookies:false,something_else:None, 'some_domain': 'DOMAIN(c6f130761097acd8)',IPv4:"IP4(8be193f535e5b88f)", "IPv6":"IP6(c3d82cb949013623)"}"#
        } else {
            r#"{hide_the_cookies:false,something_else:None, 'some_domain': 'google.com.',IPv4:"255.255.255.255", "IPv6":"::cd"}"#
        }
        .to_owned();

        let censor = LogCensor {
            // For the tests we need it repeatable and seed filled with zeros is good as any other
            mask_seed: [0; 32],
            ..Default::default()
        };
        censor.set_enabled(set_enabled);
        let actual = censor.censor_logs(original);

        assert_eq!(actual, expected);
    }
}
