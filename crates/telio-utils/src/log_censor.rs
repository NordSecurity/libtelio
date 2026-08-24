use regex_lite::{Captures, Match, Regex, RegexBuilder};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::atomic::AtomicBool,
};

/// LogCensor can postprocess logs and replace IP addresses and domain names.
#[derive(Debug)]
pub struct LogCensor {
    mode: LogCensorMode,
    mask_seed: [u8; 32],
    regex: Regex,
    hide_data_regex: Regex,
    is_enabled: AtomicBool,
}

/// Mode of operation for the LogCensor
#[derive(Debug, Default)]
pub enum LogCensorMode {
    #[default]
    /// Substrings to be censored are replaced with the hex encoding of the hash
    Hash,
    /// Substrings to be censored are replaced with `...`
    Dots,
    /// Substrings to be censored are completely removed
    EmptyString,
}

const FILE_EXTENSION_ALLOWLIST: &[&str] =
    &["rs", "json", "toml", "log", "so", "dylib", "dll", "exe"];

impl Default for LogCensor {
    fn default() -> Self {
        #[allow(clippy::expect_used)]
        let hide_data_regex = Regex::new(r#"(\\?['"])?hide_(user_data|thread_id)(\\?['"])?(\s)*:(\s)*(true|false)(\s)*,(\s)*"#)
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
                    (?<SCHEME>[a-zA-Z][a-zA-Z0-9+.\-]*://)?
                    (\*?\.)?
                    (([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+
                    [a-zA-Z]{2,}
                    \.?
                )
                ",
        )
        .ignore_whitespace(true)
        .build()
        .map(|re| LogCensor {
            mask_seed: rand::random::<[u8; 32]>(),
            regex: re,
            is_enabled: AtomicBool::new(true),
            hide_data_regex,
            mode: LogCensorMode::default(),
        })
        .expect("Statically known string for LogCensor is a valid regex")
    }
}

impl LogCensor {
    /// Enables log censoring via postprocessing.
    pub fn set_enabled(&self, enabled: bool) {
        self.is_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Sets the mode of operation of the `self`.
    pub fn set_mode(&mut self, mode: LogCensorMode) {
        self.mode = mode;
    }

    fn should_censor(&self) -> bool {
        self.is_enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Checks whether the regex match is a fragment of a
    /// longer token, meaning it is a false positive that
    /// must be left uncensored.
    fn incorrect_chars_on_bounds(input: &str, m: &Match, reject_leading_slash: bool) -> bool {
        let is_word_char = |c: char| c.is_alphanumeric() || c == '_' || c == '.';
        // Using char boundaries, so slicing is safe.
        let before = input[..m.start()].chars().next_back();
        let after = input[m.end()..].chars().next();
        before.is_some_and(|c| is_word_char(c) || (reject_leading_slash && c == '/'))
            || after.is_some_and(is_word_char)
    }

    fn has_allowed_extension(candidate: &str) -> bool {
        candidate.rsplit('.').next().is_some_and(|ext| {
            FILE_EXTENSION_ALLOWLIST
                .iter()
                .any(|deny| ext.eq_ignore_ascii_case(deny))
        })
    }

    /// A match is treated as a domain only when its casing is
    /// unambiguous.
    ///
    /// Mixed forms like `TelioLogLevel.DEBUG`
    /// are most likely enums that appear in logs.
    fn has_ambiguous_casing(candidate: &str) -> bool {
        let (has_lower, tld_all_lower) =
            candidate
                .chars()
                .fold((false, true), |(has_lower, tld_all_lower), c| match c {
                    '.' => (has_lower, true),
                    _ if c.is_ascii_alphabetic() => (
                        has_lower || c.is_ascii_lowercase(),
                        tld_all_lower && c.is_ascii_lowercase(),
                    ),
                    _ => (has_lower, false),
                });

        if tld_all_lower {
            return false;
        }
        has_lower
    }

    /// Censor a matched domain
    ///
    /// The wildcard prefix (`*.` / `.`) and
    /// trailing dot are excluded from the hash.
    /// Leading `www.` label is normalized away
    /// as it's an alias for the apex domain).
    fn censor_domain(&self, matched: &str) -> String {
        if matches!(self.mode, LogCensorMode::EmptyString) {
            return String::new();
        }

        let (notation, rest) = if let Some(rest) = matched.strip_prefix("*.") {
            ("*.", rest)
        } else if let Some(rest) = matched.strip_prefix('.') {
            (".", rest)
        } else {
            ("", matched)
        };

        let (rest, trailing_dot) = match rest.strip_suffix('.') {
            Some(host) => (host, "."),
            None => (rest, ""),
        };

        let host = match (rest.get(..4), rest.get(4..)) {
            (Some(prefix), Some(remainder))
                if prefix.eq_ignore_ascii_case("www.") && remainder.contains('.') =>
            {
                remainder
            }
            _ => rest,
        };

        let canonical = host.to_ascii_lowercase();
        format!(
            "{notation}{}{trailing_dot}",
            self.censor_input("DOMAIN", canonical.as_bytes())
        )
    }

    fn hash(&self, name: &str, input: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();

        hasher.update(input);
        hasher.update(&self.mask_seed);
        let hash_prefix = &hasher.finalize().to_hex();

        // Blake3 hash is much bigger than 8 bytes / 16 nibbles
        format!("{name}({hash_prefix:.16})")
    }

    fn censor_input(&self, name: &str, input: &[u8]) -> String {
        match self.mode {
            LogCensorMode::Hash => self.hash(name, input),
            LogCensorMode::Dots => format!("{name}(...)"),
            LogCensorMode::EmptyString => String::new(),
        }
    }

    /// Replace IPs and domains in `log` according to the selected mode of operation.
    pub fn censor_logs(&self, log: String) -> String {
        let log = match self.hide_data_regex.replace_all(&log, |_: &Captures| "") {
            std::borrow::Cow::Borrowed(_) => log,
            std::borrow::Cow::Owned(replaced) => replaced,
        };

        if !self.should_censor() {
            return log;
        }

        let replaced = self.regex.replace_all(&log, |captures: &Captures| {
            let name = "IP4";

            if let Some(ip) = captures
                .name(name)
                .and_then(|m| Ipv4Addr::from_str(m.as_str()).ok())
            {
                return self.censor_input(name, ip.octets().as_slice());
            }

            let name = "IP6";

            if let Some((m, ip)) = captures
                .name(name)
                .and_then(|m| Ipv6Addr::from_str(m.as_str()).ok().map(|ip| (m, ip)))
            {
                if Self::incorrect_chars_on_bounds(&log, &m, false) {
                    return m.as_str().to_owned();
                }
                return self.censor_input(name, ip.octets().as_slice());
            }

            if let Some(m) = captures.name("DOMAIN") {
                // A leading scheme means the match can't be a file name or an enum variant
                if let Some(scheme) = captures.name("SCHEME") {
                    let (scheme, host) = m.as_str().split_at(scheme.end() - m.start());
                    return format!("{}{}", scheme, self.censor_domain(host));
                }

                if Self::incorrect_chars_on_bounds(&log, &m, true)
                    || Self::has_allowed_extension(m.as_str())
                    || Self::has_ambiguous_casing(m.as_str())
                {
                    return m.as_str().to_owned();
                }
                return self.censor_domain(m.as_str());
            }

            captures.get(0).map(|s| s.as_str().to_owned()).unwrap_or(
                "Regex crate guarantees this, too low priority to panic on its fail, though"
                    .to_string(),
            )
        });

        match replaced {
            std::borrow::Cow::Borrowed(_) => log,
            std::borrow::Cow::Owned(replaced) => replaced,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;

    /// LogCensor with a repeatable seed so token values are stable.
    fn test_censor() -> LogCensor {
        LogCensor {
            mask_seed: [0; 32],
            ..Default::default()
        }
    }

    /// Expected token for an IPv4 address.
    fn ip4(addr: &str) -> String {
        test_censor().hash("IP4", &Ipv4Addr::from_str(addr).unwrap().octets())
    }

    /// Expected token for an IPv6 address.
    fn ip6(addr: &str) -> String {
        test_censor().hash("IP6", &Ipv6Addr::from_str(addr).unwrap().octets())
    }

    /// Expected token for a host in canonical form.
    fn dom(canonical: &str) -> String {
        test_censor().hash("DOMAIN", canonical.as_bytes())
    }

    fn examples() -> Vec<(String, String)> {
        let same = |s: &str| (s.to_owned(), s.to_owned());
        vec![
            (
                "1999-09-09 [INFO] New endpoint (1.2.3.4:1234) created".to_owned(),
                format!(
                    "1999-09-09 [INFO] New endpoint ({}:1234) created",
                    ip4("1.2.3.4")
                ),
            ),
            (
                "1999-09-09 [INFO] New endpoint ([::aabb]:1234) created".to_owned(),
                format!(
                    "1999-09-09 [INFO] New endpoint ([{}]:1234) created",
                    ip6("::aabb")
                ),
            ),
            (
                "1999-09-09 [INFO] New endpoint ([aabb:1234::]:1234) created".to_owned(),
                format!(
                    "1999-09-09 [INFO] New endpoint ([{}]:1234) created",
                    ip6("aabb:1234::")
                ),
            ),
            (
                "1999-09-09 [INFO] New endpoint ([1:2:3:4:5:6:7:8]:1234) created".to_owned(),
                format!(
                    "1999-09-09 [INFO] New endpoint ([{}]:1234) created",
                    ip6("1:2:3:4:5:6:7:8")
                ),
            ),
            (
                "1999-09-09 [INFO] New endpoints: [1:2::8]:1234 and 4.3.2.1:1234 created"
                    .to_owned(),
                format!(
                    "1999-09-09 [INFO] New endpoints: [{}]:1234 and {}:1234 created",
                    ip6("1:2::8"),
                    ip4("4.3.2.1")
                ),
            ),
            same(
                "1999-09-09 [INFO] \"telio::device::wg_controller\":295 peer \"YOla...oFc=\" proxying: true, state: Connected, last handshake: Some(1719486326.132445116s)",
            ),
            (
                "255.255.255.255 IPv4 at the beginning and at the end 0.0.0.0".to_owned(),
                format!(
                    "{} IPv4 at the beginning and at the end {}",
                    ip4("255.255.255.255"),
                    ip4("0.0.0.0")
                ),
            ),
            same("255.255.255.255aa we don't count these as IPv4s 0.0.0.0_a"),
            (
                "::cd IPv6 at the beginning and at the end a:b::c:d".to_owned(),
                format!(
                    "{} IPv6 at the beginning and at the end {}",
                    ip6("::cd"),
                    ip6("a:b::c:d")
                ),
            ),
            same("mace::cdcd no IPv6 addresses here crypto_aead::aead"),
            (
                "A list of IPv6, IPv4 and some strange mix: [a:b:c::d:e:f, 1.2.3.4, 1.2::c:d]"
                    .to_owned(),
                format!(
                    "A list of IPv6, IPv4 and some strange mix: [{}, {}, 1.2::c:d]",
                    ip6("a:b:c::d:e:f"),
                    ip4("1.2.3.4")
                ),
            ),
            (
                r#"2024-10-15 09:39:44.161127 TelioLogLevel.DEBUG "telio_dns::forward":220 forwarding lookup: example.com A"#.to_owned(),
                format!(
                    r#"2024-10-15 09:39:44.161127 TelioLogLevel.DEBUG "telio_dns::forward":220 forwarding lookup: {} A"#,
                    dom("example.com")
                ),
            ),
            (
                r#"2024-10-15 09:39:44.161127 TelioLogLevel.DEBUG "telio_dns::forward":220 forwarding lookup: example.com. A"#.to_owned(),
                format!(
                    r#"2024-10-15 09:39:44.161127 TelioLogLevel.DEBUG "telio_dns::forward":220 forwarding lookup: {}. A"#,
                    dom("example.com")
                ),
            ),
            {
                let original = r#"2024-10-15 09:39:44.160969 TelioLogLevel.DEBUG "telio_dns::nameserver":221 DNS request: Request { message: MessageRequest { header: Header { id: 43687, message_type: Query, op_code: Query, authoritative: false, truncation: false, recursion_desired: true, recursion_available: false, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 0, name_server_count: 0, additional_count: 0 }, query: WireQuery { query: LowerQuery { name: LowerName(Name("example.com.")), original: Query { name: Name("example.com."), query_type: A, query_class: IN } }, original: [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1] }, answers: [], name_servers: [], additionals: [], sig0: [], edns: None }, src: 100.127.234.27:41983, protocol: UDP }"#;
                let expected = original
                    .replace("example.com", &dom("example.com"))
                    .replace("100.127.234.27", &ip4("100.127.234.27"));
                (original.to_owned(), expected)
            },
            {
                // The `www.` label is normalized away
                let original = r#"2024-10-15 09:38:38.506464 TelioLogLevel.DEBUG "hickory_resolver::name_server::name_server_pool":374 got a request result: Ok(DnsResponse { message: Message { header: Header { id: 7817, message_type: Response, op_code: Query, authoritative: false, truncation: false, recursion_desired: false, recursion_available: true, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 1, name_server_count: 0, additional_count: 0 }, queries: [Query { name: Name("www.example.com."), query_type: A, query_class: IN }], answers: [Record { name_labels: Name("www.example.com."), rr_type: A, dns_class: IN, ttl: 0, rdata: Some(A(A(142.250.179.206))) }], name_servers: [], additionals: [], signature: [], edns: None }, buffer: [30, 137, 128, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 142, 250, 179, 206] })"#;
                let expected = original
                    .replace(
                        "www.example.com",
                        &dom("example.com"),
                    )
                    .replace("142.250.179.206", &ip4("142.250.179.206"));
                (original.to_owned(), expected)
            },
            {
                let original = r#"2024-10-15 09:39:25.924396 TelioLogLevel.DEBUG "hickory_resolver::name_server::name_server_pool":374 got a request result: Ok(DnsResponse { message: Message { header: Header { id: 2866, message_type: Response, op_code: Query, authoritative: false, truncation: false, recursion_desired: false, recursion_available: true, authentic_data: false, checking_disabled: false, response_code: NoError, query_count: 1, answer_count: 1, name_server_count: 0, additional_count: 0 }, queries: [Query { name: Name("www.microsoft.com."), query_type: CNAME, query_class: IN }], answers: [Record { name_labels: Name("www.microsoft.com."), rr_type: CNAME, dns_class: IN, ttl: 0, rdata: Some(CNAME(CNAME(Name("www.microsoft.com-c-3.edgekey.net.")))) }], name_servers: [], additionals: [], signature: [], edns: None }, buffer: [11, 50, 128, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 5, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 0, 0, 0, 35, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0] })"#;
                let expected = original
                    .replace(
                        "www.microsoft.com-c-3.edgekey.net",
                        &dom("microsoft.com-c-3.edgekey.net"),
                    )
                    .replace(
                        "www.microsoft.com",
                        &dom("microsoft.com"),
                    );
                (original.to_owned(), expected)
            },
            {
                let original = r#"2025-04-09 21:03:34 TelioLogLevel.INFO "telio::ffi":973 Telio::set_tp_lite_domain_whitelist entry with instance id: 7396187745541688151. domains: ["adsalsa.it", "stockfinate.com"], redirects: [DnsRedirect { blocking: 1.2.3.4:53, standard: 4.3.2.1:53 }]"#;
                let expected = original
                    .replace("adsalsa.it", &dom("adsalsa.it"))
                    .replace("stockfinate.com", &dom("stockfinate.com"))
                    .replace("1.2.3.4", &ip4("1.2.3.4"))
                    .replace("4.3.2.1", &ip4("4.3.2.1"));
                (original.to_owned(), expected)
            },
            (
                "connecting to www.example.com now".to_owned(),
                format!("connecting to {} now", dom("example.com")),
            ),
            same("panicked at crates/telio-utils/src/log_censor.rs:264"),
            same("failed to parse config.json, reading Cargo.toml and main.rs:12"),
            (
                "forwarding lookup: main.rs. A".to_owned(),
                format!("forwarding lookup: {}. A", dom("main.rs")),
            ),
            (
                // Accepted over-censoring: with an extension not on the allowlist
                "failed to download update.zip from server".to_owned(),
                format!("failed to download {} from server", dom("update.zip")),
            ),
            (
                "loading .env.local file".to_owned(),
                format!("loading .{} file", dom("env.local")),
            ),
            same("GET /assets/update.zip served"),
            (
                "fetching example.com/api/users".to_owned(),
                format!("fetching {}/api/users", dom("example.com")),
            ),
            (
                // Accepted over-censoring: relative path whose first
                // segment looks like a domain
                "listing update.zip/contents now".to_owned(),
                format!("listing {}/contents now", dom("update.zip")),
            ),
            same("requires version 1.2.3 e.g the latest"),
            (
                "lookup EXAMPLE.COM failed".to_owned(),
                format!("lookup {} failed", dom("example.com")),
            ),
            (
                "fetch http://stockfinate.com timed out".to_owned(),
                format!("fetch http://{} timed out", dom("stockfinate.com")),
            ),
            (
                "GET https://www.example.com/search?q=x done".to_owned(),
                format!("GET https://{}/search?q=x done", dom("example.com")),
            ),
            (
                "proxy http://1.2.3.4:8080 used".to_owned(),
                format!("proxy http://{}:8080 used", ip4("1.2.3.4")),
            ),
            (
                r#"whitelist: ["*.adsalsa.it", ".stockfinate.com"]"#.to_owned(),
                format!(
                    r#"whitelist: ["*.{}", ".{}"]"#,
                    dom("adsalsa.it"),
                    dom("stockfinate.com")
                ),
            ),
            (
                "wss://relay.nordvpn.com. reconnect".to_owned(),
                format!("wss://{}. reconnect", dom("relay.nordvpn.com")),
            ),
            (
                "https://EXAMPLE.COM up".to_owned(),
                format!("https://{} up", dom("example.com")),
            ),
            (
                "https://example.com up".to_owned(),
                format!("https://{} up", dom("example.com")),
            ),
            (
                "open MAIN.RS failed".to_owned(),
                "open MAIN.RS failed".to_owned(),
            ),
            (
                // Accepted residual: mixed case forms are skipped
                "peer Example.COM seen".to_owned(),
                "peer Example.COM seen".to_owned(),
            ),
        ]
    }

    #[test]
    fn test_log_censor() {
        let censor = test_censor();

        for (original_log, expected_censored_log) in examples() {
            assert_eq!(expected_censored_log, censor.censor_logs(original_log));
        }
    }

    #[test]
    fn test_domain_hash_relatability() {
        let censor = test_censor();
        let token = dom("example.com");
        // Every spelling of the same host must contain the same DOMAIN(..)
        let cases = [
            ("lookup example.com now", format!("lookup {token} now")),
            ("lookup example.com. now", format!("lookup {token}. now")),
            ("lookup www.example.com now", format!("lookup {token} now")),
            (
                "lookup www.example.com. now",
                format!("lookup {token}. now"),
            ),
            ("lookup EXAMPLE.COM now", format!("lookup {token} now")),
            (
                "lookup http://example.com now",
                format!("lookup http://{token} now"),
            ),
            (
                r#"lookup "*.example.com" now"#,
                format!(r#"lookup "*.{token}" now"#),
            ),
            (
                "GET https://www.example.com/search?q=x done",
                format!("GET https://{token}/search?q=x done"),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(expected, censor.censor_logs(input.to_owned()), "{input}");
        }
    }

    #[test]
    fn test_no_sensitive_domain_leak() {
        let censor = test_censor();
        let token = dom("example.co.uk");
        let inputs = [
            "visit example.co.uk now",
            "visit www.example.co.uk now",
            "visit example.co.uk. now",
            r#"whitelist ["*.example.co.uk"] set"#,
            r#"suffix ".example.co.uk" set"#,
            "GET https://www.example.co.uk/news done",
            "GET example.co.uk/news done",
        ];
        for input in inputs {
            let censored = censor.censor_logs(input.to_owned());
            assert!(!censored.contains("example"), "leaked: {censored}");
            assert!(censored.contains(&token), "not relatable: {censored}");
        }

        let censored = censor.censor_logs("connect mail.example.com now".to_owned());
        assert_eq!(censored, format!("connect {} now", dom("mail.example.com")));
        assert!(!censored.contains("example"));
        assert_ne!(dom("mail.example.com"), dom("example.com"));
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
        for (original_log, _) in examples() {
            let original_log_copy = original_log.clone();
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
        let original = r#"{hide_user_data:true, "hide_user_data": false, 'hide_user_data' :true,hide_thread_id:false,hide_the_cookies:false,something_else:None, 'some_domain': 'example.com.',IPv4:"255.255.255.255", "IPv6":"::cd"}"#.to_owned();
        let expected = if set_enabled {
            format!(
                r#"{{hide_the_cookies:false,something_else:None, 'some_domain': '{}.',IPv4:"{}", "IPv6":"{}"}}"#,
                dom("example.com"),
                ip4("255.255.255.255"),
                ip6("::cd")
            )
        } else {
            r#"{hide_the_cookies:false,something_else:None, 'some_domain': 'example.com.',IPv4:"255.255.255.255", "IPv6":"::cd"}"#
                .to_owned()
        };

        let censor = test_censor();
        censor.set_enabled(set_enabled);
        let actual = censor.censor_logs(original);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_log_censor_modes() {
        let mut censor = test_censor();
        censor.set_mode(LogCensorMode::Dots);
        let ip_input = "1999-09-09 [INFO] New endpoint (1.2.3.4:1234) created";
        let censored = censor.censor_logs(ip_input.to_owned());
        assert_eq!(
            censored,
            "1999-09-09 [INFO] New endpoint (IP4(...):1234) created"
        );
        let domain_input = "see www.example.com. and *.example.co.uk here";
        let censored = censor.censor_logs(domain_input.to_owned());
        assert_eq!(censored, "see DOMAIN(...). and *.DOMAIN(...) here");

        censor.set_mode(LogCensorMode::EmptyString);
        let censored = censor.censor_logs(ip_input.to_owned());
        assert_eq!(censored, "1999-09-09 [INFO] New endpoint (:1234) created");
        // EmptyString drops the whole token, notation prefixes included.
        let censored = censor.censor_logs(domain_input.to_owned());
        assert_eq!(censored, "see  and  here");
    }

    // The multi-byte chars before the match used to shift the boundary
    // check (byte offsets were used as char indices), so "ace::cdcd" was
    // censored despite the alphanumeric 'm' right before it.
    #[test]
    fn test_boundary_check_handles_multibyte_chars() {
        let censor = test_censor();
        let input = "日志 mace::cdcd".to_owned();
        assert_eq!(censor.censor_logs(input.clone()), input);
    }

    #[test]
    fn test_has_ambiguous_casing_mixed_case() {
        assert!(LogCensor::has_ambiguous_casing("Example.COM"));
        assert!(LogCensor::has_ambiguous_casing("Example.Com"));
        assert!(LogCensor::has_ambiguous_casing("example.COM"));
        assert!(!LogCensor::has_ambiguous_casing("EXAMPLE.COM"));
        assert!(!LogCensor::has_ambiguous_casing("example.com"));
        assert!(!LogCensor::has_ambiguous_casing("example.com."));
    }
}
