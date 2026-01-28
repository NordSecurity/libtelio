//! Code related to TP-Lite stats collection

use core::slice;
use std::{collections::HashMap, ffi::c_void};

use parking_lot::RwLock;
use telio_model::tp_lite_stats::{BlockedDomain, DnsMetrics, NoopCallback, TpLiteStatsCallback};

use crate::libfirewall::{LibfwBlockedDomain, LibfwDnsMetrics};

pub(crate) struct CallbackManager {
    // In Rust, Box<dyn Trait> is a fat pointer containing both the data
    // and a pointer to a vtable. It's structure is an implementation detail
    // of Rust, so it is not appropriate to pass it over an FFI boundary.
    // Double-boxing it like this turns it into a plain pointer we can pass
    // over the FFI boundary
    pub(crate) callback: RwLock<Box<Box<dyn TpLiteStatsCallback>>>,
}

impl CallbackManager {
    pub(crate) fn new() -> Self {
        // By initializing with a no-op callback we can avoid using Option which makes
        // usages of this simpler
        Self {
            callback: RwLock::new(Box::new(Box::new(NoopCallback))),
        }
    }

    pub(crate) fn as_raw_ptr(&self) -> *mut c_void {
        let cb = self.callback.read();
        let ptr = &**cb as *const Box<dyn TpLiteStatsCallback>;
        ptr as *mut c_void
    }
}

pub(crate) extern "C" fn collect_stats(
    data: *mut c_void,
    domains: *const LibfwBlockedDomain,
    num_blocked_domains: usize,
    metrics: LibfwDnsMetrics,
) {
    if data.is_null() {
        return;
    }

    let cb = unsafe { &*(data as *const Box<dyn TpLiteStatsCallback>) };
    let domains = unsafe { std::slice::from_raw_parts(domains, num_blocked_domains) }
        .iter()
        .map(BlockedDomain::from)
        .collect();
    cb.collect(domains, metrics.into());
}

impl From<LibfwDnsMetrics> for DnsMetrics {
    fn from(metrics: LibfwDnsMetrics) -> Self {
        Self {
            num_requests: metrics.num_requests,
            num_responses: metrics.num_responses,
            num_malformed_requests: metrics.num_malformed_requests,
            num_malformed_responses: metrics.num_malformed_responses,
            num_cache_hits: metrics.num_cache_hits,
            record_type_distribution: unsafe {
                slice::from_raw_parts(metrics.record_type_distribution, metrics.num_record_types)
                    .iter()
                    .map(|count| (count.rr_type, count.count))
                    .collect::<HashMap<u16, u32>>()
            },
            response_type_distribution: unsafe {
                slice::from_raw_parts(
                    metrics.response_code_distribution,
                    metrics.num_response_codes,
                )
                .iter()
                .map(|count| (count.rr_type, count.count))
                .collect::<HashMap<u8, u32>>()
            },
        }
    }
}

impl From<&LibfwBlockedDomain> for BlockedDomain {
    fn from(domain: &LibfwBlockedDomain) -> Self {
        Self {
            domain_name: unsafe { std::ffi::CStr::from_ptr(domain.domain_name) }
                .to_string_lossy()
                .into_owned(),
            record_type: domain.record_type,
            timestamp: domain.timestamp,
            category: unsafe { std::ffi::CStr::from_ptr(domain.category) }
                .to_string_lossy()
                .into_owned(),
        }
    }
}
