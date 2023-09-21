use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Possible [DualTarget] errors.
#[derive(thiserror::Error, Debug)]
pub enum DualTargetError {
    /// Target error
    #[error("No IP target provided")]
    NoTarget,
}

/// Result for [DualTarget] constructor
pub type Result<T> = std::result::Result<T, DualTargetError>;

/// Target input with IPv4 and IPv6 addresses
pub type Target = (Option<Ipv4Addr>, Option<Ipv6Addr>);

/// DualTarget wrapper
#[derive(Clone, Copy, Debug)]
pub struct DualTarget {
    target: Target,
}

impl DualTarget {
    /// [DualTarget] constructor
    pub fn new(mut target: Target, use_ipv6: bool) -> Result<Self> {
        if !use_ipv6 {
            target.1 = None;
        }

        if target.0.is_none() && target.1.is_none() {
            return Err(DualTargetError::NoTarget);
        }

        Ok(DualTarget { target })
    }

    /// Get target IPs
    pub fn get_targets(self) -> Result<(IpAddr, Option<IpAddr>)> {
        match self.target {
            // IPv6 target is preffered, because we can be sure, that address is unique
            (Some(ip4), Some(ip6)) => Ok((IpAddr::V6(ip6), Some(IpAddr::V4(ip4)))),
            (Some(ip4), None) => Ok((IpAddr::V4(ip4), None)),
            (None, Some(ip6)) => Ok((IpAddr::V6(ip6), None)),
            (None, None) => Err(DualTargetError::NoTarget),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_dual_target() {
        assert!(DualTarget::new((None, None), false).is_err());
        assert!(DualTarget::new((None, None), true).is_err());

        assert_eq!(
            (
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
            ),
            DualTarget::new((Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)), true)
                .unwrap()
                .get_targets()
                .unwrap()
        );

        assert_eq!(
            (IpAddr::V4(Ipv4Addr::LOCALHOST), None),
            DualTarget::new(
                (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)),
                false
            )
            .unwrap()
            .get_targets()
            .unwrap()
        );

        assert_eq!(
            (IpAddr::V4(Ipv4Addr::LOCALHOST), None),
            DualTarget::new((Some(Ipv4Addr::LOCALHOST), None), true)
                .unwrap()
                .get_targets()
                .unwrap()
        );

        assert_eq!(
            (IpAddr::V4(Ipv4Addr::LOCALHOST), None),
            DualTarget::new((Some(Ipv4Addr::LOCALHOST), None), false)
                .unwrap()
                .get_targets()
                .unwrap()
        );

        assert_eq!(
            (IpAddr::V6(Ipv6Addr::LOCALHOST), None),
            DualTarget::new((None, Some(Ipv6Addr::LOCALHOST)), true)
                .unwrap()
                .get_targets()
                .unwrap()
        );

        assert!(DualTarget::new((None, Some(Ipv6Addr::LOCALHOST)), false).is_err());
    }
}
