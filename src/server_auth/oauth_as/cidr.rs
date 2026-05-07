//! Minimal CIDR membership check for IPv4/IPv6. Used to gate
//! `/authorize` to requests originating from the configured reverse
//! proxy — anyone outside the trusted CIDRs cannot inject a fake
//! `X-Forwarded-User` because their request never reaches the
//! authorization step.
//!
//! Pulling a real CIDR crate would be overkill for the handful of
//! comparisons we actually do. The implementation is bit-exact and
//! covered by tests.

use anyhow::{bail, Result};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("CIDR missing '/': {s}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prefix length: {prefix}"))?;
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IP: {addr}"))?;
        match ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    bail!("v4 prefix > 32: {prefix}");
                }
                let bits = u32::from_be_bytes(v4.octets());
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(Cidr::V4 {
                    network: bits & mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    bail!("v6 prefix > 128: {prefix}");
                }
                let bits = u128::from_be_bytes(v6.octets());
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Ok(Cidr::V6 {
                    network: bits & mask,
                    prefix,
                })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(v4)) => {
                let bits = u32::from_be_bytes(v4.octets());
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (bits & mask) == *network
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(v6)) => {
                let bits = u128::from_be_bytes(v6.octets());
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (bits & mask) == *network
            }
            // v4 / v6 mismatch never matches.
            _ => false,
        }
    }
}

/// True iff `ip` belongs to any CIDR in the list. Empty list is a
/// programming error — callers must reject empty lists at config
/// validation time, not here.
pub fn ip_in_any(ip: IpAddr, cidrs: &[Cidr]) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

pub fn parse_all(specs: &[String]) -> Result<Vec<Cidr>> {
    specs.iter().map(|s| Cidr::parse(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    #[test]
    fn test_v4_loopback_membership() {
        let c = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_v4_exact_host() {
        let c = Cidr::parse("10.0.0.5/32").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
    }

    #[test]
    fn test_v6_membership() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(IpAddr::V6("2001:db8:cafe::1".parse::<Ipv6Addr>().unwrap())));
        assert!(!c.contains(IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn test_v4_v6_mismatch_never_matches() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!c.contains(IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn test_zero_prefix_matches_all() {
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        assert!(Cidr::parse("nope").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("::1/200").is_err());
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn test_ip_in_any_with_multiple_ranges() {
        let cidrs = parse_all(&["127.0.0.0/8".to_string(), "10.0.0.0/8".to_string()]).unwrap();
        assert!(ip_in_any(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), &cidrs));
        assert!(!ip_in_any(
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            &cidrs
        ));
    }
}
