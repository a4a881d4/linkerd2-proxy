use http;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use convert::TryFrom;
use dns;

#[derive(Clone, Debug)]
pub struct HostAndPort {
    pub host: Host,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsNameAndPort {
    pub host: dns::Name,
    pub port: u16,
}


#[derive(Clone, Debug)]
pub enum Host {
    DnsName(dns::Name),
    Ip(IpAddr),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HostAndPortError {
    /// The host is not a valid DNS name or IP address.
    InvalidHost,

    /// The port is missing.
    MissingPort,
}

// ===== impl HostAndPort =====

impl HostAndPort {
    pub fn normalize(a: &http::uri::Authority, default_port: Option<u16>)
        -> Result<Self, HostAndPortError>
    {
        let host = IpAddr::from_str(a.host())
            .map(Host::Ip)
            .or_else(|_|
                dns::Name::try_from(a.host().as_bytes())
                    .map(Host::DnsName)
                    .map_err(|_| HostAndPortError::InvalidHost))?;
        let port = a.port()
            .or(default_port)
            .ok_or_else(|| HostAndPortError::MissingPort)?;
        Ok(HostAndPort {
            host,
            port
        })
    }

    pub fn is_loopback(&self) -> bool {
        match &self.host {
            Host::DnsName(dns_name) => dns_name.is_localhost(),
            Host::Ip(ip) => ip.is_loopback(),
        }
    }
}

impl<'a> From<&'a HostAndPort> for http::uri::Authority {
    fn from(a: &HostAndPort) -> Self {
        let s = match a.host {
            Host::DnsName(ref n) => format!("{}:{}", n, a.port),
            Host::Ip(ref ip) => format!("{}:{}", ip, a.port),
        };
        http::uri::Authority::from_str(&s).unwrap()
    }
}

impl fmt::Display for HostAndPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.host {
            Host::DnsName(ref dns) => {
                write!(f, "{}:{}", dns, self.port)
            }
            Host::Ip(ref ip) => {
                write!(f, "{}:{}", ip, self.port)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use http::uri::Authority;
    use super::*;

    #[test]
    fn test_is_loopback() {
        let cases = &[
            ("localhost", false), // Not absolute
            ("localhost.", true),
            ("LocalhOsT.", true), // Case-insensitive
            ("mlocalhost.", false), // prefixed
            ("localhost1.", false), // suffixed
            ("127.0.0.1", true), // IPv4
            ("[::1]", true), // IPv6
        ];
        for (host, expected_result) in cases {
            let authority = Authority::from_static(host);
            let hp = HostAndPort::normalize(&authority, Some(80)).unwrap();
            assert_eq!(hp.is_loopback(), *expected_result, "{:?}", host)
        }
    }
}
