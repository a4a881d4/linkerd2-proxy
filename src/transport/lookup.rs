use futures::Future;
use std::{error, fmt, io};
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};

use dns;
use svc;
use transport::{connect, tls, HostAndPort};

#[derive(Debug)]
pub struct Stack<T> {
    dns_resolver: dns::Resolver,
    _p: PhantomData<fn() -> T>,
}

#[derive(Debug, Clone)]
pub struct Connect {
    target: Target,
    dns_resolver: dns::Resolver,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub host_and_port: HostAndPort,
    pub tls: tls::ConditionalConnectionConfig<tls::ClientConfig>,
    _p: (),
}

pub enum Error {
    Io(io::Error),
    Resolve(dns::Error),
}

/// Note: this isn't actually used, but is needed to satisfy Error.
#[derive(Debug)]
pub struct InvalidTarget;

impl<T> Stack<T>
where
    T: Clone,
    Target: From<T>,
{
    pub fn new(dns_resolver: dns::Resolver) -> Self {
        Self {
            dns_resolver,
            _p: PhantomData,
        }
    }
}
impl<T> svc::Stack<T> for Stack<T>
where
    T: Clone,
    Target: From<T>,
{
    type Value = Connect;
    type Error = InvalidTarget;

    fn make(&self, t: &T) -> Result<Self::Value, Self::Error> {
        Ok(Connect {
            target:  t.clone().into(),
            dns_resolver: self.dns_resolver.clone(),
        })
    }
}

impl connect::Connect for Connect {
    type Connected = super::Connection;
    type Error = Error;
    type Future = Box<Future<Item = Self::Connected, Error = Self::Error> + Send>;

    fn connect(&self) -> Self::Future {
        let host_and_port = self.target.host_and_port.clone();
        let tls = self.target.tls.clone();
        let c = self.dns_resolver
            .resolve_one_ip(&self.target.host_and_port.host)
            .map_err(Error::Resolve)
            .and_then(move |ip_addr: IpAddr| {
                debug!("DNS resolved {:?} to {}", host_and_port.host, ip_addr);
                let addr = SocketAddr::from((ip_addr, host_and_port.port));
                connect::Connect::connect(&connect::Target::new(addr, tls))
                    .map_err(Error::Io)
            });
        Box::new(c)
    }
}

impl fmt::Display for InvalidTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid target")
    }
}

impl error::Error for InvalidTarget {}
