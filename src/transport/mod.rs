mod addr_info;
pub mod connect;
mod connection;
mod io;
pub mod metrics;
mod names;
mod prefixed;
pub mod tls;

#[cfg(test)]
mod connection_tests;

pub use self::{
    addr_info::{
        AddrInfo,
        GetOriginalDst,
        SoOriginalDst
    },
    connect::Connect,
    connection::{
        BoundPort,
        Connection,
        Peek,
    },
    names::{DnsNameAndPort, Host, HostAndPort, HostAndPortError},
    io::BoxedIo,
};
