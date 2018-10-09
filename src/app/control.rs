use std::fmt;
use std::time::Duration;

use proxy::watch_tls::WithTls;
use transport::{tls, HostAndPort};
use Conditional;

#[derive(Clone, Debug)]
pub struct Config {
    host_and_port: HostAndPort,
    tls_server_identity: Conditional<tls::Identity, tls::ReasonForNoTls>,
    tls_config: tls::ConditionalClientConfig,
    backoff: Duration,
    connect_timeout: Duration,
}

impl Config {
    pub fn new(
        host_and_port: HostAndPort,
        tls_server_identity: Conditional<tls::Identity, tls::ReasonForNoTls>,
        backoff: Duration,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            host_and_port,
            tls_server_identity,
            tls_config: Conditional::None(tls::ReasonForNoTls::Disabled),
            backoff,
            connect_timeout,
        }
    }
}

impl WithTls for Config {
    type WithTls = Self;

    fn with_tls(&self, tls_config: &tls::ConditionalClientConfig) -> Self::WithTls {
        let mut c = self.clone();
        c.tls_config = tls_config.clone();
        c
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.host_and_port, f)
    }
}

/// A module that resolves the controller's `host_and_port` once before building
/// a client.
pub mod resolve {
    use futures::{Future, Poll};
    use std::{error, fmt};
    use std::marker::PhantomData;
    use std::net::SocketAddr;

    use dns;
    use proxy::http::{client, Settings};
    use svc;
    use transport::{connect, tls};

    #[derive(Debug)]
    pub struct Layer<M> {
        dns: dns::Resolver,
        _p: PhantomData<fn() -> M>,
    }

    #[derive(Clone, Debug)]
    pub struct Stack<M> {
        dns: dns::Resolver,
        inner: M,
    }

    pub struct NewService<M> {
        config: super::Config,
        dns: dns::Resolver,
        stack: M,
    }

    pub struct Init<M>
    where
        M: svc::Stack<client::Config>,
        M::Value: svc::NewService,
    {
        state: State<M>,
    }

    enum State<M>
    where
        M: svc::Stack<client::Config>,
        M::Value: svc::NewService,
    {
        Resolve {
            future: dns::IpAddrFuture,
            config: super::Config,
            stack: M,
        },
        Inner(<M::Value as svc::NewService>::Future),
    }

    #[derive(Debug)]
    pub enum Error<S, I> {
        Dns(dns::Error),
        Invalid(S),
        Inner(I),
    }

    // === impl Layer ===

    impl<M> Layer<M>
    where
        M: svc::Stack<client::Config> + Clone,
    {
        pub fn new(dns: dns::Resolver) -> Self {
            Self {
                dns,
                _p: PhantomData,
            }
        }
    }

    impl<M> Clone for Layer<M>
    where
        M: svc::Stack<client::Config> + Clone,
    {
        fn clone(&self) -> Self {
            Self::new(self.dns.clone())
        }
    }

    impl<M> svc::Layer<super::Config, client::Config, M> for Layer<M>
    where
        M: svc::Stack<client::Config> + Clone,
    {
        type Value = <Stack<M> as svc::Stack<super::Config>>::Value;
        type Error = <Stack<M> as svc::Stack<super::Config>>::Error;
        type Stack = Stack<M>;

        fn bind(&self, inner: M) -> Self::Stack {
            Stack {
                inner,
                dns: self.dns.clone(),
            }
        }
    }

    // === impl Stack ===

    impl<M> svc::Stack<super::Config> for Stack<M>
    where
        M: svc::Stack<client::Config> + Clone,
    {
        type Value = NewService<M>;
        type Error = M::Error;

        fn make(&self, &config: &super::Config) -> Result<Self::Value, Self::Error> {
            Ok(NewService {
                dns: self.dns.clone(),
                config: config.clone(),
                stack: self.inner.clone(),
            })
        }
    }

    // === impl NewService ===

    impl<M> svc::NewService for NewService<M>
    where
        M: svc::Stack<client::Config> + Clone,
        M::Value: svc::NewService,
    {
        type Request = <M::Value as svc::NewService>::Request;
        type Response = <M::Value as svc::NewService>::Response;
        type Error = <M::Value as svc::NewService>::Error;
        type Service = <M::Value as svc::NewService>::Service;
        type InitError = <Init<M> as Future>::Error;
        type Future = Init<M>;

        fn new_service(&self) -> Self::Future {
            Init {
                state: State::Resolve {
                    future: self.dns.resolve_one_ip(&self.config.host_and_port.host),
                    stack: self.stack.clone(),
                    config: self.config.clone(),
                },
            }
        }
    }

    // === impl Init ===

    impl<M> Future for Init<M>
    where
        M: svc::Stack<client::Config>,
        M::Value: svc::NewService,
    {
        type Item = <M::Value as svc::NewService>::Service;
        type Error = Error<M::Error, <M::Value as svc::NewService>::InitError>;

        fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
            loop {
                match self.state {
                    State::Inner(ref mut fut) => {
                        return fut.poll().map_err(Error::Inner);
                    }
                    State::Resolve {
                        ref mut future,
                        ref config,
                        ref stack,
                    } => {
                        let ip = try_ready!(future.poll().map_err(Error::Dns));
                        let sa = SocketAddr::from((ip, config.host_and_port.port));

                        let tls = config.tls_server_identity.as_ref().and_then(|id| {
                            config
                                .tls_config
                                .as_ref()
                                .map(|config| tls::ConnectionConfig {
                                    server_identity: id.clone(),
                                    config: config.clone(),
                                })
                        });

                        let target = connect::Target::new(sa, tls);
                        let config = client::Config::new(target, Settings::Http2);
                        let inner = stack.make(&config).map_err(Error::Invalid)?;
                        self.state = State::Inner(svc::NewService::new_service(&inner));
                    }
                };
            }
        }
    }

    // === impl Error ===

    impl<S: fmt::Display, I: fmt::Display> fmt::Display for Error<S, I> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Error::Dns(ref e) => write!(f, "dns error"),
                Error::Invalid(ref e) => fmt::Display::fmt(&e, f),
                Error::Inner(ref e) => fmt::Display::fmt(&e, f),
            }
        }
    }

    impl<S: error::Error, I: error::Error> error::Error for Error<S, I> {}
}
