use std::time::Duration;

use Conditional;

pub struct Config {
    backoff: Duration,
    connect_timeout: Duration,
    tls: Conditional<()>,
}

pub mod resolve {
    use std::marker::PhantomData;

    use dns;
    use proxy::http::client;
    use svc;

    pub struct Layer<M> {
        dns: dns::Resolver,
        _p: PhantomData<fn() -> M>,
    }

    pub struct Stack<M> {
        dns: dns::Resolver,
        inner: M,
    }

    pub struct Service<M> {
        tls: tls
        dns: dns::Resolver,
        inner: M,
    }


    impl<M> svc::Layer<super::Config, client::Config, M> Layer<M>
    where
        M: svc::Stack<client::Config> + Clone,
    {
        type Value = <Stack<M> as svc::Stack<client::Config>>::Value;
        type Error = <Stack<M> as svc::Stack<client::Config>>::Error;
        type Stack = Stack<M>;

        fn bind(&self, inner: M) -> Self::Stack {
            Stack {
                inner,
                dns: self.dns.clone(),
            }
        }
    }

    impl<M> svc::Stack<super::Config> Stack<M>
    where
        M: svc::Stack<client::Config> + Clone,
    {
        type Value = Service;
        type Error = <Stack<M> as svc::Stack<client::Config>>::Error;

        fn make(&self, &config: &super::Config) -> Self::Stack {
            Stack {
                inner,
                dns: self.dns.clone(),
            }
        }
    }
}

/// The state needed to bind a new controller client stack.
pub(super) struct BindClient {
    backoff_delay: Duration,
    identity: Conditional<tls::Identity, tls::ReasonForNoTls>,
    host_and_port: HostAndPort,
    dns_resolver: dns::Resolver,
    log_ctx: ::logging::Client<&'static str, HostAndPort>,
}

pub mod with_tls {
    use http;

    use svc;
    use Conditional;

    impl<M: > svc::Stack<tls::ConditionalClientConfig> for Stack<M> {
        type Value = AddOrigin;
        type Error = ();

        fn make(&self, cfg: &tls::ConditionalClientConfig) -> Result<Self::Value, Self::Error> {
            let conn_cfg = match (&self.identity, cfg) {
                (Conditional::Some(ref id), Conditional::Some(ref cfg)) =>
                    Conditional::Some(tls::ConnectionConfig {
                        server_identity: id.clone(),
                        config: cfg.clone(),
                    }),
                (Conditional::None(ref reason), _) |
                (_, Conditional::None(ref reason)) =>
                    Conditional::None(reason.clone()),
            };

            let scheme = http::uri::Scheme::from_shared(Bytes::from_static(b"http")).unwrap();
            let authority = http::uri::Authority::from(&self.host_and_port);
            Ok(AddOrigin::new(backoff, scheme, authority))
        }
    }
}
