use bytes::IntoBuf;
use futures::{future, Async, Future, Poll};
use h2;
use http;
use hyper;
use std::{self, error, fmt, net};
use std::marker::PhantomData;
use tokio::executor::Executor;
use tower_h2;

use super::{h1, Settings};
use super::glue::{BodyPayload, HttpBody, HyperConnect};
use super::upgrade::{HttpConnect, Http11Upgrade};
use svc;
use task::BoxExecutor;
use transport::connect;

/// Configurs an HTTP Client `Service` `Stack`.
///
/// `settings` determines whether an HTTP/1 or HTTP/2 client is used.
#[derive(Clone, Debug)]
pub struct Config {
    pub target: connect::Target,
    pub settings: Settings,
    _p: (),
}

/// Configurs an HTTP client that uses a `C`-typed connector
///
/// The `proxy_name` is used for diagnostics (logging, mostly).
#[derive(Debug)]
pub struct Stack<T, C, B>
where
    T: Into<Config>,
    C: svc::Stack<connect::Target>,
    C::Value: connect::Connect + Clone + Send + Sync + 'static,
    B: tower_h2::Body + 'static,
{
    connect: C,
    proxy_name: &'static str,
    _p: PhantomData<fn() -> (T, B)>,
}

/// A wrapper around the error types produced by the HTTP/1 and HTTP/2 clients.
///
/// Note that the names of the variants of this type (`Error::Http1` and
/// `Error::Http2`) aren't intended to imply that the error was a protocol
/// error; instead, they refer simply to which client the error occurred in.
/// Values of either variant may ultimately be caused by IO errors or other
/// types of error which could effect either protocol client.
#[derive(Debug)]
pub enum Error {
    Http1(hyper::Error),
    Http2(tower_h2::client::Error),
}

type HyperClient<C, B> =
    hyper::Client<HyperConnect<C>, BodyPayload<B>>;

/// A `NewService` that can speak either HTTP/1 or HTTP/2.
pub struct Client<C, E, B>
where
    B: tower_h2::Body + 'static,
    C: connect::Connect + 'static,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    inner: ClientInner<C, E, B>,
}

enum ClientInner<C, E, B>
where
    B: tower_h2::Body + 'static,
    C: connect::Connect + 'static,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    Http1(HyperClient<C, B>),
    Http2(tower_h2::client::Connect<C, BoxExecutor<E>, B>),
}

/// A `Future` returned from `Client::new_service()`.
pub struct ClientNewServiceFuture<C, E, B>
where
    B: tower_h2::Body + 'static,
    C: connect::Connect + 'static,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    inner: ClientNewServiceFutureInner<C, E, B>,
}

enum ClientNewServiceFutureInner<C, E, B>
where
    B: tower_h2::Body + 'static,
    C: connect::Connect + 'static,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    Http1(Option<HyperClient<C, B>>),
    Http2(tower_h2::client::ConnectFuture<C, BoxExecutor<E>, B>),
}

/// The `Service` yielded by `Client::new_service()`.
pub struct ClientService<C, E, B>
where
    B: tower_h2::Body + 'static,
    C: connect::Connect,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    inner: ClientServiceInner<C, E, B>,
}

enum ClientServiceInner<C, E, B>
where
    B: tower_h2::Body + 'static,
    C: connect::Connect,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    Http1(HyperClient<C, B>),
    Http2(tower_h2::client::Connection<
        <C as connect::Connect>::Connected,
        BoxExecutor<E>,
        B,
    >),
}

pub enum ClientServiceFuture {
    Http1 {
        future: hyper::client::ResponseFuture,
        upgrade: Option<Http11Upgrade>,
        is_http_connect: bool,
    },
    Http2(tower_h2::client::ResponseFuture),
}

// === impl Config ===

impl Config {
    pub fn new(target: connect::Target, settings: Settings) -> Self {
        Config { target, settings, _p: () }
    }
}

// === impl Stack ===

impl<T, C, B> Stack<T, C, B>
where
    T: Into<Config>,
    C: svc::Stack<connect::Target>,
    C::Value: connect::Connect + Clone + Send + Sync + 'static,
    B: tower_h2::Body + 'static,
{
    pub fn new(proxy_name: &'static str, connect: C) -> Self {
        Self {
            connect,
            proxy_name,
            _p: PhantomData,
        }
    }
}

impl<T, C, B> Clone for Stack<T, C, B>
where
    T: Into<Config>,
    C: svc::Stack<connect::Target> + Clone,
    C::Value: connect::Connect + Clone + Send + Sync + 'static,
    B: tower_h2::Body + 'static,
{
    fn clone(&self) -> Self {
        Self::new(self.proxy_name, self.connect.clone())
    }
}

impl<T, C, B> svc::Stack<T> for Stack<T, C, B>
where
    T: Into<Config> + Clone,
    C: svc::Stack<connect::Target>,
    C::Value: connect::Connect + Clone + Send + Sync + 'static,
    <C::Value as connect::Connect>::Connected: Send,
    <C::Value as connect::Connect>::Future: Send + 'static,
    <C::Value as connect::Connect>::Error: error::Error + Send + Sync,
    B: tower_h2::Body + Send + 'static,
    <B::Data as IntoBuf>::Buf: Send + 'static,
{
    type Value = Client<C::Value, ::logging::ClientExecutor<&'static str, net::SocketAddr>, B>;
    type Error = C::Error;

    fn make(&self, t: &T) -> Result<Self::Value, Self::Error> {
        let config = t.clone().into();
        let connect = self.connect.make(&config.target)?;
        let executor = ::logging::Client::proxy(self.proxy_name, config.target.addr)
            .with_settings(config.settings.clone())
            .executor();
        debug!("building client={:?}", config);
        Ok(Client::new(&config.settings, connect, executor))
    }
}

// === impl Client ===

impl<C, E, B> Client<C, E, B>
where
    C: connect::Connect + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    C::Error: error::Error + Send + Sync,
    C::Connected: Send,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
    B: tower_h2::Body + Send + 'static,
    <B::Data as IntoBuf>::Buf: Send + 'static,
{
    /// Create a new `Client`, bound to a specific protocol (HTTP/1 or HTTP/2).
    pub fn new(settings: &Settings, connect: C, executor: E) -> Self {
        match settings {
            Settings::Http1 { was_absolute_form, .. } => {
                let h1 = hyper::Client::builder()
                    .executor(executor)
                    // hyper should never try to automatically set the Host
                    // header, instead always just passing whatever we received.
                    .set_host(false)
                    .build(HyperConnect::new(connect, *was_absolute_form));
                Client {
                    inner: ClientInner::Http1(h1),
                }
            },
            Settings::Http2 => {
                let mut h2_builder = h2::client::Builder::default();
                // h2 currently doesn't handle PUSH_PROMISE that well, so we just
                // disable it for now.
                h2_builder.enable_push(false);
                let h2 = tower_h2::client::Connect::new(connect, h2_builder, BoxExecutor::new(executor));

                Client {
                    inner: ClientInner::Http2(h2),
                }
            }
        }
    }
}

impl<C, E, B> svc::NewService for Client<C, E, B>
where
    C: connect::Connect + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    <C::Future as Future>::Error: error::Error + Send + Sync,
    C::Connected: Send,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
    B: tower_h2::Body + Send + 'static,
   <B::Data as IntoBuf>::Buf: Send + 'static,
{
    type Request = <Self::Service as svc::Service>::Request;
    type Response = <Self::Service as svc::Service>::Response;
    type Error = <Self::Service as svc::Service>::Error;
    type InitError = tower_h2::client::ConnectError<C::Error>;
    type Service = ClientService<C, E, B>;
    type Future = ClientNewServiceFuture<C, E, B>;

    fn new_service(&self) -> Self::Future {
        let inner = match self.inner {
            ClientInner::Http1(ref h1) => {
                ClientNewServiceFutureInner::Http1(Some(h1.clone()))
            },
            ClientInner::Http2(ref h2) => {
                ClientNewServiceFutureInner::Http2(h2.new_service())
            },
        };
        ClientNewServiceFuture {
            inner,
        }
    }
}

// === impl ClientNewServiceFuture ===

impl<C, E, B> Future for ClientNewServiceFuture<C, E, B>
where
    C: connect::Connect + Send + 'static,
    C::Connected: Send,
    C::Future: Send + 'static,
    B: tower_h2::Body + Send + 'static,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
   <B::Data as IntoBuf>::Buf: Send + 'static,
{
    type Item = ClientService<C, E, B>;
    type Error = tower_h2::client::ConnectError<C::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let inner = match self.inner {
            ClientNewServiceFutureInner::Http1(ref mut h1) => {
                ClientServiceInner::Http1(h1.take().expect("poll more than once"))
            },
            ClientNewServiceFutureInner::Http2(ref mut h2) => {
                let s = try_ready!(h2.poll());
                ClientServiceInner::Http2(s)
            },
        };
        Ok(Async::Ready(ClientService {
            inner,
        }))
    }
}

// === impl ClientService ===

impl<C, E, B> svc::Service for ClientService<C, E, B>
where
    C: connect::Connect + Send + Sync + 'static,
    C::Connected: Send,
    C::Future: Send + 'static,
    <C::Future as Future>::Error: error::Error + Send + Sync,
    E: Executor + Clone,
    E: future::Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
    B: tower_h2::Body + Send + 'static,
   <B::Data as IntoBuf>::Buf: Send + 'static,
{
    type Request = http::Request<B>;
    type Response = http::Response<HttpBody>;
    type Error = Error;
    type Future = ClientServiceFuture;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        match self.inner {
            ClientServiceInner::Http1(_) => Ok(Async::Ready(())),
            ClientServiceInner::Http2(ref mut h2) => h2.poll_ready().map_err(Error::from),
        }
    }

    fn call(&mut self, req: Self::Request) -> Self::Future {
        debug!("client request: method={} uri={} version={:?} headers={:?}",
            req.method(), req.uri(), req.version(), req.headers());
        match self.inner {
            ClientServiceInner::Http1(ref h1) => {
                let mut req = req.map(BodyPayload::new);
                let upgrade = req.extensions_mut().remove::<Http11Upgrade>();
                let is_http_connect = if upgrade.is_some() {
                    req.method() == &http::Method::CONNECT
                } else {
                    false
                };
                ClientServiceFuture::Http1 {
                    future: h1.request(req),
                    upgrade,
                    is_http_connect,
                }
            },
            ClientServiceInner::Http2(ref mut h2) => {
                ClientServiceFuture::Http2(h2.call(req))
            },
        }
    }
}

// === impl ClietnServiceFuture ===

impl Future for ClientServiceFuture {
    type Item = http::Response<HttpBody>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            ClientServiceFuture::Http1 { future, upgrade, is_http_connect } => {
                let poll = future.poll()
                    .map_err(|e| {
                        debug!("http/1 client error: {}", e);
                        Error::from(e)
                    });
                let mut res = try_ready!(poll)
                    .map(move |b| HttpBody::Http1 {
                        body: Some(b),
                        upgrade: upgrade.take(),
                    });
                if *is_http_connect {
                    res.extensions_mut().insert(HttpConnect);
                }

                if h1::is_upgrade(&res) {
                    trace!("client response is HTTP/1.1 upgrade");
                } else {
                    h1::strip_connection_headers(res.headers_mut());
                }
                Ok(Async::Ready(res))
            },
            ClientServiceFuture::Http2(f) => {
                let res = try_ready!(f.poll());
                let res = res.map(HttpBody::Http2);
                Ok(Async::Ready(res))
            }
        }
    }
}

// === impl Error ===

impl From<tower_h2::client::Error> for Error {
    fn from(e: tower_h2::client::Error) -> Self {
        Error::Http2(e)
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Error::Http1(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Http1(ref e) => fmt::Display::fmt(e, f),
            Error::Http2(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            Error::Http1(e) => e.cause(),
            Error::Http2(e) => e.cause(),
        }
    }
}

impl Error {
    pub fn reason(&self) -> Option<h2::Reason> {
        match self {
            // TODO: it would be good to provide better error
            // details in metrics for HTTP/1...
            Error::Http1(_) => Some(h2::Reason::INTERNAL_ERROR),
            Error::Http2(e) => e.reason(),
        }
    }
}
