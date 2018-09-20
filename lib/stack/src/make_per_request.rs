#![allow(dead_code)]

use futures::Poll;
use std::fmt;
use std::marker::PhantomData;

use svc;

pub struct Layer<T>(PhantomData<fn() -> T>);

/// A `Make` that builds a single-serving client for each request.
#[derive(Clone, Debug)]
pub struct Make<T, M: super::Make<T>> {
    inner: M,
    _p: PhantomData<fn() -> T>,
}

/// A `Service` that optionally uses a
///
/// `Service` does not handle any underlying errors and it is expected that an
/// instance will not be used after an error is returned.
pub struct Service<T, M: super::Make<T>> {
    // When `poll_ready` is called, the _next_ service to be used may be bound
    // ahead-of-time. This stack is used only to serve the next request to this
    // service.
    next: Option<M::Output>,
    make: MakeValid<T, M>
}

struct MakeValid<T, M: super::Make<T>> {
    target: T,
    make: M,
}

// === Layer ===

pub fn layer<T>() -> Layer<T> {
    Layer(PhantomData)
}

impl<T, N> super::Layer<N> for Layer<T>
where
    T: Clone,
    N: super::Make<T> + Clone,
    N::Error: fmt::Debug,
{
    type Bound = Make<T, N>;

    fn bind(&self, inner: N) -> Self::Bound {
        Make {
            inner,
            _p: PhantomData,
        }
    }
}

// === Make ===

impl<T, N> super::Make<T> for Make<T, N>
where
    T: Clone,
    N: super::Make<T> + Clone,
    N::Error: fmt::Debug,
{
    type Output = Service<T, N>;
    type Error = N::Error;

    fn make(&self, target: &T) -> Result<Self::Output, N::Error> {
        let next = self.inner.make(target)?;
        let valid = MakeValid {
            make: self.inner.clone(),
            target: target.clone(),
        };
        Ok(Service {
            next: Some(next),
            make: valid,
        })
    }
}

// === Service ===

impl<T, N> svc::Service for Service<T, N>
where
    T: Clone,
    N: super::Make<T> + Clone,
    N::Output: svc::Service,
    N::Error: fmt::Debug,
{
    type Request = <N::Output as svc::Service>::Request;
    type Response = <N::Output as svc::Service>::Response;
    type Error = <N::Output as svc::Service>::Error;
    type Future = <N::Output as svc::Service>::Future;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        if let Some(ref mut svc) = self.next {
            return svc.poll_ready();
        }

        trace!("poll_ready: new disposable client");
        let mut svc = self.make.make_valid();
        let ready = svc.poll_ready()?;
        self.next = Some(svc);
        Ok(ready)
    }

    fn call(&mut self, request: Self::Request) -> Self::Future {
        // If a service has already been bound in `poll_ready`, consume it.
        // Otherwise, bind a new service on-the-spot.
        self.next
            .take()
            .unwrap_or_else(|| self.make.make_valid())
            .call(request)
    }
}

// === MakeValid ===

impl<T, M> MakeValid<T, M>
where
    M: super::Make<T>,
    M::Error: fmt::Debug
{
    fn make_valid(&self) -> M::Output {
        self.make
            .make(&self.target)
            .expect("make must succeed")
    }
}