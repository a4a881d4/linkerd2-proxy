use futures_watch::Watch;
use std::marker::PhantomData;

use svc;
use transport::tls;

pub trait WithTls {
    type WithTls;

    fn with_tls(&self, tls: &tls::ConditionalClientConfig) -> Self::WithTls;
}

#[derive(Debug)]
pub struct Layer<T: WithTls, M: svc::Stack<T::WithTls>> {
    watch: Watch<tls::ConditionalClientConfig>,
    _p: PhantomData<fn() -> (T, M)>,
}

#[derive(Clone, Debug)]
pub struct Stack<T: WithTls, M: svc::Stack<T::WithTls>> {
    watch: Watch<tls::ConditionalClientConfig>,
    inner: M,
    _p: PhantomData<fn() -> T>,
}

#[derive(Clone, Debug)]
pub struct StackWithTls<T: WithTls, M: svc::Stack<T::WithTls>> {
    target: T,
    inner: M,
}

impl<T, M> Layer<T, M>
where
    T: WithTls + Clone,
    M: svc::Stack<T::WithTls> + Clone,
{
    pub fn new(watch: Watch<tls::ConditionalClientConfig>) -> Self {
        Layer {
            watch,
            _p: PhantomData,
        }
    }
}

impl<T, M> Clone for Layer<T, M>
where
    T: WithTls + Clone,
    M: svc::Stack<T::WithTls> + Clone,
{
    fn clone(&self) -> Self {
        Self::new(self.watch.clone())
    }
}

impl<T, M> svc::Layer<T, T::WithTls, M> for Layer<T, M>
where
    T: WithTls + Clone,
    M: svc::Stack<T::WithTls> + Clone,
{
    type Value = <Stack<T, M> as svc::Stack<T>>::Value;
    type Error = <Stack<T, M> as svc::Stack<T>>::Error;
    type Stack = Stack<T, M>;

    fn bind(&self, inner: M) -> Self::Stack {
        Stack {
            inner,
            watch: self.watch.clone(),
            _p: PhantomData,
        }
    }
}

impl<T, M> svc::Stack<T> for Stack<T, M>
where
    T: WithTls + Clone,
    M: svc::Stack<T::WithTls> + Clone,
{
    type Value = svc::watch::Service<tls::ConditionalClientConfig, StackWithTls<T, M>>;
    type Error = M::Error;

    fn make(&self, target: &T) -> Result<Self::Value, Self::Error> {
        let inner = StackWithTls {
            target: target.clone(),
            inner: self.inner.clone(),
        };
        svc::watch::Service::try(self.watch.clone(), inner)
    }
}

impl<T, M> svc::Stack<tls::ConditionalClientConfig> for StackWithTls<T, M>
where
    T: WithTls,
    M: svc::Stack<T::WithTls>,
{
    type Value = M::Value;
    type Error = M::Error;

    fn make(&self, tls: &tls::ConditionalClientConfig) -> Result<Self::Value, Self::Error> {
        self.inner.make(&self.target.with_tls(tls))
    }
}
