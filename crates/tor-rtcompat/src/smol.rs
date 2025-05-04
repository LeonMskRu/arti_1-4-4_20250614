//! Entry points for use with smol runtimes.
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.

/// Re-export the Smol runtime constructor implemented in `impls/smol.rs`.
pub use crate::impls::smol::create_runtime as create_runtime_impl;

use crate::{compound::CompoundRuntime, RealCoarseTimeProvider, ToplevelBlockOn};
use std::io::Result as IoResult;

#[cfg(feature = "native-tls")]
use crate::impls::native_tls::NativeTlsProvider;
#[cfg(feature = "rustls")]
use crate::impls::rustls::RustlsProvider;

// Bring in our Smol handle type
use crate::impls::smol::SmolRuntimeHandle;

/// An alias for the smol runtime that we prefer to use, based on whatever TLS
/// implementation has been enabled.
#[cfg(feature = "native-tls")]
pub use SmolNativeTlsRuntime as PreferredRuntime;
#[cfg(all(feature = "rustls", not(feature = "native-tls")))]
pub use SmolRustlsRuntime as PreferredRuntime;

/// A [`Runtime`](crate::Runtime) powered by smol and native-tls.
#[derive(Clone)]
#[cfg(feature = "native-tls")]
pub struct SmolNativeTlsRuntime {
    inner: NativeTlsInner,
}

#[cfg(feature = "native-tls")]
type NativeTlsInner = CompoundRuntime<
    SmolRuntimeHandle,
    SmolRuntimeHandle,
    RealCoarseTimeProvider,
    SmolRuntimeHandle,
    SmolRuntimeHandle,
    NativeTlsProvider,
    SmolRuntimeHandle,
>;

#[cfg(feature = "native-tls")]
crate::opaque::implement_opaque_runtime! {
    SmolNativeTlsRuntime { inner: NativeTlsInner }
}

/// A [`Runtime`](crate::Runtime) powered by smol and rustls.
#[derive(Clone)]
#[cfg(feature = "rustls")]
pub struct SmolRustlsRuntime {
    inner: RustlsInner,
}

#[cfg(feature = "rustls")]
type RustlsInner = CompoundRuntime<
    SmolRuntimeHandle,
    SmolRuntimeHandle,
    RealCoarseTimeProvider,
    SmolRuntimeHandle,
    SmolRuntimeHandle,
    RustlsProvider,
    SmolRuntimeHandle,
>;

#[cfg(feature = "rustls")]
crate::opaque::implement_opaque_runtime! {
    SmolRustlsRuntime { inner: RustlsInner }
}

#[cfg(feature = "native-tls")]
impl SmolNativeTlsRuntime {
    /// Create a new `SmolNativeTlsRuntime` (owns its executor).
    pub fn create() -> IoResult<Self> {
        let rt = create_runtime_impl();
        let ct = RealCoarseTimeProvider::new();
        Ok(SmolNativeTlsRuntime {
            inner: CompoundRuntime::new(
                rt.clone(),
                rt.clone(),
                ct,
                rt.clone(),
                rt.clone(),
                NativeTlsProvider::default(),
                rt.clone(),
            ),
        })
    }

    /// Return a `SmolNativeTlsRuntime` for the current smol executor.
    pub fn current() -> IoResult<Self> {
        // smol executors are global, so this is same as `create()`
        Self::create()
    }

    /// Run a single test function in a fresh runtime (Arti-internal API).
    #[doc(hidden)]
    pub fn run_test<P, F, O>(func: P) -> O
    where
        P: FnOnce(Self) -> F,
        F: futures::Future<Output = O>,
    {
        let runtime = Self::create().expect("Failed to create runtime");
        runtime.clone().block_on(func(runtime))
    }
}

#[cfg(feature = "rustls")]
impl SmolRustlsRuntime {
    /// Create a new `SmolRustlsRuntime` (owns its executor).
    pub fn create() -> IoResult<Self> {
        let rt = create_runtime_impl();
        let ct = RealCoarseTimeProvider::new();
        Ok(SmolRustlsRuntime {
            inner: CompoundRuntime::new(
                rt.clone(),
                rt.clone(),
                ct,
                rt.clone(),
                rt.clone(),
                RustlsProvider::default(),
                rt.clone(),
            ),
        })
    }

    /// Return a `SmolRustlsRuntime` for the current smol executor.
    pub fn current() -> IoResult<Self> {
        Self::create()
    }

    #[doc(hidden)]
    pub fn run_test<P, F, O>(func: P) -> O
    where
        P: FnOnce(Self) -> F,
        F: futures::Future<Output = O>,
    {
        let runtime = Self::create().expect("Failed to create runtime");
        runtime.clone().block_on(func(runtime))
    }
}
