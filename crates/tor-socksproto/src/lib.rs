#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod err;
mod handshake;
mod msg;

pub use err::Error;
pub use handshake::Action;

#[cfg(feature = "proxy-handshake")]
#[cfg_attr(docsrs, doc(cfg(feature = "proxy-handshake")))]
pub use handshake::proxy::SocksProxyHandshake;

#[cfg(feature = "client-handshake")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-handshake")))]
pub use handshake::client::SocksClientHandshake;

#[cfg(any(feature = "proxy-handshake", feature = "client-handshake"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "proxy-handshake", feature = "client-handshake")))
)]
pub use handshake::framework::{
    Buffer, Finished, Handshake, NextStep, PreciseReads, ReadPrecision, RecvStep,
};

#[deprecated(since = "0.5.2", note = "Use SocksProxyHandshake instead.")]
#[cfg(feature = "proxy-handshake")]
#[cfg_attr(docsrs, doc(cfg(feature = "proxy-handshake")))]
pub use SocksProxyHandshake as SocksHandshake;

pub use msg::{
    SocksAddr, SocksAuth, SocksCmd, SocksHostname, SocksReply, SocksRequest, SocksStatus,
    SocksVersion,
};
pub use tor_error::Truncated;

/// A Result type for the tor_socksproto crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A Result type for the tor_socksproto crate, including the possibility of a
/// truncated message.
///
/// This is a separate type from Result because a truncated message is not a
/// true error: it just means that you need to read more bytes and try again.
pub type TResult<T> = std::result::Result<Result<T>, Truncated>;

/// Suggested buffer length for socks handshakes.
//
// Note: This is chosen somewhat arbitrarily,
// to be large enough for any SOCKS handshake Tor will ever want to consume.
pub const SOCKS_BUF_LEN: usize = 1024;
