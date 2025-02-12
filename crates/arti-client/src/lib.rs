#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

mod address;
mod builder;
mod client;
#[cfg(feature = "rpc")]
pub mod rpc;
mod util;

pub mod config;
pub mod status;

pub use address::{DangerouslyIntoTorAddr, IntoTorAddr, TorAddr, TorAddrError};
pub use builder::{TorClientBuilder, MAX_LOCAL_RESOURCE_TIMEOUT};
pub use client::{BootstrapBehavior, DormantMode, InertTorClient, StreamPrefs, TorClient};
pub use config::TorClientConfig;

pub use tor_circmgr::isolation;
pub use tor_circmgr::IsolationToken;
pub use tor_error::{ErrorKind, HasKind};
pub use tor_proto::stream::{DataReader, DataStream, DataWriter};

mod err;
pub use err::{Error, ErrorHint, HintableError};

#[cfg(feature = "error_detail")]
pub use err::ErrorDetail;

/// Alias for the [`Result`] type corresponding to the high-level [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "experimental-api")]
pub use builder::DirProviderBuilder;

#[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "onion-service-client", feature = "experimental-api")))
)]
pub use {
    tor_hscrypto::pk::{HsClientDescEncKey, HsId},
    tor_keymgr::KeystoreSelector,
};

#[cfg(feature = "geoip")]
#[cfg_attr(docsrs, doc(cfg(feature = "geoip")))]
pub use tor_geoip::CountryCode;
