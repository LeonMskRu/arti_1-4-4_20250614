#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

// TODO: write more comprehensive documentation when the API is a bit more
// stable

mod arti_path;
pub mod config;
mod err;
mod key_specifier;
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

#[cfg(feature = "keymgr")]
mod keystore;
#[cfg(feature = "keymgr")]
mod mgr;

#[cfg(not(feature = "keymgr"))]
mod dummy;

pub use arti_path::{ArtiPath, DENOTATOR_SEP};
pub use err::{
    ArtiPathSyntaxError, Error, KeystoreCorruptionError, KeystoreError, UnknownKeyTypeError,
};
pub use key_specifier::{
    ArtiPathRange, ArtiPathUnavailableError, CTorPath, CTorServicePath,
    InvalidKeyPathComponentValue, KeyCertificateSpecifier, KeyPath, KeyPathError, KeyPathInfo,
    KeyPathInfoBuilder, KeyPathInfoExtractor, KeyPathPattern, KeySpecifier, KeySpecifierComponent,
    KeySpecifierComponentViaDisplayFromStr, KeySpecifierPattern,
};

#[cfg(feature = "keymgr")]
#[cfg_attr(docsrs, doc(cfg(feature = "keymgr")))]
pub use {
    keystore::arti::ArtiNativeKeystore,
    keystore::Keystore,
    mgr::{KeyMgr, KeyMgrBuilder, KeyMgrBuilderError, KeystoreEntry},
    ssh_key,
};

#[cfg(all(feature = "keymgr", feature = "ephemeral-keystore"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "keymgr", feature = "ephemeral-keystore")))
)]
pub use keystore::ephemeral::ArtiEphemeralKeystore;

#[cfg(all(feature = "keymgr", feature = "ctor-keystore"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "keymgr", feature = "ctor-keystore"))))]
pub use keystore::ctor::{CTorClientKeystore, CTorServiceKeystore};

#[doc(hidden)]
pub use key_specifier::derive as key_specifier_derive;

pub use tor_key_forge::{
    EncodableItem, ErasedKey, KeyType, Keygen, KeygenRng, SshKeyAlgorithm, SshKeyData,
    ToEncodableKey,
};

derive_deftly::template_export_semver_check! { "0.12.1" }

#[cfg(not(feature = "keymgr"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "keymgr"))))]
pub use dummy::*;

/// A boxed [`Keystore`].
pub(crate) type BoxedKeystore = Box<dyn Keystore>;

#[doc(hidden)]
pub use {derive_deftly, inventory};

use derive_more::{AsRef, Display, From};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An identifier for a particular [`Keystore`] instance.
//
// TODO (#1193): restrict the charset of this ID
#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Display, AsRef,
)]
#[serde(transparent)]
#[non_exhaustive]
pub struct KeystoreId(String);

impl FromStr for KeystoreId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(s.into()))
    }
}

/// Specifies which keystores a [`KeyMgr`] operation should apply to.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash, From)]
#[non_exhaustive]
pub enum KeystoreSelector<'a> {
    /// Try to use the keystore with the specified ID.
    Id(&'a KeystoreId),
    /// Use the primary key store.
    #[default]
    Primary,
}
