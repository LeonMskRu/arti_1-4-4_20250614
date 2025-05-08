#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod certs;
mod err;
mod key_type;
mod macros;
mod ssh;
mod traits;

pub use certs::{CertData, ParsedEd25519Cert, ValidatedEd25519Cert};
pub use err::Error;
pub use key_type::{CertType, KeyType, KeystoreItemType};
pub use ssh::{SshKeyAlgorithm, SshKeyData};
pub use traits::{
    EncodableItem, InvalidCertError, ItemType, Keygen, KeygenRng, KeystoreItem, ToEncodableCert,
    ToEncodableKey,
};

// Note: we use various tor-cert types in our public API,
// so let's reexport them for convenience...
pub use tor_cert::{Ed25519Cert, EncodedEd25519Cert, KeyUnknownCert};

// Needed to export our derive_deftly macros.
#[doc(hidden)]
pub use derive_deftly;

#[doc(hidden)]
pub use macros::deps as macro_deps;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A type-erased key. Used by the tor-keymgr.
pub type ErasedKey = Box<dyn traits::ItemType>;
