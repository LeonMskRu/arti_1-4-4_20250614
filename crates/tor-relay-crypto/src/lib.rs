#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod certs;
pub mod pk;

// Pleasant re-export.
pub use certs::{gen_link_cert, gen_signing_cert, RelayLinkSigningKeyCert, RelaySigningKeyCert};
