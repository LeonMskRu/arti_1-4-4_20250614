#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

pub mod certs;
pub mod pk;

// Pleasant re-export.
pub use certs::{gen_link_cert, gen_signing_cert, RelayLinkSigningKeyCert, RelaySigningKeyCert};
