#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

pub mod chancell;
mod err;
pub mod relaycell;
pub mod restrict;
mod slicewriter;

pub use err::Error;

/// An error type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
