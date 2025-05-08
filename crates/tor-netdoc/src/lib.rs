#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

#[cfg(feature = "hs-service")]
pub(crate) mod build;
#[macro_use]
pub(crate) mod parse;
pub mod doc;
mod err;
pub mod types;
mod util;

// Use `#[doc(hidden)]` rather than pub(crate), because otherwise the doctest
// doesn't work.
#[doc(hidden)]
pub use util::batching_split_before;

pub use err::{BuildError, Error, NetdocErrorKind, Pos};

#[cfg(feature = "hs-service")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-service")))]
pub use build::NetdocBuilder;

/// Alias for the Result type returned by most objects in this module.
pub type Result<T> = std::result::Result<T, Error>;

/// Alias for the Result type returned by document-builder functions in this
/// module.
pub type BuildResult<T> = std::result::Result<T, BuildError>;

/// Indicates whether we should parse an annotated list of objects or a
/// non-annotated list.
#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum AllowAnnotations {
    /// Parsing a document where items might be annotated.
    ///
    /// Annotations are a list of zero or more items with keywords
    /// beginning with @ that precede the items that are actually part
    /// of the document.
    AnnotationsAllowed,
    /// Parsing a document where annotations are not allowed.
    AnnotationsNotAllowed,
}

/// Return a list of the protocols [supported](tor_protover::doc_supported)
/// by this crate.
pub fn supported_protocols() -> tor_protover::Protocols {
    use tor_protover::named::*;
    // WARNING: REMOVING ELEMENTS FROM THIS LIST CAN BE DANGEROUS!
    // SEE [`tor_protover::doc_changing`]
    [
        DESC_CROSSSIGN,
        DESC_NO_TAP,
        DESC_FAMILY_IDS,
        MICRODESC_ED25519_KEY,
        MICRODESC_NO_TAP,
        CONS_ED25519_MDS,
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[test]
    fn protocols() {
        let pr = supported_protocols();
        let expected = "Cons=2 Desc=2-4 Microdesc=2-3".parse().unwrap();
        assert_eq!(pr, expected);
    }
}
