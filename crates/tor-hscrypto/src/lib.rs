#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
#![allow(dead_code, unused_variables)]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod macros;
#[cfg(feature = "ope")]
pub mod ope;
pub mod ops;
pub mod pk;
pub mod pow;
pub mod time;

use macros::define_bytes;

#[cfg(feature = "memquota-memcost")]
use {derive_deftly::Deftly, tor_memquota::derive_deftly_template_HasMemoryCost};

define_bytes! {
/// A value to identify an onion service during a given period. (`N_hs_subcred`)
///
/// This is computed from the onion service's public ID and the blinded ID for
/// the current time period.
///
/// Given this piece of information, the original public ID and blinded ID cannot
/// be re-derived.
#[derive(Copy, Clone, Debug)]
pub struct Subcredential([u8; 32]);
}

/// Counts which revision of an onion service descriptor is which, within a
/// given time period.
///
/// There can be gaps in this numbering. A descriptor with a higher-valued
/// revision counter supersedes one with a lower revision counter.
#[derive(
    Copy,
    Clone,
    Debug,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
)]
pub struct RevisionCounter(u64);

/// Default number of introduction points a service should establish
///
/// Default value for `[NUM_INTRO_POINT]`, rend-spec-v3 2.5.4.
//
// TODO arguably these aren't "crypto" so should be in some currently non-existent tor-hscommon
pub const NUM_INTRO_POINT_DEF: usize = 3;

/// Maximum number of introduction points a service should establish and we should tolerate
///
/// Maximum value for `[NUM_INTRO_POINT]`, rend-spec-v3 2.5.4.
pub const NUM_INTRO_POINT_MAX: usize = 20;

/// Length of a `RENDEZVOUS` cookie
const REND_COOKIE_LEN: usize = 20;

define_bytes! {
/// An opaque value `RENDEZVOUS_COOKIE` used at a rendezvous point to match clients and services.
///
/// See rend-spec-v3 s4.1.
///
/// The client includes this value to the rendezvous point in its
/// `ESTABLISH_RENDEZVOUS` message; the service later provides the same value in its
/// `RENDEZVOUS1` message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "memquota-memcost",
    derive(Deftly),
    derive_deftly(HasMemoryCost),
)]
pub struct RendCookie([u8; REND_COOKIE_LEN]);
}

impl rand::distr::Distribution<RendCookie> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> RendCookie {
        RendCookie(rng.random::<[u8; REND_COOKIE_LEN]>().into())
    }
}
