#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(
    not(all(feature = "full", feature = "experimental")),
    allow(unused, unreachable_pub)
)]

#[cfg(feature = "bench")]
pub mod bench_utils;
pub mod channel;
mod congestion;
mod crypto;
pub mod memquota;
pub mod stream;
pub(crate) mod tunnel;
mod util;

pub use util::err::{Error, ResolveError};
pub use util::skew::ClockSkew;

pub use channel::params::ChannelPaddingInstructions;
pub use congestion::params as ccparams;
pub use crypto::cell::{HopNum, HopNumDisplay};
pub use tunnel::circuit;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

use std::fmt::Debug;
use tor_memquota::{
    mq_queue::{self, ChannelSpec as _},
    HasMemoryCost,
};
use tor_rtcompat::DynTimeProvider;

#[doc(hidden)]
pub use {derive_deftly, tor_memquota};

/// Timestamp object that we update whenever we get incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
static LAST_INCOMING_TRAFFIC: util::ts::AtomicOptTimestamp = util::ts::AtomicOptTimestamp::new();

/// Called whenever we receive incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
#[inline]
pub(crate) fn note_incoming_traffic() {
    LAST_INCOMING_TRAFFIC.update();
}

/// Return the amount of time since we last received "incoming traffic".
///
/// This is a global counter, and is subject to interference from
/// other users of the `tor_proto`.  Its only permissible use is for
/// checking how recently we have been definitely able to receive
/// incoming traffic.
///
/// When enabled, this timestamp is updated whenever we receive a valid
/// cell, and whenever we complete a channel handshake.
///
/// Returns `None` if we never received "incoming traffic".
pub fn time_since_last_incoming_traffic() -> Option<std::time::Duration> {
    LAST_INCOMING_TRAFFIC.time_since_update().map(Into::into)
}

/// Make an MPSC queue, of any type, that participates in memquota, but a fake one for testing
#[cfg(any(test, feature = "testing"))] // Used by Channel::new_fake which is also feature=testing
pub(crate) fn fake_mpsc<T: HasMemoryCost + Debug + Send>(
    buffer: usize,
) -> (
    mq_queue::Sender<T, mq_queue::MpscSpec>,
    mq_queue::Receiver<T, mq_queue::MpscSpec>,
) {
    mq_queue::MpscSpec::new(buffer)
        .new_mq(
            // The fake Account doesn't care about the data ages, so this will do.
            //
            // Thiw would be wrong to use generally in tests, where we might want to mock time,
            // since we end up, here with totally *different* mocked time.
            // But it's OK here, and saves passing a runtime parameter into this function.
            DynTimeProvider::new(tor_rtmock::MockRuntime::default()),
            &tor_memquota::Account::new_noop(),
        )
        .expect("create fake mpsc")
}
