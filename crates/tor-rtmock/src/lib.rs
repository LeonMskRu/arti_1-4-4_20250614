#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(any(not(feature = "full"), miri), allow(unused))]

extern crate core;

#[macro_use]
mod util;

pub mod io;
pub mod net;
pub mod simple_time;
pub mod task;

// TODO #1885, see MockSleepProvider's cfg_attr deprecated
//
// We must use a blanket allow because otherwise every impl we write
// on the deprecated types would need a separate allow!
//
// This is here rather than in time.rs because cfg'd inner attributes don't work properly
#[cfg_attr(not(test), allow(deprecated))]
pub mod time;

mod net_runtime;
mod runtime;
#[cfg_attr(not(test), allow(deprecated))] // TODO #1885, see comment above on mod time
mod sleep_runtime;
mod time_core;

pub use net_runtime::MockNetRuntime;
pub use runtime::MockRuntime;
#[allow(deprecated)]
pub use sleep_runtime::MockSleepRuntime;
