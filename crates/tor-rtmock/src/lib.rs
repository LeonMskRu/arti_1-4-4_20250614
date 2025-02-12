#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(any(not(feature = "full"), miri), allow(unused))]

extern crate core;

#[macro_use]
mod util;

pub mod io;
pub mod net;
pub mod simple_time;
pub mod task;
pub mod time;

mod net_runtime;
mod runtime;
mod sleep_runtime;
mod time_core;

pub use net_runtime::MockNetRuntime;
pub use runtime::MockRuntime;
pub use sleep_runtime::MockSleepRuntime;
