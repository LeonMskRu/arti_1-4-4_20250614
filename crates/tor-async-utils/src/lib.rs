#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod join_read_write;
mod prepare_send;
mod sink_close_channel;
mod sink_try_send;
mod sinkext;
mod watch;

pub mod peekable_stream;
pub mod stream_peek;

pub use join_read_write::*;

pub use prepare_send::{SinkPrepareExt, SinkPrepareSendFuture, SinkSendable};

pub use sinkext::SinkExt;

pub use sink_close_channel::SinkCloseChannel;

pub use sink_try_send::{ErasedSinkTrySendError, MpscOtherSinkTrySendError};
pub use sink_try_send::{SinkTrySend, SinkTrySendError};

pub use watch::{DropNotifyEofSignallable, DropNotifyWatchSender, PostageWatchSenderExt};

pub use oneshot_fused_workaround as oneshot;

use futures::channel::mpsc;

/// Precisely [`futures::channel::mpsc::channel`]
///
/// In `arti.git` we disallow this method, because we want to ensure
/// that all our queues participate in our memory quota system
/// (see `tor-memquota` and `tor_proto::memquota`).y
///
/// Use this method to make an `mpsc::channel` when you know that's not appropriate.
///
/// (`#[allow]` on an expression is unstable Rust, so this is needed to avoid
/// decorating whole functions with the allow.)
#[allow(clippy::disallowed_methods)] // We don't care about mq tracking in this test code
pub fn mpsc_channel_no_memquota<T>(buffer: usize) -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
    mpsc::channel(buffer)
}
