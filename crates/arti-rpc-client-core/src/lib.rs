#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@

//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO RPC: Possibly add this to our big list of lints.
#![deny(unsafe_op_in_unsafe_fn)]

mod conn;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod llconn;
mod msgs;
#[macro_use]
mod util;
#[cfg(test)]
mod testing;

pub use conn::{
    BuilderError, ConnPtDescription, ConnectError, ConnectFailure, ProtoError, RpcConn,
    RpcConnBuilder, StreamError,
};
pub use msgs::{request::InvalidRequestError, response::RpcError, AnyRequestId, ObjectId};
