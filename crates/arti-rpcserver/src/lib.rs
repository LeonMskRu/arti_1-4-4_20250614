#![doc = include_str!("../README.md")]

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

mod cancel;
mod codecs;
mod connection;
mod err;
mod globalid;
mod mgr;
mod msgs;
mod objmap;
mod session;
mod stream;

pub use connection::{auth::RpcAuthentication, Connection, ConnectionError};
pub use mgr::RpcMgr;
pub use session::RpcSession;

/// Return a list of RPC methods that will be needed to use `arti-rpcserver` with the given runtime.
pub fn rpc_methods<R: tor_rtcompat::Runtime>() -> Vec<tor_rpcbase::dispatch::InvokerEnt> {
    tor_rpcbase::invoker_ent_list![
        crate::stream::new_oneshot_client_on_client::<R>, //
    ]
}
