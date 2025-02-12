#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

mod connect;
mod err;
mod isol_map;
mod keys;
mod pow;
mod proto_oneshot;
mod relay_info;
mod state;

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use futures::stream::BoxStream;
use futures::task::SpawnExt as _;
use futures::StreamExt as _;

use educe::Educe;
use tracing::debug;

use tor_circmgr::hspool::HsCircPool;
use tor_circmgr::isolation::StreamIsolation;
use tor_error::{internal, Bug};
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDir;
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

pub use err::FailedAttemptError;
pub use err::{ConnError, DescriptorError, DescriptorErrorDetail, StartupError};
pub use keys::{HsClientDescEncKeypairSpecifier, HsClientSecretKeys, HsClientSecretKeysBuilder};
pub use relay_info::InvalidTarget;
pub use state::HsClientConnectorConfig;

use err::{rend_pt_identity_for_error, IntroPtIndex, RendPtIdentityForError};
use state::{Config, MockableConnectorData, Services};

/// An object that negotiates connections with onion services
///
/// This can be used by multiple requests on behalf of different clients,
/// with potentially different HS service discovery keys (`KS_hsc_*`)
/// and potentially different circuit isolation.
///
/// The principal entrypoint is
/// [`get_or_launch_connection()`](HsClientConnector::get_or_launch_connection).
///
/// This object is handle-like: it is fairly cheap to clone,
///  and contains `Arc`s internally.
#[derive(Educe)]
#[educe(Clone)]
pub struct HsClientConnector<R: Runtime, D: state::MockableConnectorData = connect::Data> {
    /// The runtime
    runtime: R,
    /// A [`HsCircPool`] that we use to build circuits to HsDirs, introduction
    /// points, and rendezvous points.
    circpool: Arc<HsCircPool<R>>,
    /// Information we are remembering about different onion services.
    services: Arc<Mutex<state::Services<D>>>,
    /// For mocking in tests of `state.rs`
    mock_for_state: D::MockGlobalState,
}

impl<R: Runtime> HsClientConnector<R, connect::Data> {
    /// Create a new `HsClientConnector`
    ///
    /// `housekeeping_prompt` should yield "occasionally",
    /// perhaps every few hours or maybe daily.
    ///
    /// In Arti we arrange for this to happen when we have a new consensus.
    ///
    /// Housekeeping events shouldn't arrive while we're dormant,
    /// since the housekeeping might involve processing that ought to be deferred.
    // This ^ is why we don't have a separate "launch background tasks" method.
    // It is fine for this background task to be launched pre-bootstrap, since it willp
    // do nothing until it gets events.
    pub fn new(
        runtime: R,
        circpool: Arc<HsCircPool<R>>,
        config: &impl HsClientConnectorConfig,
        housekeeping_prompt: BoxStream<'static, ()>,
    ) -> Result<Self, StartupError> {
        let config = Config {
            retry: config.as_ref().clone(),
        };
        let connector = HsClientConnector {
            runtime,
            circpool,
            services: Arc::new(Mutex::new(Services::new(config))),
            mock_for_state: (),
        };
        connector.spawn_housekeeping_task(housekeeping_prompt)?;
        Ok(connector)
    }

    /// Connect to a hidden service
    ///
    /// On success, this function will return an open
    /// rendezvous circuit with an authenticated connection to the onion service
    /// whose identity is `hs_id`.  If such a circuit already exists, and its isolation
    /// is compatible with `isolation`, that circuit may be returned; otherwise,
    /// a new circuit will be created.
    ///
    /// Once a circuit is returned, the caller can use it to open new streams to the
    /// onion service. To do so, call [`ClientCirc::begin_stream`] on it.
    ///
    /// Each HS connection request must provide the appropriate
    /// service discovery keys to use -
    /// or [`default`](HsClientSecretKeys::default)
    /// if the hidden service is not running in restricted discovery mode.
    //
    // This returns an explicit `impl Future` so that we can write the `Send` bound.
    // Without this, it is possible for `Services::get_or_launch_connection`
    // to not return a `Send` future.
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1034#note_2881718
    pub fn get_or_launch_circuit<'r>(
        &'r self,
        netdir: &'r Arc<NetDir>,
        hs_id: HsId,
        secret_keys: HsClientSecretKeys,
        isolation: StreamIsolation,
    ) -> impl Future<Output = Result<Arc<ClientCirc>, ConnError>> + Send + Sync + 'r {
        // As in tor-circmgr,  we take `StreamIsolation`, to ensure that callers in
        // arti-client pass us the final overall isolation,
        // including the per-TorClient isolation.
        // But internally we need a Box<dyn Isolation> since we need .join().
        let isolation = Box::new(isolation);
        Services::get_or_launch_connection(self, netdir, hs_id, isolation, secret_keys)
    }

    /// A deprecated alias for `get_or_launch_circuit`.
    ///
    /// We renamed it to be
    /// more clear about what exactly it is launching.
    #[deprecated(since = "0.5.1", note = "Use get_or_launch_circuit instead.")]
    pub fn get_or_launch_connection<'r>(
        &'r self,
        netdir: &'r Arc<NetDir>,
        hs_id: HsId,
        secret_keys: HsClientSecretKeys,
        isolation: StreamIsolation,
    ) -> impl Future<Output = Result<Arc<ClientCirc>, ConnError>> + Send + Sync + 'r {
        self.get_or_launch_circuit(netdir, hs_id, secret_keys, isolation)
    }
}

impl<R: Runtime, D: MockableConnectorData> HsClientConnector<R, D> {
    /// Lock the `Services` table and return the guard
    ///
    /// Convenience method
    fn services(&self) -> Result<MutexGuard<Services<D>>, Bug> {
        self.services
            .lock()
            .map_err(|_| internal!("HS connector poisoned"))
    }

    /// Spawn a task which watches `prompt` and calls [`Services::run_housekeeping`]
    fn spawn_housekeeping_task(
        &self,
        mut prompt: BoxStream<'static, ()>,
    ) -> Result<(), StartupError> {
        self.runtime
            .spawn({
                let connector = self.clone();
                let runtime = self.runtime.clone();
                async move {
                    while let Some(()) = prompt.next().await {
                        let Ok(mut services) = connector.services() else {
                            break;
                        };

                        // (Currently) this is "expire old data".
                        services.run_housekeeping(runtime.now());
                    }
                    debug!("HS connector housekeeping task exiting (EOF on prompt stream)");
                }
            })
            .map_err(|cause| StartupError::Spawn {
                spawning: "housekeeping task",
                cause: cause.into(),
            })
    }
}
