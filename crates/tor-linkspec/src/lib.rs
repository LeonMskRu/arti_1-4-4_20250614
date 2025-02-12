#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "decode")]
pub mod decode;
#[macro_use]
mod ids;
mod ls;
mod owned;
mod traits;
mod transport;
#[cfg(feature = "verbatim")]
pub mod verbatim;

pub use ids::{
    by_id::{ByRelayIds, ByRelayIdsError, ListByRelayIds, ListByRelayIdsError, ListByRelayIdsIter},
    set::RelayIdSet,
    RelayId, RelayIdError, RelayIdRef, RelayIdType, RelayIdTypeIter,
};
pub use ls::{EncodedLinkSpec, LinkSpec, LinkSpecType};
pub use owned::{
    IntoOwnedChanTarget, LoggedChanTarget, OwnedChanTarget, OwnedChanTargetBuilder,
    OwnedCircTarget, OwnedCircTargetBuilder, RelayIds, RelayIdsBuilder,
};
pub use traits::{
    ChanTarget, CircTarget, DirectChanMethodsHelper, HasAddrs, HasChanMethod, HasRelayIds,
    HasRelayIdsLegacy,
};
pub use transport::{BridgeAddr, BridgeAddrError, ChannelMethod, TransportId, TransportIdError};
pub use transport::{
    PtTarget, PtTargetAddr, PtTargetInvalidSetting, PtTargetSettings, PtTransportName,
};
