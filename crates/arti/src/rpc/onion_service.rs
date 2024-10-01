use super::session::ArtiRpcSession;
use crate::onion_proxy::Proxy;
use base64ct::Encoding;
use std::sync::Arc;
use tor_error::{ErrorKind, HasKind};
use tor_hsservice::{HsId, OnionCaaError, OnionCsrError};
use tor_rpcbase::{self as rpc, ObjectId};

#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_get_onion_service"))]
struct GetOnionService {
    domain: String,
}

impl rpc::RpcMethod for GetOnionService {
    type Output = OnionServiceInfo;
    type Update = rpc::NoUpdates;
}

#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceInfo {
    service: ObjectId,
}

#[derive(Clone, Debug, thiserror::Error)]
enum GetOnionServiceError {
    #[error("Arti appears to be shutting down")]
    Shutdown,
    #[error("Invalid onion address")]
    BadOnionAddress(#[from] tor_hscrypto::pk::HsIdParseError),
    #[error("Onion service not found")]
    NotFound,
}

impl HasKind for GetOnionServiceError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Shutdown => ErrorKind::ArtiShuttingDown,
            Self::BadOnionAddress(_) => ErrorKind::OnionServiceAddressInvalid,
            Self::NotFound => ErrorKind::OnionServiceNotFound,
        }
    }
}

#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_onion_service_name"))]
struct OnionServiceName {}

impl rpc::RpcMethod for OnionServiceName {
    type Output = OnionServiceNameResponse;
    type Update = rpc::NoUpdates;
}

#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceNameResponse {
    name: String,
}

#[derive(Clone, Debug, thiserror::Error)]
enum OnionServiceNameError {
    #[error("The key for the onion service couldn't be found")]
    KeyNotFound,
}

impl HasKind for OnionServiceNameError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::KeyNotFound => ErrorKind::Internal,
        }
    }
}

#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_onion_service_csr"))]
struct OnionServiceCsr {
    ca_nonce: String,
}

impl rpc::RpcMethod for OnionServiceCsr {
    type Output = OnionServiceCsrResponse;
    type Update = rpc::NoUpdates;
}

#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceCsrResponse {
    csr: String,
}

#[derive(Clone, Debug, thiserror::Error)]
enum OnionServiceCsrError {
    #[error("The Base64 encoding of the CA nonce is invalid")]
    InvalidBase64,
    #[error("The signing key for the onion service couldn't be found")]
    KeyNotFound,
    #[error("The CA nonce is too long")]
    CANonceTooLong,
}

impl HasKind for OnionServiceCsrError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidBase64 => ErrorKind::BadApiUsage,
            Self::KeyNotFound => ErrorKind::Internal,
            Self::CANonceTooLong => ErrorKind::BadApiUsage,
        }
    }
}

#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_onion_service_caa"))]
struct OnionServiceCaa {
    expiry: u64,
}

impl rpc::RpcMethod for OnionServiceCaa {
    type Output = OnionServiceCaaResponse;
    type Update = rpc::NoUpdates;
}

#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceCaaResponse {
    caa: String,
    expiry: u64,
    signature: String,
}

#[derive(Clone, Debug, thiserror::Error)]
enum OnionServiceCaaError {
    #[error("The signing key for the onion service couldn't be found")]
    KeyNotFound,
    #[error("The system clock time makes no sense")]
    InvalidSystemTime,
}

impl HasKind for OnionServiceCaaError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::KeyNotFound => ErrorKind::Internal,
            Self::InvalidSystemTime => ErrorKind::Internal,
        }
    }
}

async fn rpc_session_get_onion_service(
    session: Arc<ArtiRpcSession>,
    method: Box<GetOnionService>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceInfo, GetOnionServiceError> {
    let rhs = method
        .domain
        .rmatch_indices('.')
        .nth(1)
        .map(|(i, _)| i + 1)
        .unwrap_or(0);
    let rhs = &method.domain[rhs..];
    let hsid: HsId = rhs.parse()?;

    let onion_services = session
        .arti_state
        .get_onion_services()
        .await
        .map_err(|_| GetOnionServiceError::Shutdown)?;

    let onion_service = match onion_services.get_by_hsid(&hsid) {
        Some(s) => s,
        None => return Err(GetOnionServiceError::NotFound),
    };

    Ok(OnionServiceInfo {
        service: ctx.register_owned(Arc::new(onion_service)),
    })
}
rpc::static_rpc_invoke_fn! {rpc_session_get_onion_service;}

async fn rpc_onion_service_name(
    onion_service: Arc<Proxy>,
    _method: Box<OnionServiceName>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceNameResponse, OnionServiceNameError> {
    let name = onion_service
        .svc
        .onion_name()
        .ok_or(OnionServiceNameError::KeyNotFound)?;

    Ok(OnionServiceNameResponse {
        name: name.to_string(),
    })
}
rpc::static_rpc_invoke_fn! {rpc_onion_service_name;}

async fn rpc_onion_service_csr(
    onion_service: Arc<Proxy>,
    method: Box<OnionServiceCsr>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceCsrResponse, OnionServiceCsrError> {
    let ca_nonce = base64ct::Base64::decode_vec(&method.ca_nonce)
        .map_err(|_| OnionServiceCsrError::InvalidBase64)?;

    let csr = onion_service
        .svc
        .onion_csr(&ca_nonce)
        .map_err(|e| match e {
            OnionCsrError::CANonceTooLong => OnionServiceCsrError::CANonceTooLong,
            OnionCsrError::KeyNotFound => OnionServiceCsrError::KeyNotFound,
        })?;

    Ok(OnionServiceCsrResponse {
        csr: base64ct::Base64::encode_string(&csr),
    })
}
rpc::static_rpc_invoke_fn! {rpc_onion_service_csr;}

async fn rpc_onion_service_caa(
    onion_service: Arc<Proxy>,
    method: Box<OnionServiceCaa>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceCaaResponse, OnionServiceCaaError> {
    let caa = onion_service
        .svc
        .onion_caa(method.expiry)
        .map_err(|e| match e {
            OnionCaaError::KeyNotFound => OnionServiceCaaError::KeyNotFound,
            OnionCaaError::InvalidSystemTime => OnionServiceCaaError::InvalidSystemTime,
        })?;

    Ok(OnionServiceCaaResponse {
        caa: caa.caa,
        expiry: caa.expiry,
        signature: base64ct::Base64::encode_string(&caa.signature),
    })
}
rpc::static_rpc_invoke_fn! {rpc_onion_service_caa;}
