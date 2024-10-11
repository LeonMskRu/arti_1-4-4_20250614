//! Implement RPC functions relating to onion services.
//! Currently only functions related to ACME are implemented.

use super::session::ArtiRpcSession;
use crate::onion_proxy::Proxy;
use base64ct::Encoding;
use std::sync::Arc;
use tor_error::{ErrorKind, HasKind};
use tor_hsservice::{HsId, OnionCaaError, OnionCsrError};
use tor_rpcbase::{self as rpc, SingleIdResponse};

/// Get an onion service by its domain
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_get_onion_service"))]
struct GetOnionService {
    /// Hostname ending in .onion, can include subdomains
    domain: String,
}

impl rpc::RpcMethod for GetOnionService {
    type Output = SingleIdResponse;
    type Update = rpc::NoUpdates;
}

/// An error occurred getting the onion service object
#[derive(Clone, Debug, thiserror::Error)]
enum GetOnionServiceError {
    /// The Sender was dropped without setting any onion services;
    /// likely, Arti is shutting down.
    #[error("Arti appears to be shutting down")]
    Shutdown,
    /// The onion address couldn't be parsed
    #[error("Invalid onion address")]
    BadOnionAddress(#[from] tor_hscrypto::pk::HsIdParseError),
    /// There isn't a running onion service with that name
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

/// Get the second level domain of the onion service
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_get_onion_service_name"))]
struct GetOnionServiceName {}

impl rpc::RpcMethod for GetOnionServiceName {
    type Output = OnionServiceName;
    type Update = rpc::NoUpdates;
}

/// The SLD of an onion service
#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceName {
    /// The SLD of the onion service, e.g. <x>.onion
    domain: String,
}

/// An error occurred getting the domain name
#[derive(Clone, Debug, thiserror::Error)]
enum OnionServiceNameError {
    /// Arti doesn't have the required signing keys
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

/// Create a CA/BF Certificate Signing Request for this onion service
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_generate_onion_service_csr"))]
struct GenerateOnionServiceCsr {
    /// The CA/BF CA Signing Nonce provided by the CA, Base64 encoded
    ca_nonce: String,
}

impl rpc::RpcMethod for GenerateOnionServiceCsr {
    type Output = OnionServiceCsr;
    type Update = rpc::NoUpdates;
}

/// A signed CSR for the onion service - using the provided CA nonce
#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceCsr {
    /// A base64 encoded DER encoded PKCS#10 certificate signing request
    csr: String,
}

/// An error occurred generating the CSR
#[derive(Debug, Clone, thiserror::Error)]
enum OnionServiceCsrError {
    /// Base64 decode failed
    #[error("The Base64 encoding of the CA nonce is invalid")]
    InvalidBase64,
    /// Arti doesn't have the required signing keys
    #[error("The signing key for the onion service couldn't be found")]
    KeyNotFound,
    /// CA nonce input is longer too long
    #[error("The CA nonce is too long")]
    CANonceTooLong,
    /// CA nonce input is longer too short
    #[error("The CA nonce is too short")]
    CANonceTooShort,
    /// Something else happened
    #[error(transparent)]
    Other(#[from] OnionCsrError),
}

impl HasKind for OnionServiceCsrError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidBase64 => ErrorKind::BadApiUsage,
            Self::KeyNotFound => ErrorKind::Internal,
            Self::CANonceTooLong => ErrorKind::BadApiUsage,
            Self::CANonceTooShort => ErrorKind::BadApiUsage,
            Self::Other(_) => ErrorKind::Internal,
        }
    }
}

/// Gets the CAA record set for the onion service, signed for presentation in an ACME exchange
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_acme_get_onion_service_caa"))]
struct GetOnionServiceCaa {
    /// How long should the CAA signature be valid for, in seconds
    expiry: u64,
}

impl rpc::RpcMethod for GetOnionServiceCaa {
    type Output = OnionServiceCaa;
    type Update = rpc::NoUpdates;
}

/// A signed CAA record set for an onion service
#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct OnionServiceCaa {
    /// The encoded CAA record set
    caa: String,
    /// Unix timestamp of when this record set will expire
    expiry: u64,
    /// A base64 encoded signature over the CAA record set
    signature: String,
}

/// An error occurred generating the CAA record set
#[derive(Clone, Debug, thiserror::Error)]
enum OnionServiceCaaError {
    /// Arti doesn't have the required signing keys
    #[error("The signing key for the onion service couldn't be found")]
    KeyNotFound,
    /// The system clock is bogus
    #[error("The system clock time makes no sense")]
    InvalidSystemTime,
    /// The CAA config is invalid in a way that means it can't be encoded to a zone file format
    #[error("The CAA record set couldn't be built")]
    EncodeError(String),
    /// Something else happened
    #[error(transparent)]
    Other(#[from] OnionCaaError),
}

impl HasKind for OnionServiceCaaError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::KeyNotFound => ErrorKind::Internal,
            Self::InvalidSystemTime => ErrorKind::Internal,
            Self::EncodeError(_) => ErrorKind::Internal,
            Self::Other(_) => ErrorKind::Internal,
        }
    }
}

/// Implementation for GetOnionService on an ArtiRpcSession.
async fn rpc_session_get_onion_service(
    session: Arc<ArtiRpcSession>,
    method: Box<GetOnionService>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<SingleIdResponse, GetOnionServiceError> {
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

    let onion_service: Arc<Proxy> = match onion_services.get_by_hsid(&hsid) {
        Some(s) => s,
        None => return Err(GetOnionServiceError::NotFound),
    };

    Ok(SingleIdResponse::from(ctx.register_weak(onion_service)))
}
rpc::static_rpc_invoke_fn! {rpc_session_get_onion_service;}

/// Implementation for OnionServiceName on an ArtiRpcSession.
async fn rpc_onion_service_name(
    onion_service: Arc<Proxy>,
    _method: Box<GetOnionServiceName>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceName, OnionServiceNameError> {
    let name = onion_service
        .svc
        .onion_name()
        .ok_or(OnionServiceNameError::KeyNotFound)?;

    Ok(OnionServiceName {
        domain: name.to_string(),
    })
}
rpc::static_rpc_invoke_fn! {rpc_onion_service_name;}

/// Implementation for OnionServiceCsr on an ArtiRpcSession.
async fn rpc_onion_service_csr(
    onion_service: Arc<Proxy>,
    method: Box<GenerateOnionServiceCsr>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceCsr, OnionServiceCsrError> {
    let ca_nonce = base64ct::Base64::decode_vec(&method.ca_nonce)
        .map_err(|_| OnionServiceCsrError::InvalidBase64)?;

    let csr = onion_service
        .svc
        .generate_onion_csr(&ca_nonce)
        .map_err(|e| match e {
            OnionCsrError::CANonceTooLong => OnionServiceCsrError::CANonceTooLong,
            OnionCsrError::CANonceTooShort => OnionServiceCsrError::CANonceTooShort,
            OnionCsrError::KeyNotFound => OnionServiceCsrError::KeyNotFound,
            o => o.into(),
        })?;

    Ok(OnionServiceCsr {
        csr: base64ct::Base64::encode_string(&csr),
    })
}
rpc::static_rpc_invoke_fn! {rpc_onion_service_csr;}

/// Implementation for OnionServiceCaa on an ArtiRpcSession.
async fn rpc_onion_service_caa(
    onion_service: Arc<Proxy>,
    method: Box<GetOnionServiceCaa>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<OnionServiceCaa, OnionServiceCaaError> {
    let caa = onion_service
        .svc
        .get_onion_caa(method.expiry)
        .map_err(|e| match e {
            OnionCaaError::KeyNotFound => OnionServiceCaaError::KeyNotFound,
            OnionCaaError::InvalidSystemTime => OnionServiceCaaError::InvalidSystemTime,
            OnionCaaError::EncodeError(e) => OnionServiceCaaError::EncodeError(e.to_string()),
            o => o.into(),
        })?;

    Ok(OnionServiceCaa {
        caa: caa.caa().to_owned(),
        expiry: caa.expiry(),
        signature: base64ct::Base64::encode_string(caa.signature()),
    })
}
rpc::static_rpc_invoke_fn! {rpc_onion_service_caa;}
