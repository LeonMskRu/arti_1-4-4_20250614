#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

pub mod config;
mod proxy;

pub use config::ProxyConfig;
pub use proxy::OnionServiceReverseProxy;
