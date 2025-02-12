#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

mod config;
mod restriction;
mod selector;
mod target_port;
mod usage;

pub use config::RelaySelectionConfig;
pub use restriction::{RelayExclusion, RelayRestriction};
pub use selector::{RelaySelector, SelectionInfo};
pub use target_port::TargetPort;
pub use usage::RelayUsage;

/// A property that can be provided by relays.
///
/// The predicates that implement this trait are typically lower level ones that
/// represent only some of the properties that need to be checked before a relay
/// can be used.  Code should generally use RelaySelector instead.
pub trait LowLevelRelayPredicate {
    /// Return true if `relay` provides this predicate.
    fn low_level_predicate_permits_relay(&self, relay: &tor_netdir::Relay<'_>) -> bool;
}

/// Helper module for our tests.
#[cfg(test)]
pub(crate) mod testing {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::{LowLevelRelayPredicate, RelaySelectionConfig};
    use once_cell::sync::Lazy;
    use std::collections::HashSet;
    use tor_netdir::{NetDir, Relay, SubnetConfig};
    use tor_netdoc::doc::netstatus::RelayFlags;

    /// Use a predicate to divide a NetDir into the relays that do and do not
    /// conform (respectively).
    ///
    /// # Panics
    ///
    /// Panics if either the "yes" list or the "no" list is empty, to ensure
    /// that all of our tests are really testing something.
    pub(crate) fn split_netdir<'a, P: LowLevelRelayPredicate>(
        netdir: &'a NetDir,
        pred: &P,
    ) -> (Vec<Relay<'a>>, Vec<Relay<'a>>) {
        let (yes, no): (Vec<_>, Vec<_>) = netdir
            .relays()
            .partition(|r| pred.low_level_predicate_permits_relay(r));
        assert!(!yes.is_empty());
        assert!(!no.is_empty());
        (yes, no)
    }

    /// Return a basic configuration.
    pub(crate) fn cfg() -> RelaySelectionConfig<'static> {
        static STABLE_PORTS: Lazy<HashSet<u16>> = Lazy::new(|| [22].into_iter().collect());
        RelaySelectionConfig {
            long_lived_ports: &STABLE_PORTS,
            subnet_config: SubnetConfig::default(),
        }
    }

    // Construct a test network to exercise the various cases in this crate.
    pub(crate) fn testnet() -> NetDir {
        tor_netdir::testnet::construct_custom_netdir(|idx, node, _| {
            if idx % 7 == 0 {
                node.rs.clear_flags(RelayFlags::FAST);
            }
            if idx % 5 == 0 {
                node.rs.clear_flags(RelayFlags::STABLE);
            };
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap()
    }
}
