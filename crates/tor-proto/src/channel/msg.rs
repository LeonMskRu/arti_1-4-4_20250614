//! This contains restricted message sets namespaced by link protocol version.
//!
//! In other words, each protocl version define sets of possible messages depending on the channel
//! type as in client or relay and initiator or responder.
//!
//! This module also defines [`MessageFilter`] which can be used to filter messages based on
//! specific details of the message such as direction, command, channel type and channel stage.

/// Subprotocol LINK version 4.
///
/// Increases circuit ID width to 4 bytes.
pub(crate) mod linkv4 {
    use tor_cell::chancell::msg::AnyChanMsg;
    use tor_cell::restricted_msg;

    restricted_msg! {
        /// Handshake messages for a Relay as the Initiator.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeRelayInitiatorMsg: ChanMsg {
            Authenticate,
            Certs,
            Netinfo
        }
    }

    restricted_msg! {
        /// Handshake messages for a Relay as the Responder.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeRelayResponderMsg: ChanMsg {
            AuthChallenge,
            Certs,
            Netinfo
        }
    }

    restricted_msg! {
        /// Handshake messages for Client to Relay which is always the Initiator.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeClientInitiatorMsg: ChanMsg {
            Netinfo
        }
    }

    /// A channel message that we allow to be sent from a Client to a Relay on
    /// an open channel.
    #[allow(unused)] // TODO: Remove once used.
    pub(crate) type OpenChanMsgC2R = AnyChanMsg;

    restricted_msg! {
        /// A channel message that we allow to be sent from a Relay to a Client on
        /// an open channel.
        ///
        /// (An Open channel here is one on which we have received a NETINFO cell.)
        ///
        /// Note that an unexpected message type will _not_ be ignored: instead, it
        /// will cause the channel to shut down.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgR2C : ChanMsg {
            // Not Create*, since we are not a relay.
            // Not Created, since we never send CREATE.
            CreatedFast,
            Created2,
            Relay,
            // Not RelayEarly, since we are a client.
            Destroy,
            // Not PaddingNegotiate, since we are not a relay.
            // Not Versions, Certs, AuthChallenge, Authenticate: they are for handshakes.
            // Not Authorize: it is reserved, but unused.
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent (bidirectionally) from a Relay to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgR2R : ChanMsg {
            // Not Vpadding, only sent during handshake.
            // Not Create/Created, it is obsolete (TAP).
            // Not Create2/Created2, only client sends those.
            Relay,
            RelayEarly,
            Destroy,
            // Not PaddingNegotiate, only client sends this.
            // Not Versions, Certs, AuthChallenge, Authenticate, Netinfo: they are for handshakes.
            // Not Authorize: it is reserved, but unused.
        }
    }
}

/// Subprotocol LINK version 5.
///
/// Adds support for padding and negotiation.
pub(crate) mod linkv5 {
    use tor_cell::chancell::msg::AnyChanMsg;
    use tor_cell::restricted_msg;

    restricted_msg! {
        /// Handshake messages for a Relay as the Initiator.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeRelayInitiatorMsg: ChanMsg {
            Authenticate,
            Certs,
            Netinfo,
            Vpadding,
        }
    }

    restricted_msg! {
        /// Handshake messages for a Relay as the Responder.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeRelayResponderMsg: ChanMsg {
            AuthChallenge,
            Certs,
            Netinfo,
            Vpadding,
        }
    }

    restricted_msg! {
        /// Handshake messages for Client to Relay which is always the Initiator.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeClientInitiatorMsg: ChanMsg {
            Netinfo,
            Vpadding,
        }
    }

    /// A channel message that we allow to be sent from a Client to a Relay on
    /// an open channel.
    #[allow(unused)] // TODO: Remove once used.
    pub(crate) type OpenChanMsgC2R = AnyChanMsg;

    restricted_msg! {
        /// A channel message that we allow to be sent from a Relay to a Client on
        /// an open channel.
        ///
        /// (An Open channel here is one on which we have received a NETINFO cell.)
        ///
        /// Note that an unexpected message type will _not_ be ignored: instead, it
        /// will cause the channel to shut down.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgR2C : ChanMsg {
            Padding,
            // Not Create*, since we are not a relay.
            // Not Created, since we never send CREATE.
            CreatedFast,
            Created2,
            Relay,
            // Not RelayEarly, since we are a client.
            Destroy,
            // Not PaddingNegotiate, since we are not a relay.
            // Not Versions, Certs, AuthChallenge, Authenticate: they are for handshakes.
            // Not Authorize: it is reserved, but unused.
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent (bidirectionally) from a Relay to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgR2R : ChanMsg {
            Padding,
            // Not Vpadding, only sent during handshake.
            // Not Create/Created, it is obsolete (TAP).
            // Not Create2/Created2, only client sends those.
            Relay,
            RelayEarly,
            Destroy,
            // Not PaddingNegotiate, only client sends this.
            // Not Versions, Certs, AuthChallenge, Authenticate, Netinfo: they are for handshakes.
            // Not Authorize: it is reserved, but unused.
        }
    }
}

/// Helper function: Return true iff the given link protocol version value is known to us.
pub(crate) fn is_link_version_known(v: u16) -> bool {
    v == 4 || v == 5
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known_link_version() {
        // Unknown low link version.
        assert!(!is_link_version_known(1));
        // Known link versions.
        assert!(is_link_version_known(4));
        assert!(is_link_version_known(5));
        // Unknown above link versions.
        assert!(!is_link_version_known(6));
        assert!(!is_link_version_known(42));
    }
}
