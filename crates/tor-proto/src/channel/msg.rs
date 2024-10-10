//! This contains restricted message sets namespaced by link protocol version.
//!
//! In other words, each protocl version define sets of possible messages depending on the channel
//! type as in client or relay and initiator or responder.
//!
//! This module also defines [`MessageFilter`] which can be used to filter messages based on
//! specific details of the message such as direction, command, channel type and channel stage.

use tor_cell::chancell::ChanCmd;

use crate::{channel::ChannelType, Error};

/// Subprotocol LINK version 4.
///
/// Increases circuit ID width to 4 bytes.
pub(crate) mod linkv4 {
    use tor_cell::chancell::msg::AnyChanMsg;
    use tor_cell::restricted_msg;

    use super::{MessageDetails, MessageDirection, MessageStage};
    use crate::channel::ChannelType;

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

    /// Return true iff the given channel type at the given channel negotiation stage for the given
    /// message details is allowed.
    ///
    /// In order to learn the answer, we check against the specific restricted message set if the
    /// command is known and if so, it is allowed.
    ///
    /// This is very verbose and testing every possible branch. It is more important that it is
    /// easily readable by a human as in easy to follow than to be compact. A lot can go wrong
    /// if this is confusing.
    ///
    /// XXX: Very code duplicated with the linkv5 is_allowed() function so any improvements not
    /// compromising readability is very welcome.
    pub(crate) fn is_allowed(
        chan_type: ChannelType,
        stage: &MessageStage,
        details: &MessageDetails,
    ) -> bool {
        let cmd = details.cmd;
        match chan_type {
            ChannelType::ClientInitiator => match stage {
                MessageStage::Handshake => match details.direction {
                    MessageDirection::Inbound => HandshakeRelayResponderMsg::is_known_cmd(cmd),
                    MessageDirection::Outbound => HandshakeClientInitiatorMsg::is_known_cmd(cmd),
                },
                MessageStage::Open => match details.direction {
                    MessageDirection::Inbound => OpenChanMsgR2C::is_known_cmd(cmd),
                    MessageDirection::Outbound => OpenChanMsgC2R::is_known_cmd(cmd),
                },
            },
            ChannelType::RelayInitiator => match stage {
                MessageStage::Handshake => match details.direction {
                    MessageDirection::Inbound => HandshakeRelayResponderMsg::is_known_cmd(cmd),
                    MessageDirection::Outbound => HandshakeRelayInitiatorMsg::is_known_cmd(cmd),
                },
                // Regardless of Inbound or Outbound, same restricted set for Relay <-> Relay.
                MessageStage::Open => OpenChanMsgR2R::is_known_cmd(cmd),
            },
            ChannelType::RelayResponder { authenticated } => match stage {
                // Authenticated is only learned after the handshake is done.
                MessageStage::Handshake => match details.direction {
                    MessageDirection::Inbound => HandshakeRelayInitiatorMsg::is_known_cmd(cmd),
                    MessageDirection::Outbound => HandshakeRelayResponderMsg::is_known_cmd(cmd),
                },
                MessageStage::Open => match authenticated {
                    // Unauthenticated channel means, as a Relay, we respond to a Client.
                    false => match details.direction {
                        MessageDirection::Inbound => OpenChanMsgC2R::is_known_cmd(cmd),
                        MessageDirection::Outbound => OpenChanMsgR2C::is_known_cmd(cmd),
                    },
                    // Authenticated channel means, as a Relay, we respond to a Relay. Regardless
                    // of Inbound or Outbound, same restricted set for Relay <-> Relay.
                    true => OpenChanMsgR2R::is_known_cmd(cmd),
                },
            },
        }
    }
}

/// Subprotocol LINK version 5.
///
/// Adds support for padding and negotiation.
pub(crate) mod linkv5 {
    use tor_cell::chancell::msg::AnyChanMsg;
    use tor_cell::restricted_msg;

    use super::{MessageDetails, MessageDirection, MessageStage};
    use crate::channel::ChannelType;

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

    /// Return true iff the given channel type at the given channel negotiation stage for the given
    /// message details is allowed.
    ///
    /// In order to learn the answer, we check against the specific restricted message set if the
    /// command is known and if so, it is allowed.
    ///
    /// This is very verbose and testing every possible branch. It is more important that it is
    /// easily readable by a human as in easy to follow than to be compact. A lot can go wrong
    /// if this is confusing.
    ///
    /// XXX: Very code duplicated with the linkv4 is_allowed() function so any improvements not
    /// compromising readability is very welcome.
    pub(crate) fn is_allowed(
        chan_type: ChannelType,
        stage: &MessageStage,
        details: &MessageDetails,
    ) -> bool {
        let cmd = details.cmd;
        match chan_type {
            ChannelType::ClientInitiator => match stage {
                MessageStage::Handshake => match details.direction {
                    MessageDirection::Inbound => HandshakeRelayResponderMsg::is_known_cmd(cmd),
                    MessageDirection::Outbound => HandshakeClientInitiatorMsg::is_known_cmd(cmd),
                },
                MessageStage::Open => match details.direction {
                    MessageDirection::Inbound => OpenChanMsgR2C::is_known_cmd(cmd),
                    MessageDirection::Outbound => OpenChanMsgC2R::is_known_cmd(cmd),
                },
            },
            ChannelType::RelayInitiator => match stage {
                MessageStage::Handshake => match details.direction {
                    MessageDirection::Inbound => HandshakeRelayResponderMsg::is_known_cmd(cmd),
                    MessageDirection::Outbound => HandshakeRelayInitiatorMsg::is_known_cmd(cmd),
                },
                // Regardless of Inbound or Outbound, same restricted set for Relay <-> Relay.
                MessageStage::Open => OpenChanMsgR2R::is_known_cmd(cmd),
            },
            ChannelType::RelayResponder { authenticated } => match stage {
                // Authenticated is only learned after the handshake is done.
                MessageStage::Handshake => match details.direction {
                    MessageDirection::Inbound => HandshakeRelayInitiatorMsg::is_known_cmd(cmd),
                    MessageDirection::Outbound => HandshakeRelayResponderMsg::is_known_cmd(cmd),
                },
                MessageStage::Open => match authenticated {
                    // Unauthenticated channel means, as a Relay, we respond to a Client.
                    false => match details.direction {
                        MessageDirection::Inbound => OpenChanMsgC2R::is_known_cmd(cmd),
                        MessageDirection::Outbound => OpenChanMsgR2C::is_known_cmd(cmd),
                    },
                    // Authenticated channel means, as a Relay, we respond to a Relay. Regardless
                    // of Inbound or Outbound, same restricted set for Relay <-> Relay.
                    true => OpenChanMsgR2R::is_known_cmd(cmd),
                },
            },
        }
    }
}

/// What stage a channel can be of a negotiation. This is used in order to learn which restricted
/// message set we should be looking at.
///
/// Notice that we don't have the "New" stage and this is because we only learn the link protocol
/// version once we enter the Handshake stage.
pub(crate) enum MessageStage {
    /// Handshaking as in the channel is working to become open.
    Handshake,
    /// Open as the channel is now open.
    Open,
}

impl MessageStage {
    /// Return an error using the given message for the right stage.
    ///
    /// Very useful helper that just select the right error type for the stage.
    fn to_err(&self, msg: String) -> Error {
        match self {
            Self::Handshake => Error::HandshakeProto(msg),
            Self::Open => Error::ChanProto(msg),
        }
    }
}

/// What direction the message is destined to. Quite self explantory.
///
/// This again is very important because depending on the direction, the restricted message set
/// changes.
#[derive(derive_more::Display)]
pub(crate) enum MessageDirection {
    /// A message that is being received.
    Inbound,
    /// A message that is being sent.
    Outbound,
}

/// A message filter object which is used to learn if a certain message is allowed or not on a
/// channel.
///
/// It is pinned to a link protocol version, a channel type and a channel message stage.
pub(crate) struct MessageFilter {
    /// For what link protocol version this filter applies for.
    link_version: u16,
    /// For which channel type this filter applies for.
    channel_type: ChannelType,
    /// At which stage this filter applies for.
    stage: MessageStage,
}

/// An object to wrap the details of a message and on which we have helpful constructors depending
/// on the direction we want.
pub(crate) struct MessageDetails {
    /// Channel command.
    cmd: ChanCmd,
    /// Direction of the message.
    direction: MessageDirection,
}

impl MessageDetails {
    /// Constructor of a new Inbound message details.
    pub(crate) fn new_inbound(cmd: ChanCmd) -> Self {
        Self {
            cmd,
            direction: MessageDirection::Inbound,
        }
    }
    /// Constructor of a new Outbound message details.
    pub(crate) fn new_outbound(cmd: ChanCmd) -> Self {
        Self {
            cmd,
            direction: MessageDirection::Outbound,
        }
    }
}

impl std::fmt::Display for MessageDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} cell command {}", self.direction, self.cmd)
    }
}

impl MessageFilter {
    /// Constructor
    pub(crate) fn new(link_version: u16, channel_type: ChannelType, stage: MessageStage) -> Self {
        Self {
            link_version,
            channel_type,
            stage,
        }
    }

    /// Return Ok if the message is allowed for this filter object.
    ///
    /// If not allowed, an error is returned describing why and the context around it.
    pub(crate) fn is_allowed(&self, details: &MessageDetails) -> Result<(), Error> {
        let r = match self.link_version {
            4 => linkv4::is_allowed(self.channel_type, &self.stage, details),
            5 => linkv5::is_allowed(self.channel_type, &self.stage, details),
            _ => {
                // In reality, we should never get here because it is not possible to create a
                // Handshake cell handler for an unknown version. Regardless, don't explode.
                return Err(Error::ChanProto(format!(
                    "Channel message filter link version is unknown: {}",
                    self.link_version
                )));
            }
        };
        // Return a meaningful error if command is not allowed.
        r.then_some(()).ok_or_else(|| {
            self.stage.to_err(format!(
                "Cell not allowed on link v{} channel for {details} for channel type {}",
                self.link_version, self.channel_type
            ))
        })
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
