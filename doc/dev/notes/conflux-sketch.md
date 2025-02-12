# Conflux design sketch

Date: Jan 29th, 2025

Document sketching out the design for Conflux (traffic splitting), [proposal
329](https://spec.torproject.org/proposals/329), in arti on the client side.

Client and relay won't share the same circuit reactor but there is a good
chance that this design can be shared between the two due to the similar
behavior on both the client and relay exit side.

## 10,000 feet from above

Conflux is the ability to split traffic between multiple circuits which
increases performance, resilience and stability of a stream of data.

The protocol defines that N circuits be part of a multi path construction and
that they exit to the same point. Taken from the prop329, this is an example
where N=2:

         Primary Circuit (lower RTT)
            +-------+      +--------+
            |Guard 1|----->|Middle 1|----------+
            +---^---+      +--------+          |
   +-----+      |                           +--v---+
   | OP  +------+                           | Exit |--> ...
   +-----+      |                           +--^---+
            +---v---+      +--------+          |
            |Guard 2|----->|Middle 2|----------+
            +-------+      +--------+
         Secondary Circuit (higher RTT)


The primary circuit is chosen based on the desired UX properties (see proposal) as
long as congestion control allows it. Several factors can trigger a switch to a
secondary circuit.

# Proposal to rename ClientCirc

The motivation for this rename is because of the advent of the multi path
feature (conflux). It means that a stream can be opened on N circuits where N >
1, and thus the concept of `ClientCirc` becomes false as it is not a single
circuit anymore.

A **circuit** boils down to a construction used to ensure data transmision is
anonymous and secure as a **single path** through the network.

We would like to introduce the "Tunnel" concept which is a semantic of a
"virtual pathway through the network" which, internally, it translates to
having N circuits where N >=1 or multiple path.

This design sketch does a dive from the top (public API) to bottom (circ
manager). It describes the changes and implications it means for the user to
the different crate using it.

## The Big Change

### Client circuit: `ClientCirc`

We propose that `ClientCirc` be refactored into three objects:

- `ClientTunnel` (user traffic, data).
- `ClientOnionTunnel` (onion service)
- `ClientDirTunnel` (directory).

Those will most likely share a common `Tunnel` trait or simply be wrappers.

This type distinction would prevent API users to misuse the tunnels as they are
very different constructions and purposes which, in our case, can lead to
safety issues. Leveraging a type system to minimize safety failures is
important.

Another reason is, as the "API Tech Specifics" section describes, there are
methods that are only possible for specific tunnel purposes. And thus,
splitting the semantic would help greatly.

### Circuit manager: `CircMgr`

As the multi path work design is allowing us to merge circuit reactors or even
add circuits to a reactor, it means that the circuit manager would become a
tunnel manager instead by building tunnels with N circuits as requested.

And so, we could think of renaming `tor-circmgr` to `tor-tunnelmgr` and thus
`CircMgr` to `TunnelMgr`.

This would be quite a rename and change but it would isolate the concept of
circuit within `tor-proto` exclusively while all other crates deal with
tunnels.

#### Constructing Tunnels

Here is a high level algorithm on how a tunnel is built:

1. The tunnel manager gets a request (or preemptively build) for a tunnel with
   a set of parameters describing how to build the tunnel (path, purpose,
   circuit parameters, ...).

2. If the requests asks for a multi path N > 1, then the manager spins N
   tunnel of N=1 for each.

   If the request is for N=1, non multi path, return the tunnel.

3. (multi path) Once all tunnels of N=1 have opened, the tunnel manager
   picks one reactor to be the main reactor. It then pulls the circuits from
   the other reactors with a control command `ShutdownAndReturnCircuit`.

4. (multi path) The collected circuits are then given to the main reactor
   with a control command `LinkCircuits` which will initiate automatically the
   conflux linking process. The returned result of this command indicates
   either an error or a confirmation that the reactor is fully linked and
   ready for streams.

## API Tech Specifics

### The `ClientCirc` public API

Most current methods will still apply to the concept of a tunnel except few
exceptions:

- `begin_dir_stream()` could be only for `ClientDirTunnel`.

- `binding_key()` would only apply to N=1 else error. It is currently only used
   for introduction point establishment which is **never** multi path.

- `extend_ntor_*()` would only apply to N=1 else error.

- `extend_virtual()` could be only for `ClientOnionTunnel`.

- `last_hop_num()` applies to multi path because the Exit is always the same
   and because this function is used to speak with the last hop, it works out.

- `first_hop()` and `first_hop_clock_skew` would only apply to N=1. This is has
   a single use which is for directory fetch. We could consider moving it to
   `ClientDirTunnel` only.

- `path_ref()` would need to return every circuit path in the tunnel. Likely a
   `Vec<Path>` or some HashMap if the circuit positionning matters.

- `resolve*()` could be only for `ClientTunnel` avoiding anyone calling this on
   an onion service or, worst, directory tunnel.

- `start_conversation()` takes a `HopNum` and that is problematic in a multi
   path tunnel. Thus possible we would only apply this function to a N=1
   tunnel or pin this to the last hop but this would go against our leaky pipe
   design. But then the alternative is to expose a way to do a conversation on
   a specific circuit and so we would need to have a way to gather multi path
   circuit identifiers so they can be used in such function.

### The `CircMgr` public API

We could think of renaming `tor-circmgr` to `tor-tunnelmgr` considering we want
to remove the concept of circuit from crates and keep that in the `tor-proto`
crate to keep them fully internal. This means `CircMgr` to `TunnelMgr` and this
means quite a rename ;).

Otherwise, `CircMgr` requires changes and renaming:

- `retire_circ()` would change to `retire_tunnel()`

- The `builder()` returns a `CircuitBuilder` which we should be renamed to
  `TunnelBuilder` along `CircParameters` to `TunnelParameters`.

  The `CircuitBuilder::build()` function would either need to be changed to
  return an `enum` (Dir or UserTraffic tunnel) or have two functions,
  `build_dir()` and `build()`.

There is a reality where `get_or_launch_*()` functions could be confusing to
users. Reason is that this function offers no "only get, don't fetch" option
and so its name might be overloaded for no reasons.

A user likely wants at this point to just "get" a tunnel that can then be used
to transfer whatever data it wants. It doesn't matter much if it is launched or
taken from a preemptive pool.

> [dgoulet] Its worth noting here that at the moment, multi path (conflux)
construction is never launched on demand, it is always preemptively built and
given if available. This means that our API will need a way to say "force
launch" or have an explicit `launch()`.

We propose to introduce a new functions:

- `get_dir()` returning a `ClientDirTunnel`.

- `get()` returning a `ClientTunnel`.

The parameter(s) are left outside of this proposal as it will possibly need
a more complex struct to allow custom circuit configuration, etc...

The alternative is to keep the current functions but change their returned
value:

- `get_or_launch_dir()` would return a `ClientDirTunnel`.

- `get_or_launch_exit()` would return a `ClientTunnel`. We could consider
   renaming this one because the concept of "exit" is not something that
   everyone understands.

### The `ClientStreamCtrl` public API

This one is simple, there is a `circuit()`, we would need to return likely a
`dyn Tunnel` which we would need to match what the intend use is for this
function.

However, at the moment, this is unused through out our code base so its worth
thinking if this is worth keeping? Does a `ClientDataStreamCtrl` need access to
the underlying circuit? Couldn't it just have a rx to the reactor?

### The `HsClientConnector` public API

The `get_or_launch_circuit()` would simply return a `ClientOnionTunnel`.

## Circuit reactor changes

Currently, there is a 1:1 mapping between a circuit and its corresponding
reactor.

To support traffic splitting/conflux, we plan to modify the circuit reactor to
support handling multiple circuits.

Most of the circuit `Reactor` internals will be moved to a separate structure,
representing a circuit. The control and command channels will remain in the
`Reactor`, because they will be shared by all circuit. The `Reactor` will
look like so:

```rust
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// Receiver for control messages for this reactor, sent by `ClientCirc` objects.
    ///
    /// This channel is polled in [`Reactor::run_once`], but only if the `chan_sender` sink
    /// is ready to accept cells.
    control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// Receiver for command messages for this reactor, sent by `ClientCirc` objects.
    ///
    /// This channel is polled in [`Reactor::run_once`].
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `chan_sender` is not
    /// ready (whereas `control` messages are not read until the `chan_sender` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<CtrlCmd>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: oneshot::Sender<void::Void>,
    /// All the circuits.
    circuits: CircuitSet,
    /// The StreamMap of the last hop
    streams: StreamMap,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
}
```

`CircuitSet` is a set of one or more circuits. Circuit are represented
internally by the `ClientCircuit` struct:

```rust
/// A client circuit.
///
/// Multi path have `N` (usually, `N = 2`) circuits.
pub(super) struct ClientCircuit {
    /// The channel this circuit is attached to.
    channel: Arc<Channel>,
    /// Sender object used to actually send cells.
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    chan_sender: SometimesUnboundedSink<AnyChanCell, ChannelSender>,
    /// Input stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    // TODO: could use a SPSC channel here instead.
    input: Arc<Mutex<CircuitRxReceiver>>,
    /// The cryptographic state for this circuit for inbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit.
    crypto_in: InboundClientCrypt,
    /// The cryptographic state for this circuit for outbound cells.
    crypto_out: OutboundClientCrypt,
    /// List of hops state objects used by the reactor
    hops: Vec<CircHop>,
    /// Mutable information about this circuit, shared with
    /// [`ClientCirc`](super::ClientCirc).
    mutable: Arc<Mutex<MutableState>>,
    /// This circuit's identifier on the upstream channel.
    channel_id: CircId,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// A handler for a meta cell, together with a result channel to notify on completion.
    meta_handler: Option<Box<dyn MetaCellHandler + Send>>,
    /// A handler for incoming stream requests.
    #[cfg(feature = "hs-service")]
    incoming_stream_req_handler: Option<IncomingStreamRequestHandler>,
    /// Memory quota account
    #[allow(dead_code)] // Partly here to keep it alive as long as the circuit
    memquota: CircuitAccount,
}
```

**IMPORTANT**: we will need to rethink `CircHop`. In the current, pre-conflux
world, the reactor contains a `Vec<CircHop>`, where each `CircHop` has a
`StreamMap` for the streams open for that hop. This leaky-pipe
topology for streams would complicate our conflux implementation,
and we suspect is not needed in general, even with conflux disabled,
so we have decided to move the stream map out of `CircHop` and
into the `Reactor` itself.

The `CircuitSet` API:

```rust

impl CircuitSet {
    /// Create a new set, consisting of a single circuit.
    pub(super) fn new(circuit: ClientCircuit) -> Self { ... }

    /// Return the only circuit of this set.
    ///
    /// Returns an error if there is more than one circuit in the set,
    /// or if called before any circuits are available.
    pub(super) fn single_circuit(&mut self) -> Result<&mut ClientCircuit, Bug> { ... }

    /// Return the specified circuit of this set.
    ///
    /// Returns an error if the specified circuit doesn't exist.
    pub(super) fn circuit(&mut self, id: CircId) -> Result<&mut ClientCircuit, Bug> { ... }

    /// Return the primary circuit of this set.
    ///
    /// Returns an error if called before any circuits are available.
    pub(super) fn primary(&mut self) -> Result<&mut ClientCircuit, Bug> { ... }

    /// Return a [`Stream`] of incoming `ClientCircChanMsg` to poll from the
    /// main loop.
    pub(super) fn inputs(&self) -> impl Stream<Item = ClientCircChanMsg> { ... }
}
```

### New control commands

We will extend `CtrlCmd` and `CtrlCmd` with a number of client-side
conflux-specific commands

```rust
    enum CtrlCmd {
        ...
        /// Shutdown the reactor, returning the underlying circuit.
        ///
        /// The result is sent over the `done` channel.
        ///
        /// Returns an error if
        ///   * the reactor has more than one circuit.
        ///   * the ClientCircuits do not all have the same length
        ///   * the ClientCircuit do not all have the same exit
        ///   * any 2 ClientCircuits share the same guard or middle relays
        ShutdownAndReturnCircuit {
            /// Channel for notifying sender of completion.
            done: oneshot::Sender<Result<ClientCircuit>>,
        }
        ...
    }

    enum CtrlMsg {
        ...
        /// Link the given circuits of other reactors, obtained using
        /// CtrlCmd::ShutdownAndReturnCircuit, into the reactor receiving
        /// this command.
        ///
        /// The circuit will be used to form a `CircuitSet`.
        /// On receipt, the receiving reactor will initiate the conflux handshake
        /// to link the circuits. See [CONFLUX_HANDSHAKE] in prop329.
        LinkCircuits {
            /// The circuits to link in this reactor.
            circuits: Vec<ClientCircuit>,
            /// Channel for notifying sender of completion.
            done: oneshot::Sender<Result<()>>,
        },
    }
```


### Reactor main loop changes

The reactor main loop will be modified to `select!` between
   * the command channel (for control messages that do not require sending
     any outgoing messages on any of our channels), and
   * the channel of the *primary* circuit, for readiness

When the channel of the primary circuit becomes ready to accept cells,
`select_biased!` between
   * the control channel
   * the `inputs` of the `CircuitSet`. This will poll the channels of
     *all* circuits
   * the `ready_streams` of the `CircuitSet`. This will poll each stream of each
     hop of *each* circuit for ready items.

### Open design questions

1. The reactor is essentially a state machine, where in each state, only a
   subset of the `CtrlCmd`s/`CtrlMsg`s are allowed (for example, it is illegal
   to call `ClientCirc::extend_ntor` on a multipath circuit. It would be nice if
   we could somehow redesign it as a typestate(?), i.e. use the type system to
   prevent sending illegal control commands to reactor. However, that would
   require making the reactor generic over the control message types, and which
   will, in turn mean making the `ClientCirc` a typestate too (because the
   sending ends of the control channels are stored in `ClientCirc`).
