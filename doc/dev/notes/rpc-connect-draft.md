# RPC connections - design proposal

This proposes a method for applications to
obtain connections to the Arti RPC system.

## Use cases / connection styles / requirements

 1. A fairly vanilla Tor-aware application
    wants to route its connections via Arti,
    and just wants to use SOCKS and not RPC.
    Its connections should be isolated from other clients.

 2. A slightly more sophisticated client application
    knows enough about RPC to make simple enquiry calls,
    and wants to be able to maybe do some simple management operations,
    but wants to make RPC calls to obtain SOCKS details
	that will be used for multiple requests.

 2. A fully sophisticated client application
    wants to use a "system Arti" (or a "user Arti")
	via RPC.

 3. An application embeds a copy of Arti,
    but is also happy to use a system Arti.
    Again, the application should be able to manage its own state.
    But, other applications shouldn't be able to mess with it.

 4. An application embeds a copy of Arti,
    and wants to insist that no-one else uses it.
	(Not clear if we need or want to allow this use case.)

 5. The system administrator (or user) needs to be abl to
    have full access, including complete reconfiguration.

## Other requirementrs

 6. Most of the above considers clients ("arti proxy").
    We need to support relays too.
	They don't offer SOCKS, but they need to offer RPC functionality,
	possibly a completely different set to clients'.

 7. It should be convenient for the user or sysadmin to
    cause the software to behave as they wish.
	The discussion in !2388 suggests that
	environment variables are a good idea:
	ie, it should be possible to appropriately influence the behaviour
	by setting env vars, as well as by writing config files
	or hardcoding values in the application.
	
 8. Applications should have the a minimum amount of knowledge
    consistent with getting their work done.

 9. If the user runs a "user Arti" on a Unix system,
    it should be possible to prevent other users
	accessing its RPC API at all.
    Ideally it should be possible to prevent its use even via raw SOCKS
    (use case 1 above).

## Observations

We intend to support in-process clients by using an
in-process transport for the same RPC protocol.
So the set of available API calls, and their semantics,
will be the same, etc.
But in-process needs a different way of connecting.

There should be a hierarchy of connection information configuration:
env vars should override config files;
config files should override hardcoded defaults.

Use case 1 doesn't involve the RPC system.
We intend to continue to support it.
There may be value in a hybrid use case where 

Applications' connections should be isolated from other users,
so we need to be able to distinguish different applications.
For use case 1, that's ad hoc.
For the others it can be explicit.
Use cases 2 onwards should be able to create hidden services;
each application should be able to manage its own state,
control how its connections are made, and so forth.
Other applications (other than the superuser)
shouldn't be able to mess with it.

Some applications in use cases 2/3
can maintain a connection to Arti and it is that connection
which identifies the application.
The application may make further connections,
which should all be associated with that application.

But will some applications in use cases 2/3
want to be able to (for example) use the RPC system
to create hidden services, which will then run,
even while the application disconnects?
This necessarily involves some kind of host-global namespace,
or something.

## Application separate

Often a single human user's applications
will run in a similar privilege context
(eg the same unix user).
In this scenario,
we need a security mechanism at the Arti RPC interface
that stops entirely other users from messing with things,
but there is no need for anything beyond
knowing that the application is running as the same user as arti.
Applications that want mutual isolation
are trusted to do that correctly,
and not "cheat" somehow.

But sometimes we want to be able to
defend applications from each other.
On Unix this means running them as different users.
Arti may run as the same user as some apps, or not.
Cross-user mutually-untrusting privsep on Unix is not straightforward.

## Key concept

Emerging from all of this is the concept of an Application,
which seems to have the following properties:

 * Arti distinguishes different Applications.
 * Each Application's Tor circuits are isolated from each other.
 * At the very least, we have Applications which last as long as
   the RPC session they were established in.

(I think in the current implementation an Application corresponds
roughly to a Rust `TorClient` object.)

## Proposal

### Configuration (and default config) of `arti` cli on Unix

The default TorClient you get via RPC without authentication
is no more capable than you can do with raw SOCKS.

Some config setting in Arti allows you to specify that
only the same user may use this Arti instance.

In that case Arti will not allow raw SOCKS connections,
and you can't get a default TorClient without authenticating.

### Same-user authentication on Unix (including MacOs)

We have Arti write a secret to a well-known file in `~`.
The default connection string specifies this filename.

### Cross-user authentication in Unix (including MacOs)

There are a number of ways that this can be done.
We should only support ways that are suitable for
*mutually* untrusting users,
since otherwise there is too much risk of abuse
(ie, accidental use of facilities with asymmetric trust).

Approaches I am aware of include:

 1. Use AF_UNIX.
    Control the permissons of the directory containing
    the socket.
    Requires manual setup of the directory and
	the Unix users/groups.

 2. Use a dumb proxy to do the connection,
    and have the proxy perform an identification/authorisation.
	Eg, connect via "ssh somehost arti rpc-client-forwarder" or userv.
	Needs RPC command to permanently limit session privilege.

 3. Use a JSON-RPC-aware proxy which implements
    an object ID namespace partition
	and translates authentication requests.

 4. SO_PASSCRED

 5. Manually configure a secret for a hash-based authentication scheme.

 6. Public key enrolment.

 7. Like 1 but arti writes a secret to a file which the client reads.

Of these I propose that we initially implement only 1,
and only by (i) having Arti supporting multiple AF_UNIX listeners
with configured pathnames
(ii) having the RPC client library be able to connect to an ambiently
configured filename.

### Cross-user authentication in Android

"Cross user" means different uids, ie (roughly) "different Android app".

TBD, but we can probably use the Android binder somehow.

### Cross-??? authentication in iOS (Apple phones/tablets)

FIIK.

*Can* we even usefully have a shared Arti on iOS which offers RPC?

We should ideally make sure that whatever we do can be made to work.
Hopefully that wouldn't involve a complete upending of our entire design.

### Discovery

In the current protocol we are proposing to use connection strings.
I think connection strings are fine,
*but* applications should not normally provide one.

Instead, the default behaviour should be to look for
 * a "user arti" (on Unix)
 * a system arti
 * if the application has chosen to embed a copy of Arti,
   spin up the internal one

This should all be done with one API call,
and the application code should be unaware of it.

### API calls

I suggest:

A new `RpcClientBuilder`
which can also *launch* Arti (if that's compiled in).
(Initially we might not support this
but it should be contemplated in our API
and it should be the usual encouraged case for embedders.)

`RpcClientBuilder`  is at a higher level than connection strings.

You can configure:
 * `application_name_for_logging: &str`
   (passed to Arti perhaps via some RPC API call on `session`,
   or perhaps via connection string, and used for logging, not for security)
 * Configuration information (used to configure a launched Arti)
 * Disabling starting of a fresh Arti
   (ie insisting on using a user or system one)
 * Specifying a precise raw connection string
   (discouraged)

If it starts an Arti it will also shut it down after the last RPC connection closes.
The locally-started Arti will not be readily accessible to other processes.

We need a way to get more RPC connections for the same Application.
This seems to imply the existence of connection strings containing secrets?
Or something?

The default behaviour should probably be to start Arti if necessary.
That means that when we implement that,
there will be a significant behavioural change.

The default way of finding Arti will be to look
in fixed places in `~` and `/`.

The RPC client probably ought not to try to look at Arti configuration.

Instead there could be environment variasbles
and builder options to control
  * Location of the socket and secret file for a user arti
  * Location of the socket and secret file for a system arti
  * Raw connection string
