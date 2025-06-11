# safelog

Mark data as sensitive for logging purposes.

Some information is too sensitive to routinely write to system logs, but
must nonetheless sometimes be displayed.  This crate provides a way to mark
such information, and log it conditionally, but not by default.

### Examples

There are two main ways to mark a piece of data as sensitive: by storing it
within a [`Sensitive`] object long-term, or by wrapping it in a
[`Sensitive`] object right before passing it to a formatter:

```rust
use safelog::{Sensitive, sensitive};

// With this declaration, a student's name and gpa will be suppressed by default
// when passing the student to Debug.
#[derive(Debug)]
struct Student {
   name: Sensitive<String>,
   grade: u8,
   homeroom: String,
   gpa: Sensitive<f32>,
}

// In this function, a user's IP will not be printed by default.
fn record_login(username: &str, ip: &std::net::IpAddr) {
    println!("Login from {} at {}", username, sensitive(ip));
}
```

You can disable safe-logging globally (across all threads) or locally
(across a single thread).

```rust
# let debug_mode = true;
# let log_encrypted_data = |_|();
# let big_secret = ();
use safelog::{disable_safe_logging, with_safe_logging_suppressed};

// If we're running in debug mode, turn off safe logging
// globally.  Safe logging will remain disabled until the
// guard object is dropped.
let guard = if debug_mode {
   // This call can fail if safe logging has already been enforced.
   disable_safe_logging().ok()
} else {
   None
};

// If we know that it's safe to record sensitive data with a given API,
// we can disable safe logging temporarily. This affects only the current thread.
with_safe_logging_suppressed(|| log_encrypted_data(big_secret));
```

### Common Patterns

#### Logging Network Operations Safely
```rust
use safelog::{Sensitive, sensitive};
use std::net::SocketAddr;

fn handle_socks_request(command: &str, client_addr: SocketAddr, port: u16) {
    // Command type is safe, but client address is sensitive 
    println!("Processing {} request from {} on port {}", 
          command,                         // "CONNECT", "RESOLVE" - operational context
          sensitive(client_addr.ip()),     // Hide client IP - shows as [scrubbed]
          port                             // Port is often OK to show
    );
}

// Example usage:
# let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
# handle_socks_request("CONNECT", addr, 443);
```

*Based on the SOCKS request logging pattern in [`crates/arti/src/socks.rs:512-514`](../arti/src/socks.rs)*

#### Protecting Sensitive Data in Structs
```rust
use safelog::Sensitive;
use std::net::SocketAddr;
use std::time::SystemTime;

#[derive(Debug)]  
struct ConnectionAttempt {
    pub connection_id: u64,               // Safe - just an identifier
    pub action: &'static str,             // Safe - "connecting", "authenticating"
    pub target_addr: Sensitive<SocketAddr>, // Hidden - destination is sensitive
    pub bridge_addr: Sensitive<SocketAddr>, // Hidden - bridge location is sensitive
    pub attempt_time: SystemTime,         // Safe - just a timestamp
}

// When logged, only connection_id, action, and attempt_time will be visible
```

*Based on error struct patterns with sensitive fields in [`crates/arti-client/src/err.rs:182`](../arti-client/src/err.rs) and [`crates/tor-chanmgr/src/err.rs:60,75`](../tor-chanmgr/src/err.rs)*

#### Safe Error Reporting  
```rust
use safelog::sensitive;
use std::net::SocketAddr;

fn connection_failed(action: &str, client_addr: SocketAddr, error: std::io::Error) {
    // Include operational context while protecting user identity
    eprintln!(
        "Connection failed during {} from {}: {}", 
        action,                     // "handshake", "data_transfer" - operational context
        sensitive(client_addr),     // Hide client address - shows as [scrubbed]
        error                       // Error details are usually safe to log
    );
}

// Example usage:
# let addr: SocketAddr = "10.0.0.1:9150".parse().unwrap();
# let error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
# connection_failed("handshake", addr, error);
```

*Based on the connection error handling pattern in [`examples/axum/axum-hello-world/src/main.rs:65`](../../examples/axum/axum-hello-world/src/main.rs)*

### An example deployment

This crate was originally created for use in the `arti` project, which tries
to implements the Tor anonymity protocol in Rust.  In `arti`, we want to
avoid logging information by default if it could compromise users'
anonymity, or create an incentive for attacking users and relays in order to
access their logs.

In general, Arti treats the following information as [`Sensitive`]:
  * Client addresses.
  * The destinations (target addresses) of client requests.

Arti does _not_ label all private information as `Sensitive`: when
information isn't _ever_ suitable for logging, we omit it entirely.

License: MIT OR Apache-2.0
