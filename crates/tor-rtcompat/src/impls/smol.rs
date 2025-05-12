//! Re-exports of the smol runtime for use with arti.
//! This crate defines a slim API around our async runtime so that we
//! can swap it out easily.

/// Types used for networking (smol implementation)
pub(crate) mod net {
    use super::SmolRuntimeHandle;
    use crate::{impls, traits};
    #[cfg(unix)]
    use async_net::unix::{UnixListener, UnixStream};
    use async_net::{TcpListener, TcpStream, UdpSocket as SmolUdpSocket};
    use async_trait::async_trait;
    use futures::future::Future;
    use futures::stream::Stream;
    use paste::paste;
    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tor_general_addr::unix;

    /// Provide wrapper for different stream types
    /// (e.g async_net::TcpStream and async_net::unix::UnixStream).
    macro_rules! impl_stream {
        { $kind:ident, $addr:ty } => { paste! {

            /// A `Stream` of incoming streams.
            pub struct [<Incoming $kind Streams>] {
                /// A state object, stored in an Option so we can take ownership of it
                // TODO: Currently this is an Option so we can take ownership of it using `.take()`.
                // Check if this approach can be improved once supporting Rust 2024.
                state: Option<[<Incoming $kind StreamsState>]>,
            }

            /// The result type returned by `take_and_poll_*`.
            type [<$kind FResult>] = (IoResult<([<$kind Stream>], $addr)>, [<$kind Listener>]);

            /// Helper to implement `Incoming*Streams`
            async fn [<take_and_poll_ $kind:lower>](lis: [<$kind Listener>]) -> [<$kind FResult>] {
                let result = lis.accept().await;
                (result, lis)
            }

            /// The possible states for an `Incoming*Streams`.
            enum [<Incoming $kind StreamsState>] {
                /// We're ready to call `accept` on the listener again.
                Ready([<$kind Listener>]),

                /// We've called `accept` on the listener, and we're waiting
                Accepting(Pin<Box<dyn Future<Output = [<$kind FResult>]> + Send + Sync>>),
            }

            impl [<Incoming $kind Streams>] {
                /// Create a new `Incoming*Streams` from a listener.
                pub fn from_listener(lis: [<$kind Listener>]) -> Self {
                    Self { state: Some([<Incoming $kind StreamsState>]::Ready(lis)) }
                }
            }

            impl Stream for [<Incoming $kind Streams>] {
                type Item = IoResult<([<$kind Stream>], $addr)>;

                fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
                    use [<Incoming $kind StreamsState>] as St;
                    let state = self.state.take().expect("No valid state!");
                    let mut future = match state {
                        St::Ready(lis) => Box::pin([<take_and_poll_ $kind:lower>](lis)),
                        St::Accepting(fut) => fut,
                    };
                    match future.as_mut().poll(cx) {
                        Poll::Ready((val, lis)) => {
                            self.state = Some(St::Ready(lis));
                            Poll::Ready(Some(val))
                        }
                        Poll::Pending => {
                            self.state = Some(St::Accepting(future));
                            Poll::Pending
                        }
                    }
                }
            }

            impl traits::NetStreamListener<$addr> for [<$kind Listener>] {
                type Stream = [<$kind Stream>];
                type Incoming = [<Incoming $kind Streams>];

                fn incoming(self) -> Self::Incoming {
                    [<Incoming $kind Streams>]::from_listener(self)
                }

                fn local_addr(&self) -> IoResult<$addr> {
                    [<$kind Listener>]::local_addr(self)
                }
            }
        }}
    }

    impl_stream! { Tcp, std::net::SocketAddr }
    #[cfg(unix)]
    impl_stream! { Unix, unix::SocketAddr }

    #[async_trait]
    impl traits::NetStreamProvider<std::net::SocketAddr> for SmolRuntimeHandle {
        type Stream = TcpStream;
        type Listener = TcpListener;

        async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::Stream> {
            TcpStream::connect(addr).await
        }

        async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::Listener> {
            TcpListener::bind(addr).await
        }
    }

    #[cfg(unix)]
    #[async_trait]
    impl traits::NetStreamProvider<unix::SocketAddr> for SmolRuntimeHandle {
        type Stream = UnixStream;
        type Listener = UnixListener;

        async fn connect(&self, addr: &unix::SocketAddr) -> IoResult<Self::Stream> {
            let path = addr
                .as_pathname()
                .ok_or(crate::unix::UnsupportedAfUnixAddressType)?;
            UnixStream::connect(path).await
        }

        async fn listen(&self, addr: &unix::SocketAddr) -> IoResult<Self::Listener> {
            let path = addr
                .as_pathname()
                .ok_or(crate::unix::UnsupportedAfUnixAddressType)?;
            UnixListener::bind(path)
        }
    }

    #[cfg(not(unix))]
    crate::impls::impl_unix_non_provider! { Smol }

    #[async_trait]
    impl traits::UdpProvider for SmolRuntimeHandle {
        type UdpSocket = UdpSocket;

        async fn bind(&self, addr: &std::net::SocketAddr) -> IoResult<Self::UdpSocket> {
            SmolUdpSocket::bind(addr)
                .await
                .map(|socket| UdpSocket { socket })
        }
    }

    /// Wrapper for `SmolUdpSocket`.
    // Required to implement `traits::UdpSocket`.
    pub struct UdpSocket {
        /// The underlying socket.
        socket: SmolUdpSocket,
    }

    #[async_trait]
    impl traits::UdpSocket for UdpSocket {
        async fn recv(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
            self.socket.recv_from(buf).await
        }

        async fn send(&self, buf: &[u8], target: &SocketAddr) -> IoResult<usize> {
            self.socket.send_to(buf, target).await
        }

        fn local_addr(&self) -> IoResult<SocketAddr> {
            self.socket.local_addr()
        }
    }

    impl traits::StreamOps for TcpStream {
        fn set_tcp_notsent_lowat(&self, lowat: u32) -> IoResult<()> {
            impls::streamops::set_tcp_notsent_lowat(self, lowat)
        }

        #[cfg(target_os = "linux")]
        fn new_handle(&self) -> Box<dyn traits::StreamOps + Send + Unpin> {
            Box::new(impls::streamops::TcpSockFd::from_fd(self))
        }
    }

    #[cfg(unix)]
    impl traits::StreamOps for UnixStream {
        fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
            Err(traits::UnsupportedStreamOp::new(
                "set_tcp_notsent_lowat",
                "unsupported on Unix streams",
            )
            .into())
        }
    }
}

// ==============================

use crate::traits::*;
use blocking::unblock;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::{Future, FutureExt};
use smol::spawn as smol_spawn;
use std::pin::Pin;
use std::time::Duration;

/// Handle for the smol runtime.
#[derive(Clone, Copy)]
pub struct SmolRuntimeHandle;

/// Construct a new smol runtime handle.
pub fn create_runtime() -> SmolRuntimeHandle {
    SmolRuntimeHandle
}

impl SleepProvider for SmolRuntimeHandle {
    type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        Box::pin(async_io::Timer::after(duration).map(|_| ()))
    }
}

impl ToplevelBlockOn for SmolRuntimeHandle {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        smol::block_on(f)
    }
}

impl Blocking for SmolRuntimeHandle {
    type ThreadHandle<T: Send + 'static> = blocking::Task<T>;

    fn spawn_blocking<F, T>(&self, f: F) -> blocking::Task<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        unblock(f)
    }

    fn reenter_block_on<F: Future>(&self, f: F) -> F::Output {
        smol::block_on(f)
    }
}

impl Spawn for SmolRuntimeHandle {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        smol_spawn(future).detach();
        Ok(())
    }
}
