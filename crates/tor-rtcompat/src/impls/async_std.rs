//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

/// Types used for networking (async_std implementation)
mod net {
    use crate::traits;

    use async_std_crate::net::{TcpListener, TcpStream, UdpSocket as StdUdpSocket};
    #[cfg(unix)]
    use async_std_crate::os::unix::net::{
        UnixListener as AsyncStdUnixListener, UnixStream as AsyncStdUnixStream,
    };
    use async_trait::async_trait;
    use cfg_if::cfg_if;
    use futures::future::Future;
    use futures::io::{AsyncRead, AsyncWrite};
    use futures::stream::{BoxStream, Stream, StreamExt};
    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A `Stream` of incoming TCP streams.
    ///
    /// Differs from the output of [`TcpListener::incoming`] in that this
    /// struct is a real type, and that it returns a TCP stream and an address
    /// for each input.
    pub struct IncomingStreams {
        /// A state object, stored in an Option so we can take ownership of it
        /// while poll is being called.
        // TODO(nickm): I hate using this trick.  At some point in the
        // future, once Rust has nice support for async traits, maybe
        // we can refactor it.
        state: Option<IncomingStreamsState>,
    }
    /// The result type returned by [`take_and_poll`].
    ///
    /// It has to include the TcpListener, since take_and_poll() has
    /// ownership of the listener.
    type FResult = (IoResult<(TcpStream, SocketAddr)>, TcpListener);
    /// Helper to implement [`IncomingStreams`]
    ///
    /// This function calls [`TcpListener::accept`] while owning the
    /// listener.  Thus, it returns a future that itself owns the listener,
    /// and we don't have lifetime troubles.
    async fn take_and_poll(lis: TcpListener) -> FResult {
        let result = lis.accept().await;
        (result, lis)
    }
    /// The possible states for an [`IncomingStreams`].
    enum IncomingStreamsState {
        /// We're ready to call `accept` on the listener again.
        Ready(TcpListener),
        /// We've called `accept` on the listener, and we're waiting
        /// for a future to complete.
        Accepting(Pin<Box<dyn Future<Output = FResult> + Send>>),
    }
    impl IncomingStreams {
        /// Create a new IncomingStreams from a TcpListener.
        pub fn from_listener(lis: TcpListener) -> IncomingStreams {
            IncomingStreams {
                state: Some(IncomingStreamsState::Ready(lis)),
            }
        }
    }
    impl Stream for IncomingStreams {
        type Item = IoResult<(TcpStream, SocketAddr)>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            use IncomingStreamsState as St;
            let state = self.state.take().expect("No valid state!");
            let mut future = match state {
                St::Ready(lis) => Box::pin(take_and_poll(lis)),
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
    #[async_trait]
    impl traits::TcpListener for TcpListener {
        type TcpStream = TcpStream;
        type Incoming = IncomingStreams;
        async fn accept(&self) -> IoResult<(Self::TcpStream, SocketAddr)> {
            TcpListener::accept(self).await
        }
        fn incoming(self) -> IncomingStreams {
            IncomingStreams::from_listener(self)
        }
        fn local_addr(&self) -> IoResult<SocketAddr> {
            TcpListener::local_addr(self)
        }
    }

    #[async_trait]
    impl traits::TcpProvider for async_executors::AsyncStd {
        type TcpStream = TcpStream;
        type TcpListener = TcpListener;
        async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
            TcpStream::connect(addr).await
        }
        async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
            TcpListener::bind(*addr).await
        }
    }

    #[async_trait]
    impl traits::UdpProvider for async_executors::AsyncStd {
        type UdpSocket = UdpSocket;

        async fn bind(&self, addr: &std::net::SocketAddr) -> IoResult<Self::UdpSocket> {
            StdUdpSocket::bind(*addr)
                .await
                .map(|socket| UdpSocket { socket })
        }
    }

    /// Wrap a AsyncStd UdpSocket
    pub struct UdpSocket {
        /// The underlying UdpSocket
        socket: StdUdpSocket,
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

    /// Wrap a async-std UnixSocket
    pub struct UnixStream {
        /// The underlying UnixStream
        #[cfg(unix)]
        s: AsyncStdUnixStream,

        /// Unit, so that this struct can't be constructed on non-unix platforms.
        #[cfg(not(unix))]
        _void: (),
    }
    #[cfg(unix)]
    impl From<AsyncStdUnixStream> for UnixStream {
        fn from(s: AsyncStdUnixStream) -> UnixStream {
            UnixStream { s }
        }
    }
    impl AsyncRead for UnixStream {
        #[allow(unused_mut)]
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            cfg_if! {
                if #[cfg(unix)] {
                    Pin::new(&mut self.s).poll_read(cx, buf)
                }
                else {
                    let _ = (cx, buf);
                    Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
                }
            }
        }
    }
    impl AsyncWrite for UnixStream {
        #[allow(unused_mut)]
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            cfg_if! {
                if #[cfg(unix)] {
                    Pin::new(&mut self.s).poll_write(cx, buf)
                }
                else {
                    let _ = (cx, buf);
                    Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
                }
            }
        }
        #[allow(unused_mut)]
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            cfg_if! {
                if #[cfg(unix)] {
                    Pin::new(&mut self.s).poll_flush(cx)
                }
                else {
                    let _ = cx;
                    Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
                }
            }
        }
        #[allow(unused_mut)]
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            cfg_if! {
                if #[cfg(unix)] {
                    Pin::new(&mut self.s).poll_close(cx)
                }
                else {
                    let _ = cx;
                    Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
                }
            }
        }
    }

    /// Wrap a async-std UnixListener
    pub struct UnixListener {
        /// The underlying listener.
        #[cfg(unix)]
        pub(super) lis: AsyncStdUnixListener,

        /// Unit, so that this struct can't be constructed on non-unix platforms.
        #[cfg(not(unix))]
        _void: (),
    }
    #[cfg(unix)]
    impl From<AsyncStdUnixListener> for UnixListener {
        fn from(lis: AsyncStdUnixListener) -> Self {
            Self { lis }
        }
    }
    #[async_trait]
    impl traits::UnixListener for UnixListener {
        type UnixStream = UnixStream;
        type Incoming = BoxStream<'static, IoResult<(Self::UnixStream, traits::UnixSocketAddr)>>;
        async fn accept(&self) -> IoResult<(Self::UnixStream, traits::UnixSocketAddr)> {
            cfg_if! {
                if #[cfg(unix)] {
                    let (stream, addr) = self.lis.accept().await?;
                    Ok((stream.into(), addr.into()))
                }
                else {
                    Err(std::io::ErrorKind::Unsupported.into())
                }
            }
        }
        fn incoming(self) -> Self::Incoming {
            cfg_if! {
                if #[cfg(unix)] {
                    async_stream::try_stream! {
                        loop {
                            let (stream, address) = self.accept().await?;
                            yield (stream, address);
                        }
                    }.boxed()
                }
                else {
                    futures::stream::once(async { Err(std::io::ErrorKind::Unsupported.into()) } ).boxed()
                }
            }
        }
        fn local_addr(&self) -> IoResult<traits::UnixSocketAddr> {
            cfg_if! {
                if #[cfg(unix)] {
                    self.lis.local_addr().map(Into::into)
                }
                else {
                    Err(std::io::ErrorKind::Unsupported.into())
                }
            }
        }
    }

    #[async_trait]
    impl traits::UnixProvider for async_executors::AsyncStd {
        type UnixStream = UnixStream;
        type UnixListener = UnixListener;

        async fn connect_unix(&self, path: &Path) -> IoResult<Self::UnixStream> {
            cfg_if! {
                if #[cfg(unix)] {
                    let s = AsyncStdUnixStream::connect(path).await?;
                    Ok(s.into())
                }
                else {
                    let _ = path;
                    Err(std::io::ErrorKind::Unsupported.into())
                }
            }
        }

        async fn listen_unix(&self, path: &Path) -> IoResult<Self::UnixListener> {
            cfg_if! {
                if #[cfg(unix)] {
                    let lis = AsyncStdUnixListener::bind(path).await?;
                    Ok(lis.into())
                }
                else {
                    let _ = path;
                    Err(std::io::ErrorKind::Unsupported.into())
                }
            }
        }

        async fn unbound_unix(&self) -> IoResult<(Self::UnixStream, Self::UnixStream)> {
            cfg_if! {
                if #[cfg(unix)] {
                    let pair = AsyncStdUnixStream::pair()?;
                    Ok((pair.0.into(), pair.1.into()))
                }
                else {
                    Err(std::io::ErrorKind::Unsupported.into())
                }
            }
        }
    }

    #[cfg(unix)]
    impl From<async_std_crate::os::unix::net::SocketAddr> for traits::UnixSocketAddr {
        fn from(value: async_std_crate::os::unix::net::SocketAddr) -> Self {
            Self {
                path: value.as_pathname().map(|p| p.to_owned()),
            }
        }
    }
}

// ==============================

use futures::{Future, FutureExt};
use std::pin::Pin;
use std::time::Duration;

use crate::traits::*;

/// Create and return a new `async_std` runtime.
pub fn create_runtime() -> async_executors::AsyncStd {
    async_executors::AsyncStd::new()
}

impl SleepProvider for async_executors::AsyncStd {
    type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        Box::pin(async_io::Timer::after(duration).map(|_| ()))
    }
}

impl BlockOn for async_executors::AsyncStd {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        async_executors::AsyncStd::block_on(f)
    }
}
