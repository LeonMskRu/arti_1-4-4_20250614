//! Re-exports of the tokio runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.

/// Types used for networking (tokio implementation)
pub(crate) mod net {
    use crate::traits::{self, UnixSocketAddr};
    use async_trait::async_trait;

    use cfg_if::cfg_if;
    #[cfg(unix)]
    pub(crate) use tokio_crate::net::{
        unix::SocketAddr as TokioUnixSocketAddr, UnixListener as TokioUnixListener,
        UnixStream as TokioUnixStream,
    };
    pub(crate) use tokio_crate::net::{
        TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
    };

    use futures::io::{AsyncRead, AsyncWrite};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Wrapper for Tokio's TcpStream that implements the standard
    /// AsyncRead and AsyncWrite.
    pub struct TcpStream {
        /// Underlying tokio_util::compat::Compat wrapper.
        s: Compat<TokioTcpStream>,
    }
    impl From<TokioTcpStream> for TcpStream {
        fn from(s: TokioTcpStream) -> TcpStream {
            let s = s.compat();
            TcpStream { s }
        }
    }
    impl AsyncRead for TcpStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            Pin::new(&mut self.s).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for TcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            Pin::new(&mut self.s).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::new(&mut self.s).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            Pin::new(&mut self.s).poll_close(cx)
        }
    }

    /// Wrap a Tokio TcpListener to behave as a futures::io::TcpListener.
    pub struct TcpListener {
        /// The underlying listener.
        pub(super) lis: TokioTcpListener,
    }

    /// Asynchronous stream that yields incoming connections from a
    /// TcpListener.
    ///
    /// This is analogous to async_std::net::Incoming.
    pub struct IncomingTcpStreams {
        /// Reference to the underlying listener.
        pub(super) lis: TokioTcpListener,
    }

    impl futures::stream::Stream for IncomingTcpStreams {
        type Item = IoResult<(TcpStream, SocketAddr)>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.lis.poll_accept(cx) {
                Poll::Ready(Ok((s, a))) => Poll::Ready(Some(Ok((s.into(), a)))),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }
    #[async_trait]
    impl traits::TcpListener for TcpListener {
        type TcpStream = TcpStream;
        type Incoming = IncomingTcpStreams;
        async fn accept(&self) -> IoResult<(Self::TcpStream, SocketAddr)> {
            let (stream, addr) = self.lis.accept().await?;
            Ok((stream.into(), addr))
        }
        fn incoming(self) -> Self::Incoming {
            IncomingTcpStreams { lis: self.lis }
        }
        fn local_addr(&self) -> IoResult<SocketAddr> {
            self.lis.local_addr()
        }
    }

    /// Wrap a Tokio UdpSocket
    pub struct UdpSocket {
        /// The underelying UdpSocket
        socket: TokioUdpSocket,
    }

    impl UdpSocket {
        /// Bind a UdpSocket
        pub async fn bind(addr: SocketAddr) -> IoResult<Self> {
            TokioUdpSocket::bind(addr)
                .await
                .map(|socket| UdpSocket { socket })
        }
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

    /// Wrap a Tokio UnixSocket
    pub struct UnixStream {
        /// The underlying UnixStream
        #[cfg(unix)]
        s: Compat<TokioUnixStream>,

        /// Unit, so that this struct can't be constructed on non-unix platforms.
        #[cfg(not(unix))]
        _void: (),
    }
    #[cfg(unix)]
    impl From<TokioUnixStream> for UnixStream {
        fn from(s: TokioUnixStream) -> UnixStream {
            let s = s.compat();
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

    /// Wrap a Tokio UnixListener
    pub struct UnixListener {
        /// The underlying listener.
        #[cfg(unix)]
        pub(super) lis: TokioUnixListener,

        /// Unit, so that this struct can't be constructed on non-unix platforms.
        #[cfg(not(unix))]
        _void: (),
    }

    /// Asynchronous stream that yields incoming connections from a
    /// UnixListener.
    ///
    /// This is analogous to async_std::net::Incoming.
    pub struct IncomingUnixStreams {
        /// The underlying listener.
        #[cfg(unix)]
        pub(super) lis: TokioUnixListener,

        /// Unit, so that this struct can't be constructed on non-unix platforms.
        #[cfg(not(unix))]
        _void: (),
    }

    impl futures::stream::Stream for IncomingUnixStreams {
        type Item = IoResult<(UnixStream, UnixSocketAddr)>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            cfg_if! {
                if #[cfg(unix)] {
                    match self.lis.poll_accept(cx) {
                        Poll::Ready(Ok((s, a))) => Poll::Ready(Some(Ok((s.into(), a.into())))),
                        Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                        Poll::Pending => Poll::Pending,
                    }
                }
                else {
                    let _ = cx;
                    Poll::Ready(Some(Err(std::io::ErrorKind::Unsupported.into())))
                }
            }
        }
    }

    #[async_trait]
    impl traits::UnixListener for UnixListener {
        type UnixStream = UnixStream;
        type Incoming = IncomingUnixStreams;
        async fn accept(&self) -> IoResult<(Self::UnixStream, UnixSocketAddr)> {
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
                    IncomingUnixStreams { lis: self.lis }
                }
                else {
                    IncomingUnixStreams { _void: () }
                }
            }
        }
        fn local_addr(&self) -> IoResult<UnixSocketAddr> {
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

    #[cfg(unix)]
    impl From<TokioUnixSocketAddr> for UnixSocketAddr {
        fn from(value: TokioUnixSocketAddr) -> Self {
            UnixSocketAddr {
                path: value.as_pathname().map(|p| p.to_owned()),
            }
        }
    }
}

// ==============================

use crate::traits::*;
use async_trait::async_trait;
use cfg_if::cfg_if;
use futures::Future;
use std::io::Result as IoResult;
use std::path::Path;
use std::time::Duration;

impl SleepProvider for TokioRuntimeHandle {
    type SleepFuture = tokio_crate::time::Sleep;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        tokio_crate::time::sleep(duration)
    }
}

#[async_trait]
impl crate::traits::TcpProvider for TokioRuntimeHandle {
    type TcpStream = net::TcpStream;
    type TcpListener = net::TcpListener;

    async fn connect(&self, addr: &std::net::SocketAddr) -> IoResult<Self::TcpStream> {
        let s = net::TokioTcpStream::connect(addr).await?;
        Ok(s.into())
    }
    async fn listen(&self, addr: &std::net::SocketAddr) -> IoResult<Self::TcpListener> {
        let lis = net::TokioTcpListener::bind(*addr).await?;
        Ok(net::TcpListener { lis })
    }
}

#[async_trait]
impl crate::traits::UdpProvider for TokioRuntimeHandle {
    type UdpSocket = net::UdpSocket;

    async fn bind(&self, addr: &std::net::SocketAddr) -> IoResult<Self::UdpSocket> {
        net::UdpSocket::bind(*addr).await
    }
}

#[async_trait]
impl crate::traits::UnixProvider for TokioRuntimeHandle {
    type UnixStream = net::UnixStream;
    type UnixListener = net::UnixListener;

    async fn connect_unix(&self, path: &Path) -> IoResult<Self::UnixStream> {
        cfg_if! {
            if #[cfg(unix)] {
                let s = net::TokioUnixStream::connect(path).await?;
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
                let lis = net::TokioUnixListener::bind(path)?;
                Ok(net::UnixListener { lis })
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
                let pair = net::TokioUnixStream::pair()?;
                Ok((pair.0.into(), pair.1.into()))
            }
            else {
                Err(std::io::ErrorKind::Unsupported.into())
            }
        }
    }
}

/// Create and return a new Tokio multithreaded runtime.
pub(crate) fn create_runtime() -> IoResult<TokioRuntimeHandle> {
    let mut builder = async_executors::TokioTpBuilder::new();
    builder.tokio_builder().enable_all();
    let owned = builder.build()?;
    Ok(owned.into())
}

/// Wrapper around a Handle to a tokio runtime.
///
/// Ideally, this type would go away, and we would just use
/// `tokio::runtime::Handle` directly.  Unfortunately, we can't implement
/// `futures::Spawn` on it ourselves because of Rust's orphan rules, so we need
/// to define a new type here.
///
/// # Limitations
///
/// Note that Arti requires that the runtime should have working implementations
/// for Tokio's time, net, and io facilities, but we have no good way to check
/// that when creating this object.
#[derive(Clone, Debug)]
pub struct TokioRuntimeHandle {
    /// If present, the tokio executor that we've created (and which we own).
    ///
    /// We never access this directly; only through `handle`.  We keep it here
    /// so that our Runtime types can be agnostic about whether they own the
    /// executor.
    owned: Option<async_executors::TokioTp>,
    /// The underlying Handle.
    handle: tokio_crate::runtime::Handle,
}

impl TokioRuntimeHandle {
    /// Wrap a tokio runtime handle into a format that Arti can use.
    ///
    /// # Limitations
    ///
    /// Note that Arti requires that the runtime should have working
    /// implementations for Tokio's time, net, and io facilities, but we have
    /// no good way to check that when creating this object.
    pub(crate) fn new(handle: tokio_crate::runtime::Handle) -> Self {
        handle.into()
    }

    /// Return true if this handle owns the executor that it points to.
    pub fn is_owned(&self) -> bool {
        self.owned.is_some()
    }
}

impl From<tokio_crate::runtime::Handle> for TokioRuntimeHandle {
    fn from(handle: tokio_crate::runtime::Handle) -> Self {
        Self {
            owned: None,
            handle,
        }
    }
}

impl From<async_executors::TokioTp> for TokioRuntimeHandle {
    fn from(owner: async_executors::TokioTp) -> TokioRuntimeHandle {
        let handle = owner.block_on(async { tokio_crate::runtime::Handle::current() });
        Self {
            owned: Some(owner),
            handle,
        }
    }
}

impl BlockOn for TokioRuntimeHandle {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.handle.block_on(f)
    }
}

impl futures::task::Spawn for TokioRuntimeHandle {
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> Result<(), futures::task::SpawnError> {
        let join_handle = self.handle.spawn(future);
        drop(join_handle); // this makes the task detached.
        Ok(())
    }
}
