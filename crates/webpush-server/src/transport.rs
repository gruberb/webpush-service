//! Transport: accepting connections, TLS, protocol selection, and handing
//! each connection to hyper.
//!
//! ```text
//!   permit (max_connections)  ──>  TCP accept
//!                                      |
//!                    TLS handshake (rustls), ALPN h2 | http/1.1   [optional]
//!                                      |
//!                   hyper-util auto: HTTP/1.1 or HTTP/2, upgrades enabled
//!                                      |
//!                                 axum router
//! ```
//!
//! This layer knows nothing about Web Push. The connection permit travels
//! with every request as a [`ConnectionPermit`] extension, so a WebSocket
//! session, which outlives the HTTP connection it was upgraded from, keeps
//! counting against the limit until it closes.

use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::ring,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
use tower::ServiceExt;

use crate::{BoxError, config::Tls, shutdown::Shutdown, telemetry};

/// Held for as long as a connection, or a session upgraded from it, is open.
#[derive(Clone)]
pub struct ConnectionPermit(#[allow(dead_code)] Arc<OwnedSemaphorePermit>);

/// How a listener accepts connections.
pub struct Listener {
    /// Bound socket.
    pub tcp: TcpListener,
    /// TLS configuration, or `None` for plaintext.
    pub tls: Option<Arc<ServerConfig>>,
    /// Open connections allowed at once.
    pub max_connections: usize,
    /// Deadline for the TLS handshake.
    pub handshake_timeout: Duration,
    /// Label for the connection metrics: `public` or `internal`.
    pub name: &'static str,
}

/// Server TLS configuration: TLS 1.2 and 1.3 with the `ring` provider,
/// offering `h2` and `http/1.1` over ALPN.
pub fn tls_config(tls: &Tls) -> Result<Arc<ServerConfig>, BoxError> {
    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
    };
    tls_config_pem(&read(&tls.cert_file)?, &read(&tls.key_file)?)
}

/// As [`tls_config`], from PEM bytes.
pub fn tls_config_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, BoxError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem)?;
    let mut tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

/// Accept connections until shutdown stops the listener. Each connection
/// runs on its own tracked task; a failing connection never affects the
/// others.
pub async fn serve(listener: Listener, router: Router, shutdown: Shutdown) {
    let permits = Arc::new(Semaphore::new(listener.max_connections));
    let acceptor = listener.tls.map(TlsAcceptor::from);
    loop {
        // Waiting for a permit before accepting leaves excess connections in
        // the kernel backlog instead of accepting and dropping them.
        let permit = tokio::select! {
            p = permits.clone().acquire_owned() => p.expect("semaphore is never closed"),
            () = shutdown.stopping.cancelled() => break,
        };
        let tcp = tokio::select! {
            r = listener.tcp.accept() => match r {
                Ok((tcp, _)) => tcp,
                Err(e) => {
                    // Usually fd exhaustion; back off instead of spinning.
                    tracing::warn!(error = %e, "accept");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = shutdown.stopping.cancelled() => break,
        };
        let _ = tcp.set_nodelay(true);
        let (router, acceptor, shutdown2) = (router.clone(), acceptor.clone(), shutdown.clone());
        let (name, timeout) = (listener.name, listener.handshake_timeout);
        shutdown.tasks.spawn(async move {
            let _open = telemetry::Gauge::new(telemetry::CONNECTIONS, name);
            let permit = ConnectionPermit(Arc::new(permit));
            match acceptor {
                None => connection(tcp, router, permit, shutdown2).await,
                Some(acceptor) => {
                    let Ok(Ok(tls)) = tokio::time::timeout(timeout, acceptor.accept(tcp)).await
                    else {
                        return;
                    };
                    connection(tls, router, permit, shutdown2).await;
                }
            }
        });
    }
}

/// Serve one connection. On shutdown, hyper stops reading new requests,
/// finishes the ones in flight, and closes.
async fn connection<I>(io: I, router: Router, permit: ConnectionPermit, shutdown: Shutdown)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = router.map_request(move |mut req: Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(permit.clone());
        req
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    let conn =
        builder.serve_connection_with_upgrades(TokioIo::new(io), TowerToHyperService::new(svc));
    tokio::pin!(conn);
    let result = tokio::select! {
        r = conn.as_mut() => r,
        () = shutdown.stopping.cancelled() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = result {
        tracing::debug!(error = %e, "connection");
    }
}
