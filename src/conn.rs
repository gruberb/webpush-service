//! Transport: TLS, protocol selection, and handing each connection to hyper.
//!
//! ```text
//!        TCP accept
//!            |
//!   TLS handshake (rustls), ALPN: h2 | http/1.1
//!            |
//!   hyper-util auto: HTTP/1.1 or HTTP/2, upgrades enabled
//!            |
//!       axum router  ----> WebSocket upgrade on "/" (user agents)
//! ```
//!
//! This layer knows nothing about Web Push. Every connection, including
//! WebSocket upgrades, is served by the same axum router. There is no
//! plaintext listener (RFC 8030 §8).

use std::{sync::Arc, time::Duration};

use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
    service::TowerToHyperService,
};
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::ring,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

use crate::{BoxError, Config};

/// Connections that have not completed TLS by then are dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Server TLS configuration: TLS 1.2 and 1.3 with the `ring` provider,
/// offering `h2` and `http/1.1` over ALPN.
pub fn tls_config(cfg: &Config) -> Result<Arc<ServerConfig>, BoxError> {
    let certs = CertificateDer::pem_slice_iter(cfg.tls_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(cfg.tls_key_pem.as_bytes())?;
    let mut tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

/// Accept connections until the future is dropped. Each connection runs on
/// its own task, and a failing connection never affects the others.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    router: Router,
) -> Result<(), BoxError> {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(e) => {
                // Usually fd exhaustion; back off instead of spinning.
                tracing::warn!(error = %e, "accept");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let (acceptor, router) = (acceptor.clone(), router.clone());
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
            else {
                return;
            };
            let svc = TowerToHyperService::new(router);
            let conn = auto::Builder::new(TokioExecutor::new());
            if let Err(e) = conn
                .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                .await
            {
                tracing::debug!(error = %e, "connection");
            }
        });
    }
}
