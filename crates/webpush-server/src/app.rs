//! State shared by every handler, session, stream, and background task.

use std::{collections::HashMap, sync::Arc};

use webpush_bridge::SharedBridge;

use crate::{
    BoxError, config::Config, hub::Hub, notify::ClusterLink, registration::Secrets,
    shutdown::Shutdown,
};

/// Shared service state.
pub struct App<S> {
    /// The configuration the process started with.
    pub cfg: Config,
    /// Persistent state.
    pub store: S,
    /// Connections open on this node.
    pub hub: Hub,
    /// How to reach other nodes, when running in a cluster.
    pub cluster: Option<ClusterLink>,
    /// Configured bridges, by name.
    pub bridges: HashMap<&'static str, SharedBridge>,
    /// Keys for bridged user agents' secrets.
    pub secrets: Secrets,
    /// Shutdown tokens and the task tracker.
    pub shutdown: Shutdown,
}

impl<S> App<S> {
    /// Assemble the state. Bridges are passed in rather than built here so
    /// embedders and tests can supply their own.
    pub fn new(
        cfg: Config,
        store: S,
        bridges: Vec<SharedBridge>,
        shutdown: Shutdown,
    ) -> Result<Arc<Self>, BoxError> {
        let cluster = cfg.cluster.as_ref().map(ClusterLink::new).transpose()?;
        let mut by_name = HashMap::new();
        for b in bridges {
            if by_name.insert(b.name(), b).is_some() {
                return Err("two bridges share a name".into());
            }
        }
        Ok(Arc::new(Self {
            hub: Hub::new(cfg.websocket.queue),
            secrets: Secrets::new(&cfg.registration.secret_keys),
            cluster,
            bridges: by_name,
            store,
            shutdown,
            cfg,
        }))
    }

    /// The public origin.
    pub fn origin(&self) -> &str {
        &self.cfg.origin
    }
}
