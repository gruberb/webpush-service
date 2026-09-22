//! Cloud Bigtable [`Store`], accessed over gRPC.
//!
//! ```text
//!  family d (1 version)                          family m (1 version, max age)
//!  ua#{uaid}           seen, bridge, app, token  msg#{uaid}#t:{ch}:{topic}  message
//!  ch#{uaid}#{ch}      push, vapid               msg#{uaid}#{accepted}{id}  message
//!  push#{push}         uaid, ch                  mid#{id}                   row key
//!  rsub#{rsub}         c
//!  rq#{rsub}#{seq}     msg, status
//!  rexp#{expiry}#{id}  row
//!  route#u:{uaid}      node
//!  route#r:{rsub}      node
//! ```
//!
//! Bigtable only makes single-row writes atomic, and the layout relies on
//! that:
//!
//! ```text
//!  topic replacement                 delete / reap of message A
//!  -----------------                 --------------------------
//!  msg#{uaid}#t:{ch}:news            mid#A --> msg#{uaid}#t:{ch}:news
//!    [delete row, set cells]         CheckAndMutate(id == A)
//!    one atomic mutation               matched: delete it
//!                                      replaced by B: no match, None
//! ```
//!
//! Index rows are written after, and deleted after, the rows they point at,
//! so a reader can meet an orphan index row (ignored) but never a half
//! written one. See `docs/architecture.md` (Storage).
//!
//! # Connecting
//!
//! | Endpoint | Transport | Authentication |
//! |---|---|---|
//! | `http://…` (the emulator) | plaintext | none |
//! | `https://bigtable.googleapis.com` | TLS (`webpki-roots`) | OAuth 2.0 bearer token per call |
//!
//! Tokens come from [`webpush_gcp_auth::TokenSource`]: the configured
//! service account key, or Application Default Credentials (the metadata
//! server on Cloud Run and GKE, `gcloud auth application-default login`
//! locally). Every call also names its table in `x-goog-request-params`,
//! which Bigtable uses to route it.

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use bytes::Bytes;
use googleapis_tonic_google_bigtable_admin_v2::google::bigtable::admin::v2 as admin;
use googleapis_tonic_google_bigtable_v2::google::bigtable::v2::{
    self as bt, bigtable_client::BigtableClient, read_rows_response::cell_chunk::RowStatus,
    row_filter::Filter, row_range,
};
use tonic::{
    Code,
    metadata::MetadataValue,
    transport::{Channel, ClientTlsConfig},
};
use webpush_gcp_auth::TokenSource;

use crate::{
    BoxError, BridgeAddress, Message, Receipt, Recipient, Store, Subscription, Urgency, UserAgent,
    new_id, next_seq, now_ms,
};

/// Result of a storage operation. Errors are gRPC or decoding failures.
type Result<T> = std::result::Result<T, BoxError>;
/// Latest cell value per column qualifier.
type Row = HashMap<Vec<u8>, Vec<u8>>;

/// Column family for user agents, subscriptions, receipts, and indexes.
const D: &str = "d";
/// Column family for messages and the message id index.
const M: &str = "m";
/// OAuth scopes for reading and writing rows and for creating the table.
const SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/bigtable.data",
    "https://www.googleapis.com/auth/bigtable.admin.table",
];

/// Where the Bigtable table lives.
#[derive(Clone, Debug)]
pub struct BigtableConfig {
    /// gRPC endpoint: `https://bigtable.googleapis.com` for Cloud Bigtable,
    /// or `http://127.0.0.1:8086` for the emulator. `https` endpoints use
    /// TLS and OAuth; `http` endpoints neither.
    pub endpoint: String,
    /// Google Cloud project that contains the instance.
    pub project: String,
    /// Bigtable instance id.
    pub instance: String,
    /// Table id.
    pub table: String,
    /// The service's maximum TTL in seconds. [`BigtableStore::ensure_table`]
    /// keeps message cells for this long plus one day.
    pub max_ttl: u32,
    /// Service account key for an `https` endpoint. Without it, Application
    /// Default Credentials are used.
    pub credentials_file: Option<PathBuf>,
    /// App profile that routes the requests; the instance default if unset.
    pub app_profile: Option<String>,
}

impl BigtableConfig {
    /// Fully qualified table name, as the Bigtable API expects it.
    fn table_name(&self) -> String {
        format!(
            "projects/{}/instances/{}/tables/{}",
            self.project, self.instance, self.table
        )
    }

    /// A gRPC channel to the endpoint. The keepalive notices a dead
    /// connection before a request waits on it.
    async fn channel(&self) -> Result<Channel> {
        Self::connect_to(&self.endpoint).await
    }

    /// A channel to the admin API. Cloud Bigtable serves it on its own host,
    /// `bigtableadmin.googleapis.com`; the emulator serves both APIs on one
    /// port.
    async fn admin_channel(&self) -> Result<Channel> {
        let admin = self.endpoint.replace(
            "//bigtable.googleapis.com",
            "//bigtableadmin.googleapis.com",
        );
        Self::connect_to(&admin).await
    }

    /// A channel to `url`, with TLS for `https`.
    async fn connect_to(url: &str) -> Result<Channel> {
        let mut endpoint = Channel::from_shared(url.to_owned())?
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_while_idle(true);
        if url.starts_with("https://") {
            endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
        }
        Ok(endpoint.connect().await?)
    }

    /// Credentials for an `https` endpoint; `None` for the emulator.
    fn auth(&self) -> Result<Option<Arc<TokenSource>>> {
        if !self.endpoint.starts_with("https://") {
            return Ok(None);
        }
        let http = webpush_gcp_auth::http_client(Duration::from_secs(10))?;
        let source = match &self.credentials_file {
            Some(path) => TokenSource::from_file(path, &SCOPES, http)?,
            None => TokenSource::discover(&SCOPES, http)?,
        };
        Ok(Some(Arc::new(source)))
    }
}

/// Wrap `message` in a request with the routing header and, for Cloud
/// Bigtable, the bearer token. `params` is `field=resource`, as Bigtable
/// expects in `x-goog-request-params`.
async fn authorized<T>(
    message: T,
    auth: Option<&TokenSource>,
    params: &str,
) -> Result<tonic::Request<T>> {
    let mut req = tonic::Request::new(message);
    let md = req.metadata_mut();
    // Resource names hold `/`, which the header value must carry encoded.
    md.insert(
        "x-goog-request-params",
        MetadataValue::try_from(params.replace('/', "%2F"))?,
    );
    if let Some(auth) = auth {
        let token = auth.token().await?;
        md.insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}"))?,
        );
        if let Some(project) = auth.quota_project() {
            md.insert("x-goog-user-project", MetadataValue::try_from(project)?);
        }
    }
    Ok(req)
}

/// A [`Store`] backed by one Cloud Bigtable table.
///
/// Cheap to clone; clones share one gRPC channel.
#[derive(Clone)]
pub struct BigtableStore {
    /// Data API client.
    client: BigtableClient<Channel>,
    /// Fully qualified table name.
    table: String,
    /// Access tokens, for Cloud Bigtable.
    auth: Option<Arc<TokenSource>>,
    /// App profile, or empty for the instance default.
    app_profile: String,
}

/// A UTF-8 cell value.
fn text(row: &Row, col: &str) -> Option<String> {
    row.get(col.as_bytes())
        .and_then(|v| String::from_utf8(v.clone()).ok())
}

/// A cell holding a decimal integer.
fn number(row: &Row, col: &str) -> Option<u64> {
    text(row, col)?.parse().ok()
}

/// A mutation writing one cell at timestamp `ts_ms` (Unix milliseconds).
fn set_cell(family: &str, col: &str, value: impl Into<Vec<u8>>, ts_ms: u64) -> bt::Mutation {
    bt::Mutation {
        mutation: Some(bt::mutation::Mutation::SetCell(bt::mutation::SetCell {
            family_name: family.to_owned(),
            column_qualifier: col.as_bytes().to_vec(),
            // Bigtable tables default to millisecond timestamp granularity.
            timestamp_micros: (ts_ms * 1000).cast_signed(),
            value: value.into(),
        })),
    }
}

/// A mutation deleting every cell in the row.
fn delete_row() -> bt::Mutation {
    bt::Mutation {
        mutation: Some(bt::mutation::Mutation::DeleteFromRow(
            bt::mutation::DeleteFromRow {},
        )),
    }
}

/// Wrap a filter variant in a `RowFilter`.
fn filter(f: Filter) -> bt::RowFilter {
    bt::RowFilter { filter: Some(f) }
}

/// Keys in `[start, end)`.
fn range(start: String, end: String) -> bt::RowSet {
    bt::RowSet {
        row_keys: vec![],
        row_ranges: vec![bt::RowRange {
            start_key: Some(row_range::StartKey::StartKeyClosed(start.into_bytes())),
            end_key: Some(row_range::EndKey::EndKeyOpen(end.into_bytes())),
        }],
    }
}

/// Every key starting with `prefix`. Prefixes always end in `#`, and the
/// next byte up, `$`, bounds the range.
fn prefix(prefix: String) -> bt::RowSet {
    let end = format!("{}$", prefix.strip_suffix('#').unwrap_or(&prefix));
    range(prefix, end)
}

/// The row recording which node holds the connection for `to`.
fn route_key(to: &Recipient) -> String {
    match to {
        Recipient::UserAgent(uaid) => format!("route#u:{uaid}"),
        Recipient::Receipts(rsub) => format!("route#r:{rsub}"),
    }
}

/// `value` as an RE2 pattern that matches exactly that value.
fn exact(value: &str) -> Vec<u8> {
    let mut pattern = String::from("^");
    for c in value.chars() {
        if !c.is_ascii_alphanumeric() {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('$');
    pattern.into_bytes()
}

/// A predicate matching rows whose column `col` in family `family` holds
/// exactly `value`, or any value when `value` is `None`.
fn column_filter(family: &str, col: &str, value: Option<&str>) -> bt::RowFilter {
    let mut filters = vec![
        filter(Filter::FamilyNameRegexFilter(family.to_owned())),
        filter(Filter::ColumnQualifierRegexFilter(exact(col))),
        // Older versions stay readable until garbage collection runs; only
        // the latest value counts.
        filter(Filter::CellsPerColumnLimitFilter(1)),
    ];
    if let Some(v) = value {
        filters.push(filter(Filter::ValueRegexFilter(exact(v))));
    }
    filter(Filter::Chain(bt::row_filter::Chain { filters }))
}

/// Decode a user agent row.
fn user_agent_from_row(uaid: &str, row: &Row) -> UserAgent {
    let bridge = match (text(row, "bridge"), text(row, "app"), text(row, "token")) {
        (Some(bridge), Some(app_id), Some(token)) => Some(BridgeAddress {
            bridge,
            app_id,
            token,
        }),
        _ => None,
    };
    UserAgent {
        uaid: uaid.to_owned(),
        bridge,
        last_seen: number(row, "seen").unwrap_or_default(),
    }
}

/// The message row: keyed by topic when there is one, so a replacement
/// overwrites it, otherwise by acceptance time so rows sort oldest first.
fn message_key(m: &Message) -> String {
    match &m.topic {
        Some(t) => format!("msg#{}#t:{}:{t}", m.uaid, m.channel_id),
        None => format!("msg#{}#{:016x}{}", m.uaid, m.accepted, m.id),
    }
}

/// Decode a message row. `None` for a row that is incomplete, which happens
/// only if a write was interrupted.
fn message_from_row(key: &str, row: &Row) -> Option<Message> {
    let (uaid, slot) = key.strip_prefix("msg#")?.split_once('#')?;
    let topic = slot
        .strip_prefix("t:")
        .and_then(|rest| rest.split_once(':'))
        .map(|(_, topic)| topic.to_owned());
    Some(Message {
        id: text(row, "id")?,
        uaid: uaid.to_owned(),
        channel_id: text(row, "ch")?,
        push: text(row, "push")?,
        topic,
        body: Bytes::copy_from_slice(row.get(&b"body"[..])?),
        ctype: text(row, "ctype"),
        cenc: text(row, "cenc"),
        ttl: number(row, "ttl")?.try_into().ok()?,
        urgency: Urgency::parse(&text(row, "urgency")?)?,
        accepted: number(row, "accepted")?,
        expiry: number(row, "expiry")?,
        rsub: text(row, "rsub"),
    })
}

impl BigtableStore {
    /// Connect to the table named in `cfg`. The table must exist; see
    /// [`BigtableStore::ensure_table`].
    ///
    /// # Errors
    ///
    /// The endpoint is not a valid URI or does not accept connections, or
    /// the credentials cannot be loaded.
    pub async fn connect(cfg: &BigtableConfig) -> Result<Self> {
        Ok(BigtableStore {
            client: BigtableClient::new(cfg.channel().await?),
            table: cfg.table_name(),
            auth: cfg.auth()?,
            app_profile: cfg.app_profile.clone().unwrap_or_default(),
        })
    }

    /// Wrap a data API message for this table.
    async fn request<T>(&self, message: T) -> Result<tonic::Request<T>> {
        let params = format!("table_name={}", self.table);
        authorized(message, self.auth.as_deref(), &params).await
    }

    /// Create the table and its column families if they do not exist.
    /// Intended for the emulator and development; production tables should
    /// be provisioned ahead of time with the same schema.
    ///
    /// # Errors
    ///
    /// Connection failures and admin API errors. Callers starting alongside
    /// the emulator should retry until it accepts connections.
    pub async fn ensure_table(cfg: &BigtableConfig) -> Result<()> {
        use admin::{GcRule, gc_rule::Rule};
        let mut client = admin::bigtable_table_admin_client::BigtableTableAdminClient::new(
            cfg.admin_channel().await?,
        );
        let auth = cfg.auth()?;
        let get = admin::GetTableRequest {
            name: cfg.table_name(),
            ..Default::default()
        };
        let params = format!("name={}", cfg.table_name());
        match client
            .get_table(authorized(get, auth.as_deref(), &params).await?)
            .await
        {
            Ok(_) => return Ok(()),
            Err(s) if s.code() == Code::NotFound => {}
            Err(s) => return Err(s.into()),
        }

        let versions = || GcRule {
            rule: Some(Rule::MaxNumVersions(1)),
        };
        // Messages are also collected by age, so expired ones need no sweeper.
        let max_age = GcRule {
            rule: Some(Rule::MaxAge(prost_types::Duration {
                seconds: i64::from(cfg.max_ttl) + 86400,
                nanos: 0,
            })),
        };
        let family = |rule| admin::ColumnFamily {
            gc_rule: Some(rule),
            ..Default::default()
        };
        let families = HashMap::from([
            (D.to_owned(), family(versions())),
            (
                M.to_owned(),
                family(GcRule {
                    rule: Some(Rule::Union(admin::gc_rule::Union {
                        rules: vec![versions(), max_age],
                    })),
                }),
            ),
        ]);
        let parent = format!("projects/{}/instances/{}", cfg.project, cfg.instance);
        let params = format!("parent={parent}");
        let create = admin::CreateTableRequest {
            parent,
            table_id: cfg.table.clone(),
            table: Some(admin::Table {
                column_families: families,
                ..Default::default()
            }),
            ..Default::default()
        };
        match client
            .create_table(authorized(create, auth.as_deref(), &params).await?)
            .await
        {
            Err(s) if s.code() != Code::AlreadyExists => Err(s.into()),
            _ => Ok(()),
        }
    }

    // -- primitives ---------------------------------------------------------

    /// Apply `mutations` to one row, atomically.
    async fn mutate(&self, key: &str, mutations: Vec<bt::Mutation>) -> Result<()> {
        let req = bt::MutateRowRequest {
            table_name: self.table.clone(),
            app_profile_id: self.app_profile.clone(),
            row_key: key.as_bytes().to_vec(),
            mutations,
            ..Default::default()
        };
        self.client
            .clone()
            .mutate_row(self.request(req).await?)
            .await?;
        Ok(())
    }

    /// Write cells to one row at the current time.
    async fn put(&self, key: &str, family: &str, cols: &[(&str, &[u8])]) -> Result<()> {
        let now = now_ms();
        let cells = cols.iter().map(|(c, v)| set_cell(family, c, *v, now));
        self.mutate(key, cells.collect()).await
    }

    /// Delete a row. Deleting a missing row is not an error.
    async fn delete(&self, key: &str) -> Result<()> {
        self.mutate(key, vec![delete_row()]).await
    }

    /// Read rows, merging `CellChunk`s into whole rows.
    async fn read(&self, rows: bt::RowSet) -> Result<Vec<(String, Row)>> {
        let req = bt::ReadRowsRequest {
            table_name: self.table.clone(),
            app_profile_id: self.app_profile.clone(),
            rows: Some(rows),
            filter: Some(filter(Filter::CellsPerColumnLimitFilter(1))),
            ..Default::default()
        };
        let mut stream = self
            .client
            .clone()
            .read_rows(self.request(req).await?)
            .await?
            .into_inner();
        let mut out = Vec::new();
        // Row key and qualifier are reused from earlier chunks when omitted,
        // and a value split over several chunks is concatenated until a chunk
        // arrives with `value_size == 0`.
        let (mut key, mut qualifier) = (Vec::new(), Vec::new());
        let (mut row, mut value) = (Row::new(), Vec::new());
        while let Some(resp) = stream.message().await? {
            for chunk in resp.chunks {
                if chunk.row_status == Some(RowStatus::ResetRow(true)) {
                    row.clear();
                    value.clear();
                    continue;
                }
                if !chunk.row_key.is_empty() {
                    key = chunk.row_key;
                }
                if let Some(q) = chunk.qualifier {
                    qualifier = q;
                }
                value.extend_from_slice(&chunk.value);
                if chunk.value_size == 0 {
                    row.insert(qualifier.clone(), std::mem::take(&mut value));
                }
                if chunk.row_status == Some(RowStatus::CommitRow(true)) {
                    let k = String::from_utf8(key.clone())?;
                    out.push((k, std::mem::take(&mut row)));
                }
            }
        }
        Ok(out)
    }

    /// Read one row.
    async fn get(&self, key: &str) -> Result<Option<Row>> {
        let rows = bt::RowSet {
            row_keys: vec![key.as_bytes().to_vec()],
            row_ranges: vec![],
        };
        Ok(self.read(rows).await?.pop().map(|(_, row)| row))
    }

    /// Whether a row exists.
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.get(key).await?.is_some())
    }

    /// Apply `mutations` to row `key` only if `predicate` matches a cell in
    /// it, atomically. Returns whether it matched.
    async fn mutate_if(
        &self,
        key: &str,
        predicate: bt::RowFilter,
        mutations: Vec<bt::Mutation>,
    ) -> Result<bool> {
        let req = bt::CheckAndMutateRowRequest {
            table_name: self.table.clone(),
            app_profile_id: self.app_profile.clone(),
            row_key: key.as_bytes().to_vec(),
            predicate_filter: Some(predicate),
            true_mutations: mutations,
            ..Default::default()
        };
        let resp = self
            .client
            .clone()
            .check_and_mutate_row(self.request(req).await?)
            .await?;
        Ok(resp.into_inner().predicate_matched)
    }

    /// Delete the message row `key` only if it still holds message `id`.
    /// Returns whether it did.
    async fn delete_message_row(&self, key: &str, id: &str) -> Result<bool> {
        let predicate = column_filter(M, "id", Some(id));
        self.mutate_if(key, predicate, vec![delete_row()]).await
    }

    /// Resolve a message id to its row key and current contents. `None` if
    /// unknown or replaced.
    async fn locate(&self, id: &str) -> Result<Option<(String, Message)>> {
        let Some(idx) = self.get(&format!("mid#{id}")).await? else {
            return Ok(None);
        };
        let Some(key) = text(&idx, "row") else {
            return Ok(None);
        };
        let Some(row) = self.get(&key).await? else {
            return Ok(None);
        };
        Ok(message_from_row(&key, &row)
            .filter(|m| m.id == id)
            .map(|m| (key, m)))
    }

    /// Delete a message that is still stored under `key`, with its index.
    /// Returns whether it was still there.
    async fn remove_message(&self, key: &str, m: &Message) -> Result<bool> {
        if !self.delete_message_row(key, &m.id).await? {
            return Ok(false);
        }
        self.delete(&format!("mid#{}", m.id)).await?;
        Ok(true)
    }

    /// Queue a 410 receipt for `m` if it requested one.
    async fn owe_410(&self, m: &Message) -> Result<Option<(u64, Receipt)>> {
        let Some(rsub) = &m.rsub else { return Ok(None) };
        let r = Receipt {
            rsub: rsub.clone(),
            msg_id: m.id.clone(),
            status: 410,
        };
        Ok(self.enqueue_receipt(&r).await?.map(|seq| (seq, r)))
    }
}

impl Store for BigtableStore {
    async fn create_user_agent(&self, ua: &UserAgent) -> Result<()> {
        let seen = ua.last_seen.to_string();
        let mut cols: Vec<(&str, &[u8])> = vec![("seen", seen.as_bytes())];
        if let Some(b) = &ua.bridge {
            cols.extend([
                ("bridge", b.bridge.as_bytes()),
                ("app", b.app_id.as_bytes()),
                ("token", b.token.as_bytes()),
            ]);
        }
        self.put(&format!("ua#{}", ua.uaid), D, &cols).await
    }

    async fn user_agent(&self, uaid: &str) -> Result<Option<UserAgent>> {
        let row = self.get(&format!("ua#{uaid}")).await?;
        Ok(row.map(|row| user_agent_from_row(uaid, &row)))
    }

    async fn touch_user_agent(&self, uaid: &str, now: u64) -> Result<bool> {
        let set = set_cell(D, "seen", now.to_string(), now_ms());
        let exists = column_filter(D, "seen", None);
        self.mutate_if(&format!("ua#{uaid}"), exists, vec![set])
            .await
    }

    async fn update_bridge_token(&self, uaid: &str, token: &str) -> Result<bool> {
        let set = set_cell(D, "token", token.as_bytes(), now_ms());
        let bridged = column_filter(D, "bridge", None);
        self.mutate_if(&format!("ua#{uaid}"), bridged, vec![set])
            .await
    }

    async fn delete_user_agent(&self, uaid: &str) -> Result<Vec<(u64, Receipt)>> {
        let mut receipts = Vec::new();
        for (key, _) in self.read(prefix(format!("ch#{uaid}#"))).await? {
            if let Some(ch) = key.rsplit('#').next() {
                receipts.extend(self.delete_subscription(uaid, ch).await?);
            }
        }
        self.delete(&format!("ua#{uaid}")).await?;
        Ok(receipts)
    }

    async fn expire_user_agents(&self, cutoff: u64) -> Result<(usize, Vec<(u64, Receipt)>)> {
        // A full scan of the user agent rows. Run it rarely; see the
        // `user_agents.expire_after` setting of the server.
        let mut deleted = 0;
        let mut receipts = Vec::new();
        for (key, row) in self.read(prefix("ua#".to_owned())).await? {
            let Some(uaid) = key.strip_prefix("ua#") else {
                continue;
            };
            if user_agent_from_row(uaid, &row).last_seen < cutoff {
                receipts.extend(self.delete_user_agent(uaid).await?);
                deleted += 1;
            }
        }
        Ok((deleted, receipts))
    }

    async fn subscriptions(&self, uaid: &str) -> Result<Vec<Subscription>> {
        let mut out = Vec::new();
        for (key, row) in self.read(prefix(format!("ch#{uaid}#"))).await? {
            let (Some(ch), Some(push)) = (key.rsplit('#').next(), text(&row, "push")) else {
                continue;
            };
            out.push(Subscription {
                uaid: uaid.to_owned(),
                channel_id: ch.to_owned(),
                push,
                vapid: row
                    .get(&b"vapid"[..])
                    .and_then(|v| v.as_slice().try_into().ok()),
            });
        }
        Ok(out)
    }

    async fn channel(&self, uaid: &str, channel_id: &str) -> Result<Option<Subscription>> {
        let Some(row) = self.get(&format!("ch#{uaid}#{channel_id}")).await? else {
            return Ok(None);
        };
        Ok(Some(Subscription {
            uaid: uaid.to_owned(),
            channel_id: channel_id.to_owned(),
            push: text(&row, "push").ok_or("channel row without push")?,
            vapid: row
                .get(&b"vapid"[..])
                .and_then(|v| v.as_slice().try_into().ok()),
        }))
    }

    async fn create_subscription(
        &self,
        uaid: &str,
        channel_id: &str,
        vapid: Option<[u8; 65]>,
    ) -> Result<Subscription> {
        let sub = Subscription {
            uaid: uaid.to_owned(),
            channel_id: channel_id.to_owned(),
            push: new_id(),
            vapid,
        };
        let mut cols = vec![("push", sub.push.as_bytes())];
        if let Some(key) = &sub.vapid {
            cols.push(("vapid", key));
        }
        self.put(&format!("ch#{uaid}#{channel_id}"), D, &cols)
            .await?;
        let index: [(&str, &[u8]); 2] = [("uaid", uaid.as_bytes()), ("ch", channel_id.as_bytes())];
        self.put(&format!("push#{}", sub.push), D, &index).await?;
        Ok(sub)
    }

    async fn subscription_by_push(&self, push: &str) -> Result<Option<Subscription>> {
        let Some(row) = self.get(&format!("push#{push}")).await? else {
            return Ok(None);
        };
        let (Some(uaid), Some(ch)) = (text(&row, "uaid"), text(&row, "ch")) else {
            return Ok(None);
        };
        // The channel row is authoritative; a push row without one is an
        // orphan left by an interrupted delete.
        Ok(self.channel(&uaid, &ch).await?.filter(|s| s.push == push))
    }

    async fn delete_subscription(
        &self,
        uaid: &str,
        channel_id: &str,
    ) -> Result<Vec<(u64, Receipt)>> {
        let Some(sub) = self.channel(uaid, channel_id).await? else {
            return Ok(vec![]);
        };
        let mut receipts = Vec::new();
        for (key, row) in self.read(prefix(format!("msg#{uaid}#"))).await? {
            let Some(m) = message_from_row(&key, &row) else {
                continue;
            };
            if m.channel_id == channel_id && self.remove_message(&key, &m).await? {
                receipts.extend(self.owe_410(&m).await?);
            }
        }
        self.delete(&format!("ch#{uaid}#{channel_id}")).await?;
        self.delete(&format!("push#{}", sub.push)).await?;
        Ok(receipts)
    }

    async fn insert_message(&self, m: &Message) -> Result<()> {
        let key = message_key(m);
        let ts = m.accepted;
        let num = |n: u64| n.to_string().into_bytes();
        // Clear the row first so a replacement never inherits columns, such
        // as `rsub`, that it does not set itself.
        let mut mutations = vec![
            delete_row(),
            set_cell(M, "id", m.id.as_bytes(), ts),
            set_cell(M, "ch", m.channel_id.as_bytes(), ts),
            set_cell(M, "push", m.push.as_bytes(), ts),
            set_cell(M, "body", m.body.to_vec(), ts),
            set_cell(M, "ttl", num(m.ttl.into()), ts),
            set_cell(M, "urgency", m.urgency.as_str(), ts),
            set_cell(M, "accepted", num(m.accepted), ts),
            set_cell(M, "expiry", num(m.expiry), ts),
        ];
        for (col, value) in [("ctype", &m.ctype), ("cenc", &m.cenc), ("rsub", &m.rsub)] {
            if let Some(v) = value {
                mutations.push(set_cell(M, col, v.as_bytes(), ts));
            }
        }
        self.mutate(&key, mutations).await?;
        self.mutate(
            &format!("mid#{}", m.id),
            vec![set_cell(M, "row", key.as_bytes(), ts)],
        )
        .await?;
        if m.rsub.is_some() {
            let idx = format!("rexp#{:016x}#{}", m.expiry, m.id);
            self.put(&idx, D, &[("row", key.as_bytes())]).await?;
        }
        Ok(())
    }

    async fn pending(&self, uaid: &str, now: u64, limit: usize) -> Result<Vec<Message>> {
        // Topic rows sort by topic, not by time, so the whole prefix is read
        // and ordered here before the limit applies.
        let rows = self.read(prefix(format!("msg#{uaid}#"))).await?;
        let mut out: Vec<Message> = rows
            .iter()
            .filter_map(|(key, row)| message_from_row(key, row))
            .filter(|m| m.expiry > now)
            .collect();
        out.sort_by(|a, b| (a.accepted, &a.id).cmp(&(b.accepted, &b.id)));
        out.truncate(limit);
        Ok(out)
    }

    async fn message(&self, id: &str) -> Result<Option<Message>> {
        Ok(self.locate(id).await?.map(|(_, m)| m))
    }

    async fn delete_message(
        &self,
        id: &str,
        owner: Option<(&str, &str)>,
    ) -> Result<Option<Message>> {
        let Some((key, m)) = self.locate(id).await? else {
            return Ok(None);
        };
        if owner.is_some_and(|(uaid, ch)| m.uaid != uaid || m.channel_id != ch) {
            return Ok(None);
        }
        Ok(self.remove_message(&key, &m).await?.then_some(m))
    }

    async fn create_receipt_sub(&self) -> Result<String> {
        let rsub = new_id();
        self.put(&format!("rsub#{rsub}"), D, &[("c", b"1")]).await?;
        Ok(rsub)
    }

    async fn receipt_sub_exists(&self, rsub: &str) -> Result<bool> {
        self.exists(&format!("rsub#{rsub}")).await
    }

    async fn delete_receipt_sub(&self, rsub: &str) -> Result<bool> {
        if !self.receipt_sub_exists(rsub).await? {
            return Ok(false);
        }
        self.delete(&format!("rsub#{rsub}")).await?;
        for (key, _) in self.read(prefix(format!("rq#{rsub}#"))).await? {
            self.delete(&key).await?;
        }
        Ok(true)
    }

    async fn enqueue_receipt(&self, r: &Receipt) -> Result<Option<u64>> {
        if !self.receipt_sub_exists(&r.rsub).await? {
            return Ok(None);
        }
        let seq = next_seq();
        let key = format!("rq#{}#{seq:016x}", r.rsub);
        let status = r.status.to_string();
        let cols: [(&str, &[u8]); 2] =
            [("msg", r.msg_id.as_bytes()), ("status", status.as_bytes())];
        self.put(&key, D, &cols).await?;
        Ok(Some(seq))
    }

    async fn queued_receipts(&self, rsub: &str) -> Result<Vec<(u64, Receipt)>> {
        let rows = self.read(prefix(format!("rq#{rsub}#"))).await?;
        Ok(rows
            .iter()
            .filter_map(|(key, row)| {
                let seq = u64::from_str_radix(key.rsplit('#').next()?, 16).ok()?;
                let receipt = Receipt {
                    rsub: rsub.to_owned(),
                    msg_id: text(row, "msg")?,
                    status: number(row, "status")?.try_into().ok()?,
                };
                Some((seq, receipt))
            })
            .collect())
    }

    async fn delete_receipt(&self, rsub: &str, seq: u64) -> Result<()> {
        self.delete(&format!("rq#{rsub}#{seq:016x}")).await
    }

    async fn reap(&self, now: u64) -> Result<Vec<(u64, Receipt)>> {
        // Messages without receipts are left to Bigtable garbage collection.
        let due = range("rexp#".to_owned(), format!("rexp#{:016x}", now + 1));
        let mut receipts = Vec::new();
        for (idx, row) in self.read(due).await? {
            let id = idx.rsplit('#').next().unwrap_or_default();
            if let Some(key) = text(&row, "row")
                && let Some(mrow) = self.get(&key).await?
                && let Some(m) = message_from_row(&key, &mrow)
                && m.id == id
                && self.remove_message(&key, &m).await?
            {
                receipts.extend(self.owe_410(&m).await?);
            }
            self.delete(&idx).await?;
        }
        Ok(receipts)
    }

    async fn set_route(&self, to: &Recipient, node: &str) -> Result<Option<String>> {
        let key = route_key(to);
        let previous = self.get(&key).await?.and_then(|row| text(&row, "node"));
        self.put(&key, D, &[("node", node.as_bytes())]).await?;
        Ok(previous)
    }

    async fn route(&self, to: &Recipient) -> Result<Option<String>> {
        Ok(self
            .get(&route_key(to))
            .await?
            .and_then(|row| text(&row, "node")))
    }

    async fn clear_route(&self, to: &Recipient, node: &str) -> Result<bool> {
        let predicate = column_filter(D, "node", Some(node));
        self.mutate_if(&route_key(to), predicate, vec![delete_row()])
            .await
    }
}
