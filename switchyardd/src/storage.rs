use chrono::{DateTime, Utc};
use relay_core::{Endpoint, Envelope};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use uuid::Uuid;

pub struct Store {
    conn: Connection,
}

/// `(node_id, level, first_seen, updated_at)` -- `Store::list_trust`'s row
/// shape (design §3), named so the return type reads cleanly rather than a
/// four-tuple spelled out inline (clippy::type_complexity).
pub type TrustRow = (String, String, DateTime<Utc>, DateTime<Utc>);

/// `(node_id, advert_cbor, received_at)` -- `Store::list_peer_adverts`'s
/// row shape (design §3, cycle G), named for the same `clippy::
/// type_complexity` reason `TrustRow` above is.
pub type PeerAdvertRow = (String, Vec<u8>, DateTime<Utc>);

#[derive(Debug, Clone)]
pub struct Delivery {
    pub id: i64,
    pub message_id: Uuid,
    pub route: String,
    pub destination: Endpoint,
    pub priority: u8,
    pub attempt_count: u32,
    pub state: String,
    pub reason: Option<String>,
    pub next_attempt: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// When this row was inserted (`insert_delivery`/`insert_dead_delivery`).
    /// Backs `GET /v1/queue?state=` (Finding 2, whole-branch review) —
    /// stamped once, at insert, and never touched again.
    pub created_at: DateTime<Utc>,
    /// When this row's `state`/`reason`/`attempt_count` was last written
    /// (every `mark_*` transition below, plus insert). Also backs `GET
    /// /v1/queue?state=`.
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct Challenge {
    pub id: i64,
    // Deliberately unread outside the SQL match in find_active_challenge:
    // codes must never be exposed anywhere in engine.rs or an API response
    // (design §Security invariants) — the field exists for round-tripping,
    // not for a caller to read back.
    #[allow(dead_code)]
    pub code: String,
    pub target_protocol: String,
    pub target_ref: String,
    pub requester_protocol: String,
    pub requester_ref: String,
    pub display_name: String,
    // GET /v1/identities/challenges (Task 4) surfaces expiry only, per the
    // design's exact interface ("masked targets + expiry, NEVER codes") —
    // created_at has no consumer yet.
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Finding 3 (whole-branch review): a derived `Debug` would render `code`
/// verbatim, so any future `{:?}` in a log line (or a debug-formatted panic
/// message, `dbg!`, etc.) would leak it — codes must never be exposed
/// anywhere outside the challenge lifecycle (design §Security invariants).
/// This manual impl keeps every other field visible for diagnosability and
/// redacts only `code`.
impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Challenge")
            .field("id", &self.id)
            .field("code", &"<redacted>")
            .field("target_protocol", &self.target_protocol)
            .field("target_ref", &self.target_ref)
            .field("requester_protocol", &self.requester_protocol)
            .field("requester_ref", &self.requester_ref)
            .field("display_name", &self.display_name)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct Link {
    pub id: i64,
    pub a_protocol: String,
    pub a_ref: String,
    pub b_protocol: String,
    pub b_ref: String,
    pub display_name: String,
    pub verified_at: DateTime<Utc>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  envelope TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL REFERENCES messages(id),
  route TEXT NOT NULL,
  dest_protocol TEXT NOT NULL,
  dest_endpoint TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 2,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  next_attempt TEXT NOT NULL,
  attempted_at TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(state, priority, next_attempt);
CREATE TABLE IF NOT EXISTS message_attachments (
  message_id TEXT NOT NULL,
  sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_attachments_message_id
  ON message_attachments(message_id);
CREATE TABLE IF NOT EXISTS identity_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  a_protocol TEXT NOT NULL, a_ref TEXT NOT NULL,
  b_protocol TEXT NOT NULL, b_ref TEXT NOT NULL,
  display_name TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  UNIQUE(a_protocol, a_ref, b_protocol, b_ref)
);
CREATE TABLE IF NOT EXISTS link_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL,
  target_protocol TEXT NOT NULL, target_ref TEXT NOT NULL,
  requester_protocol TEXT NOT NULL, requester_ref TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_trust (
  node_id TEXT PRIMARY KEY,
  level TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peer_adverts (
  node_id TEXT PRIMARY KEY,
  advert_cbor BLOB NOT NULL,
  name TEXT NOT NULL,
  expires TEXT NOT NULL,
  received_at TEXT NOT NULL
);
";

/// Brings a pre-Task-4 database (created before `deliveries.priority`
/// existed) up to the current schema. `SCHEMA`'s `CREATE TABLE/INDEX IF NOT
/// EXISTS` above is a no-op against an existing `deliveries` table — it
/// never adds columns to a table that's already there — so a v0.1-era DB
/// opened by this build would otherwise be missing the column entirely and
/// every query below referencing it would fail at first use. Guarded by a
/// `pragma_table_info` check (rather than trying the `ALTER TABLE`
/// unconditionally and swallowing a "duplicate column" error) so this is
/// also a safe, idempotent no-op on every subsequent open of an
/// already-migrated DB, fresh or upgraded.
fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let has_priority: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('deliveries') WHERE name = 'priority'",
        [],
        |row| row.get(0),
    )?;
    if has_priority == 0 {
        conn.execute_batch(
            "ALTER TABLE deliveries ADD COLUMN priority INTEGER NOT NULL DEFAULT 2;
             DROP INDEX IF EXISTS idx_deliveries_due;
             CREATE INDEX idx_deliveries_due ON deliveries(state, priority, next_attempt);",
        )?;
    }
    // Finding 2 (whole-branch review): `GET /v1/queue?state=` needs
    // per-row created_at/updated_at, added to `deliveries` after v0.1. A
    // pre-existing row has no honest creation timestamp on hand, so it's
    // backfilled from `next_attempt` -- exactly what every INSERT before
    // this migration stamped it with at creation, before any retry ever had
    // a chance to push it forward (see `insert_delivery`'s callers, which
    // all pass "now" for a fresh row's `next_attempt`). Not perfectly
    // accurate for a row that had already retried once by the time this
    // migration ran, but far closer than leaving the column empty.
    let has_created_at: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('deliveries') WHERE name = 'created_at'",
        [],
        |row| row.get(0),
    )?;
    if has_created_at == 0 {
        conn.execute_batch(
            "ALTER TABLE deliveries ADD COLUMN created_at TEXT NOT NULL DEFAULT '';
             ALTER TABLE deliveries ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
             UPDATE deliveries SET created_at = next_attempt, updated_at = next_attempt
               WHERE created_at = '';",
        )?;
    }
    Ok(())
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    match DateTime::parse_from_rfc3339(s) {
        Ok(t) => t.with_timezone(&Utc),
        Err(e) => {
            // A corrupt/empty stored timestamp must not silently become the
            // epoch: as an `expires_at` that drops the message as "expired",
            // as a `next_attempt` that marks it perpetually due. Surface the
            // corruption and fall back to now -- the least-harmful generic
            // default across the fields this parses.
            tracing::warn!(value = %s, error = %e, "corrupt timestamp in storage row; defaulting to now");
            Utc::now()
        }
    }
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Store { conn })
    }

    pub fn insert_message(&self, env: &Envelope) -> rusqlite::Result<()> {
        let json = serde_json::to_string(env).expect("envelope serializes");
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (id, envelope, created_at) VALUES (?1, ?2, ?3)",
            params![env.id.to_string(), json, ts(env.created_at)],
        )?;
        Ok(())
    }

    /// Records which content-addressed blobs a message references, so that
    /// `purge_terminal` can later tell which shas are still live (referenced
    /// by a surviving message) versus orphaned (safe to delete from the CAS).
    pub fn insert_attachment_refs(
        &self,
        message_id: Uuid,
        shas: &[String],
    ) -> rusqlite::Result<()> {
        for sha in shas {
            self.conn.execute(
                "INSERT INTO message_attachments (message_id, sha256) VALUES (?1, ?2)",
                params![message_id.to_string(), sha],
            )?;
        }
        Ok(())
    }

    pub fn get_message(&self, id: Uuid) -> rusqlite::Result<Option<Envelope>> {
        let mut stmt = self
            .conn
            .prepare("SELECT envelope FROM messages WHERE id = ?1")?;
        let mut rows = stmt.query(params![id.to_string()])?;
        match rows.next()? {
            Some(row) => {
                let json: String = row.get(0)?;
                Ok(serde_json::from_str(&json).ok())
            }
            None => Ok(None),
        }
    }

    /// `priority` is the numeric rank (0=emergency..4=background) computed
    /// by `relay_core::priority_rank` from the envelope's priority class —
    /// callers pass the already-resolved rank, not a class name, so this
    /// module has no dependency on the class-name-to-rank mapping.
    pub fn insert_delivery(
        &self,
        message_id: Uuid,
        route: &str,
        dest: &Endpoint,
        next_attempt: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        priority: u8,
    ) -> rusqlite::Result<i64> {
        let now = ts(Utc::now());
        self.conn.execute(
            "INSERT INTO deliveries
               (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at, priority,
                created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                message_id.to_string(),
                route,
                dest.protocol,
                dest.endpoint,
                ts(next_attempt),
                ts(expires_at),
                priority,
                now
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Inserts a delivery that lands directly in `dead_letter` with `reason`,
    /// skipping `pending` entirely — the quota-rejection path (spec §45): a
    /// message over a queue cap never gets a live delivery attempt, but it
    /// still gets a row, so it's visible in `queue_counts`/admin status
    /// exactly like any other dead-lettered delivery instead of vanishing.
    pub fn insert_dead_delivery(
        &self,
        message_id: Uuid,
        route: &str,
        dest: &Endpoint,
        next_attempt: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        reason: &str,
    ) -> rusqlite::Result<i64> {
        let now = ts(Utc::now());
        self.conn.execute(
            "INSERT INTO deliveries
               (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at,
                state, reason, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'dead_letter', ?7, ?8, ?8)",
            params![
                message_id.to_string(),
                route,
                dest.protocol,
                dest.endpoint,
                ts(next_attempt),
                ts(expires_at),
                reason,
                now
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Count of deliveries still in flight (`pending` or `attempting`),
    /// optionally scoped to one `route`. Used to enforce `limits.per_route`
    /// and `limits.global` queue caps (spec §45) before a new delivery is
    /// admitted.
    pub fn pending_count(&self, route: Option<&str>) -> rusqlite::Result<i64> {
        match route {
            Some(r) => self.conn.query_row(
                "SELECT COUNT(*) FROM deliveries
                 WHERE route = ?1 AND state IN ('pending', 'attempting')",
                params![r],
                |row| row.get(0),
            ),
            None => self.conn.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE state IN ('pending', 'attempting')",
                [],
                |row| row.get(0),
            ),
        }
    }

    fn delivery_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Delivery> {
        Ok(Delivery {
            id: row.get(0)?,
            message_id: row.get::<_, String>(1)?.parse().unwrap_or_default(),
            route: row.get(2)?,
            destination: Endpoint {
                protocol: row.get(3)?,
                endpoint: row.get(4)?,
            },
            priority: row.get(5)?,
            attempt_count: row.get(6)?,
            state: row.get(7)?,
            reason: row.get(8)?,
            next_attempt: parse_ts(&row.get::<_, String>(9)?),
            expires_at: parse_ts(&row.get::<_, String>(10)?),
            created_at: parse_ts(&row.get::<_, String>(11)?),
            updated_at: parse_ts(&row.get::<_, String>(12)?),
        })
    }

    const DELIVERY_COLS: &'static str =
        "id, message_id, route, dest_protocol, dest_endpoint, priority, attempt_count,
         state, reason, next_attempt, expires_at, created_at, updated_at";

    /// Priority first (0=emergency ahead of 4=background), next_attempt as
    /// the tiebreaker within the same priority tier — spec §39's "low
    /// bandwidth plugins MAY use priority to determine queue ordering",
    /// applied unconditionally here since the scheduler has no per-plugin
    /// opt-out.
    pub fn due_deliveries(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> rusqlite::Result<Vec<Delivery>> {
        let sql = format!(
            "SELECT {} FROM deliveries
             WHERE state = 'pending' AND next_attempt <= ?1
             ORDER BY priority ASC, next_attempt ASC LIMIT ?2",
            Self::DELIVERY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![ts(now), limit as i64], Self::delivery_from_row)?;
        rows.collect()
    }

    pub fn mark_attempting(&self, id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'attempting',
                attempt_count = attempt_count + 1, attempted_at = ?2, updated_at = ?2
             WHERE id = ?1",
            params![id, ts(Utc::now())],
        )?;
        Ok(())
    }

    /// Guarded to only fire from 'attempting': a delivery only ever reaches
    /// 'delivered' after `mark_attempting` put it there for a Send in
    /// flight. Without this guard a late/duplicate DeliveryResult (e.g. a
    /// stray plugin ack that arrives after `reclaim_stale` or a retry has
    /// already moved the row on) could flip an already-terminal or
    /// not-yet-attempted row straight to 'delivered', producing a
    /// duplicate-looking or premature delivery. The invariant this and the
    /// other `mark_*` guards enforce: once a row lands in a terminal state
    /// ('delivered', 'failed', 'expired', 'dead_letter') it is never
    /// modified again.
    pub fn mark_delivered(&self, id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'delivered', updated_at = ?2
             WHERE id = ?1 AND state = 'attempting'",
            params![id, ts(Utc::now())],
        )?;
        Ok(())
    }

    /// Guarded to 'pending' or 'attempting': called both before
    /// `mark_attempting` runs (the plugin-offline nudge in `process_due`,
    /// row still 'pending') and after it (the try_send-full backpressure
    /// path and delivery-failed retries in `handle_result`, row
    /// 'attempting'). Either way, a row already in a terminal state must not
    /// be reopened by a late retry signal.
    pub fn mark_retry(&self, id: i64, next_attempt: DateTime<Utc>) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending', next_attempt = ?2, updated_at = ?3
             WHERE id = ?1 AND state IN ('pending', 'attempting')",
            params![id, ts(next_attempt), ts(Utc::now())],
        )?;
        Ok(())
    }

    /// Guarded to 'pending' or 'attempting' for the same reason as
    /// `mark_retry`: called on fresh 'pending' rows (TTL expiry, policy
    /// denial, missing-message) as well as 'attempting' rows (retry
    /// exhaustion in `handle_result`), but never on a row already terminal.
    pub fn mark_terminal(&self, id: i64, state: &str, reason: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = ?2, reason = ?3, updated_at = ?4
             WHERE id = ?1 AND state IN ('pending', 'attempting')",
            params![id, state, reason, ts(Utc::now())],
        )?;
        Ok(())
    }

    /// Deletes terminal deliveries (spec §45 disk limits) that reached their
    /// terminal state before `older_than`, plus any message left with no
    /// deliveries at all as a result. `next_attempt` is used as the recency
    /// signal rather than `attempted_at`: every terminal row has a
    /// `next_attempt` (it's NOT NULL from insert), whereas `attempted_at` is
    /// only ever set by `mark_attempting` and stays NULL for rows that went
    /// straight to a terminal state without an attempt (e.g. TTL_EXPIRED,
    /// POLICY_DENIED, DESTINATION_UNKNOWN), which would otherwise never be
    /// purged.
    ///
    /// Also GCs `message_attachments`: any row whose `message_id` no longer
    /// exists in `messages` (i.e. the message was just purged above, or had
    /// no deliveries at all) is deleted. The *distinct* shas that are truly
    /// unreferenced — no surviving message has a ref row for them, even if
    /// some *other*, now-dead message shared the same sha (e.g. the same
    /// file forwarded into two separate messages) — are returned so the
    /// caller (the pump) can remove the now-unreferenced blobs from the CAS.
    /// This is a `GROUP BY sha256` / `HAVING` check rather than a per-row
    /// `NOT IN`: a naive per-row anti-join would report a sha as orphaned
    /// the moment *any one* of its referencing messages was purged, even
    /// while another message sharing that same sha is still alive — which
    /// would have the pump delete a blob a live message still depends on.
    pub fn purge_terminal(
        &self,
        older_than: DateTime<Utc>,
    ) -> rusqlite::Result<(usize, Vec<String>)> {
        let deleted = self.conn.execute(
            "DELETE FROM deliveries
             WHERE state IN ('delivered','failed','expired','dead_letter')
               AND next_attempt < ?1",
            params![ts(older_than)],
        )?;
        let orphans = self.prune_orphans()?;
        Ok((deleted, orphans))
    }

    /// After deliveries are deleted, drop now-unreferenced messages, collect
    /// the CAS shas that no surviving message references (for the caller to
    /// unlink under the store lock -- see the pump), and drop dangling
    /// attachment rows. Shared by `purge_terminal` and `purge_dead_letters`.
    fn prune_orphans(&self) -> rusqlite::Result<Vec<String>> {
        self.conn.execute(
            "DELETE FROM messages WHERE id NOT IN (SELECT DISTINCT message_id FROM deliveries)",
            [],
        )?;
        let orphans: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT sha256 FROM message_attachments
                 GROUP BY sha256
                 HAVING SUM(CASE WHEN message_id IN (SELECT id FROM messages)
                                 THEN 1 ELSE 0 END) = 0",
            )?;
            let rows = stmt
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            rows
        };
        self.conn.execute(
            "DELETE FROM message_attachments WHERE message_id NOT IN (SELECT id FROM messages)",
            [],
        )?;
        Ok(orphans)
    }

    /// Requeue a terminal delivery (dead_letter/failed/expired) for another
    /// attempt: back to pending, due now, with attempt_count reset so the
    /// retry-exhaustion cap doesn't immediately re-terminate it. Returns
    /// whether a row moved (false = no such id, or not in a requeuable state).
    pub fn requeue(&self, id: i64) -> rusqlite::Result<bool> {
        let now = ts(Utc::now());
        let n = self.conn.execute(
            "UPDATE deliveries SET state = 'pending', next_attempt = ?2, attempt_count = 0,
                 reason = NULL, updated_at = ?2
             WHERE id = ?1 AND state IN ('dead_letter','failed','expired')",
            params![id, now],
        )?;
        Ok(n > 0)
    }

    /// Purge ALL dead-lettered deliveries regardless of age (operator DLQ
    /// cleanup), plus any now-orphaned messages/attachments. Returns the
    /// number of rows deleted and the orphaned CAS shas to unlink.
    pub fn purge_dead_letters(&self) -> rusqlite::Result<(usize, Vec<String>)> {
        let deleted = self
            .conn
            .execute("DELETE FROM deliveries WHERE state = 'dead_letter'", [])?;
        let orphans = self.prune_orphans()?;
        Ok((deleted, orphans))
    }

    pub fn recover(&self) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending' WHERE state = 'attempting'",
            [],
        )
    }

    pub fn reclaim_stale(&self, older_than: DateTime<Utc>) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending'
             WHERE state = 'attempting' AND attempted_at < ?1",
            params![ts(older_than)],
        )
    }

    pub fn queue_counts(&self) -> rusqlite::Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM deliveries GROUP BY state")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    pub fn deliveries_for(&self, message_id: Uuid) -> rusqlite::Result<Vec<Delivery>> {
        let sql = format!(
            "SELECT {} FROM deliveries WHERE message_id = ?1 ORDER BY id",
            Self::DELIVERY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![message_id.to_string()], Self::delivery_from_row)?;
        rows.collect()
    }

    /// Delivery rows for envelope `message_id` addressed to federation peer
    /// `peer_key` (design §5 egress: `dest_protocol = "fed"`, `dest_endpoint
    /// = "<peer_name>/<remote_route>"`) — resolves an inbound `Fed::Ack{id}`
    /// frame (which only ever carries the envelope id, never a delivery
    /// row id) back to the delivery row(s) it acknowledges. `peer_key` is
    /// whatever local identifier the connection that carried the Ack is
    /// registered under (`fed::conn::FedState.conns`'s key): for a
    /// connection to a CONFIGURED peer (dialed by us, or accepted from a
    /// node_id matching a configured peer) this is that peer's config
    /// `name`, matching the `dest_endpoint` prefix federation egress used
    /// when it sent the envelope in the first place; a connection from an
    /// unconfigured node is keyed by its raw `node_id` instead, which can
    /// never match a `dest_endpoint` prefix (egress destinations always
    /// name a configured peer, never a raw node_id) — an Ack arriving on
    /// such a connection therefore always resolves to zero rows, which is
    /// correct: this daemon could never have sent an envelope out through
    /// it under a `fed:<peer_name>/...` destination in the first place.
    /// The `LIKE ?2 || '/%'` match (rather than a bare prefix) deliberately
    /// requires the `/` separator, so a peer named `"phoen"` cannot match a
    /// delivery actually addressed to `"phoenix/regional-chat"`.
    pub fn deliveries_for_fed_ack(
        &self,
        message_id: Uuid,
        peer_key: &str,
    ) -> rusqlite::Result<Vec<Delivery>> {
        let sql = format!(
            "SELECT {} FROM deliveries
             WHERE message_id = ?1 AND dest_protocol = 'fed' AND dest_endpoint LIKE ?2 || '/%'",
            Self::DELIVERY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![message_id.to_string(), peer_key],
            Self::delivery_from_row,
        )?;
        rows.collect()
    }

    pub fn deliveries_for_id(&self, id: i64) -> Option<Delivery> {
        let sql = format!(
            "SELECT {} FROM deliveries WHERE id = ?1",
            Self::DELIVERY_COLS
        );
        self.conn
            .prepare(&sql)
            .ok()?
            .query_row(params![id], Self::delivery_from_row)
            .ok()
    }

    /// Backs `GET /v1/queue?state=` (Finding 2, whole-branch review): a
    /// straight `SELECT` on `deliveries` -- no join, every field the
    /// listing needs (`route`/`destination`/`state`/`reason`/`attempts`/
    /// `created_at`/`updated_at`) already lives on this one table. `state`
    /// optionally narrows to one literal `deliveries.state` value (the admin
    /// handler is the one that decides whether to pass it); `None` lists
    /// across every state. Newest first by `id` (monotonic autoincrement),
    /// not `created_at` -- a fan-out to several routes in one
    /// `handle_inbound` call stamps every row with the same wall-clock
    /// second, so `id` is the only tiebreaker precise enough for a stable
    /// ordering.
    pub fn list_deliveries(
        &self,
        state: Option<&str>,
        limit: i64,
    ) -> rusqlite::Result<Vec<Delivery>> {
        match state {
            Some(s) => {
                let sql = format!(
                    "SELECT {} FROM deliveries WHERE state = ?1 ORDER BY id DESC LIMIT ?2",
                    Self::DELIVERY_COLS
                );
                let mut stmt = self.conn.prepare(&sql)?;
                let rows = stmt.query_map(params![s, limit], Self::delivery_from_row)?;
                rows.collect()
            }
            None => {
                let sql = format!(
                    "SELECT {} FROM deliveries ORDER BY id DESC LIMIT ?1",
                    Self::DELIVERY_COLS
                );
                let mut stmt = self.conn.prepare(&sql)?;
                let rows = stmt.query_map(params![limit], Self::delivery_from_row)?;
                rows.collect()
            }
        }
    }

    /// Creates a new challenge. If a challenge already exists for this target,
    /// it is deleted first (single active challenge per target invariant).
    #[allow(clippy::too_many_arguments)] // interface per task brief
    pub fn create_challenge(
        &self,
        code: &str,
        target_protocol: &str,
        target_ref: &str,
        requester_protocol: &str,
        requester_ref: &str,
        display_name: &str,
        now: DateTime<Utc>,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<i64> {
        // Delete any existing challenge for this target first
        self.conn.execute(
            "DELETE FROM link_challenges WHERE target_protocol = ?1 AND target_ref = ?2",
            params![target_protocol, target_ref],
        )?;

        self.conn.execute(
            "INSERT INTO link_challenges
             (code, target_protocol, target_ref, requester_protocol, requester_ref, display_name, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![code, target_protocol, target_ref, requester_protocol, requester_ref, display_name, ts(now), ts(expires)],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Finds an active challenge matching the target and code.
    /// Returns None if no matching challenge exists, if it has expired,
    /// or if the code doesn't match.
    pub fn find_active_challenge(
        &self,
        target_protocol: &str,
        target_ref: &str,
        code: &str,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<Option<Challenge>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, code, target_protocol, target_ref, requester_protocol, requester_ref,
                    display_name, created_at, expires_at
             FROM link_challenges
             WHERE target_protocol = ?1 AND target_ref = ?2 AND code = ?3 AND expires_at > ?4",
        )?;
        let mut rows = stmt.query(params![target_protocol, target_ref, code, ts(now)])?;
        match rows.next()? {
            Some(row) => {
                let challenge = Challenge {
                    id: row.get(0)?,
                    code: row.get(1)?,
                    target_protocol: row.get(2)?,
                    target_ref: row.get(3)?,
                    requester_protocol: row.get(4)?,
                    requester_ref: row.get(5)?,
                    display_name: row.get(6)?,
                    created_at: parse_ts(&row.get::<_, String>(7)?),
                    expires_at: parse_ts(&row.get::<_, String>(8)?),
                };
                Ok(Some(challenge))
            }
            None => Ok(None),
        }
    }

    /// Deletes a challenge by id.
    pub fn delete_challenge(&self, id: i64) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM link_challenges WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Lists currently-active (non-expired) challenges, oldest first. Backs
    /// the admin API's `GET /v1/identities/challenges` (Task 4) — callers
    /// MUST mask `target_ref` before rendering, and MUST NOT surface `code`;
    /// it round-trips onto `Challenge` only for `find_active_challenge`'s SQL
    /// match, never for display (design §Security invariants).
    pub fn list_challenges(&self, now: DateTime<Utc>) -> rusqlite::Result<Vec<Challenge>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, code, target_protocol, target_ref, requester_protocol, requester_ref,
                    display_name, created_at, expires_at
             FROM link_challenges
             WHERE expires_at > ?1
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![ts(now)], |row| {
            Ok(Challenge {
                id: row.get(0)?,
                code: row.get(1)?,
                target_protocol: row.get(2)?,
                target_ref: row.get(3)?,
                requester_protocol: row.get(4)?,
                requester_ref: row.get(5)?,
                display_name: row.get(6)?,
                created_at: parse_ts(&row.get::<_, String>(7)?),
                expires_at: parse_ts(&row.get::<_, String>(8)?),
            })
        })?;
        rows.collect()
    }

    /// Inserts a new identity link. If a link with the same (a_protocol, a_ref, b_protocol, b_ref)
    /// already exists, the verified_at is updated to now. Returns the id of the inserted or updated row.
    pub fn insert_link(
        &self,
        a_protocol: &str,
        a_ref: &str,
        b_protocol: &str,
        b_ref: &str,
        display_name: &str,
        verified_at: DateTime<Utc>,
    ) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "INSERT INTO identity_links (a_protocol, a_ref, b_protocol, b_ref, display_name, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(a_protocol, a_ref, b_protocol, b_ref) DO UPDATE SET verified_at = ?6
             RETURNING id",
            params![a_protocol, a_ref, b_protocol, b_ref, display_name, ts(verified_at)],
            |row| row.get(0),
        )
    }

    /// Deletes a link by id. Returns true if a row was deleted, false otherwise.
    pub fn delete_link(&self, id: i64) -> rusqlite::Result<bool> {
        let rows_affected = self
            .conn
            .execute("DELETE FROM identity_links WHERE id = ?1", params![id])?;
        Ok(rows_affected > 0)
    }

    /// Finds a link by either side (a_protocol/a_ref OR b_protocol/b_ref).
    /// Returns the most-recently inserted/verified link (ORDER BY id DESC).
    pub fn link_for_identity(
        &self,
        protocol: &str,
        reference: &str,
    ) -> rusqlite::Result<Option<Link>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, a_protocol, a_ref, b_protocol, b_ref, display_name, verified_at
             FROM identity_links
             WHERE (a_protocol = ?1 AND a_ref = ?2) OR (b_protocol = ?1 AND b_ref = ?2)
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![protocol, reference])?;
        match rows.next()? {
            Some(row) => {
                let link = Link {
                    id: row.get(0)?,
                    a_protocol: row.get(1)?,
                    a_ref: row.get(2)?,
                    b_protocol: row.get(3)?,
                    b_ref: row.get(4)?,
                    display_name: row.get(5)?,
                    verified_at: parse_ts(&row.get::<_, String>(6)?),
                };
                Ok(Some(link))
            }
            None => Ok(None),
        }
    }

    /// Lists all identity links.
    pub fn list_links(&self) -> rusqlite::Result<Vec<Link>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, a_protocol, a_ref, b_protocol, b_ref, display_name, verified_at
             FROM identity_links ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Link {
                id: row.get(0)?,
                a_protocol: row.get(1)?,
                a_ref: row.get(2)?,
                b_protocol: row.get(3)?,
                b_ref: row.get(4)?,
                display_name: row.get(5)?,
                verified_at: parse_ts(&row.get::<_, String>(6)?),
            })
        })?;
        rows.collect()
    }

    /// Purges expired challenges (those where expires_at < now).
    /// Returns the number of rows deleted.
    pub fn purge_expired_challenges(&self, now: DateTime<Utc>) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM link_challenges WHERE expires_at < ?1",
            params![ts(now)],
        )
    }

    // ---- federation trust store (design §3, §112.7) ----------------------

    /// Current trust level for `node_id`, or `None` if the store has never
    /// seen or been told about it (§112.7's implicit `unknown`, which is
    /// never actually stored as a row -- there's nothing to record until a
    /// handshake or config seed happens).
    pub fn trust_level(&self, node_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT level FROM node_trust WHERE node_id = ?1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()
    }

    /// Records a successful handshake from a node the store has no prior
    /// entry for, at level `seen` (design §3: "a successful handshake from
    /// an unknown node records `seen`"). `INSERT OR IGNORE` -- if `node_id`
    /// already has ANY row (whether `seen` from an earlier handshake, or
    /// `verified`/`trusted`/`blocked` from config seeding), this is a no-op:
    /// discovery/handshake must NEVER raise trust beyond `seen` (§112.7
    /// MUST), and it must not touch a level that's already at or above it
    /// either.
    pub fn record_seen(&self, node_id: &str, now: DateTime<Utc>) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO node_trust (node_id, level, first_seen, updated_at)
             VALUES (?1, 'seen', ?2, ?2)",
            params![node_id, ts(now)],
        )?;
        Ok(())
    }

    /// Sets `node_id`'s trust level, config-wins semantics (design §3:
    /// `federation.peers[]`/`trusted`/`blocked` "wins over DB on load --
    /// re-seeded each boot"). Upserts via `ON CONFLICT DO UPDATE` rather
    /// than a literal `INSERT OR REPLACE` specifically so `first_seen`
    /// survives a level change on an existing row -- `INSERT OR REPLACE`
    /// deletes-then-reinserts the row, which would stamp `first_seen` to
    /// `now` on every boot instead of preserving when the node was truly
    /// first observed. `updated_at` always advances to `now`, on both the
    /// fresh-insert and the update path.
    pub fn seed_trust(
        &self,
        node_id: &str,
        level: &str,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        // Task 3 review carry-over (Important): guard the level param
        // against the 5 valid §112.7 levels — a typo'd/programmer-error
        // level string here would silently corrupt the trust store with a
        // value `trust_level`'s callers (the accept_from rank comparison,
        // the handshake blocked check) don't recognize, which is a
        // security-relevant fail-*open* if the comparison logic treats an
        // unrecognized string as passing. `debug_assert!` (not a hard
        // `Err`) because every current call site passes a value already
        // validated by `config::validate_federation` or a hardcoded
        // literal ("seen"/"trusted"/"blocked") — this is a debug-build
        // regression trip-wire for a future caller, not a runtime
        // condition production code is expected to hit.
        debug_assert!(
            matches!(
                level,
                "unknown" | "seen" | "verified" | "trusted" | "blocked"
            ),
            "seed_trust called with invalid trust level {level:?} (expected one of \
             unknown|seen|verified|trusted|blocked, design §112.7)"
        );
        self.conn.execute(
            "INSERT INTO node_trust (node_id, level, first_seen, updated_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(node_id) DO UPDATE SET level = excluded.level, updated_at = excluded.updated_at",
            params![node_id, level, ts(now)],
        )?;
        Ok(())
    }

    /// Lists every known node's trust record, node_id ascending (a stable,
    /// deterministic order for `GET /v1/federation`-style admin listings and
    /// tests, not any notion of recency).
    pub fn list_trust(&self) -> rusqlite::Result<Vec<TrustRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, level, first_seen, updated_at FROM node_trust ORDER BY node_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                parse_ts(&row.get::<_, String>(2)?),
                parse_ts(&row.get::<_, String>(3)?),
            ))
        })?;
        rows.collect()
    }

    /// Boot-time trust seeding (design §3): applies `federation.peers[]`
    /// (each at its own `trust` field, validated to `verified`|`trusted`),
    /// `federation.trusted` (⇒ `trusted`), and `federation.blocked` (⇒
    /// `blocked`) via `seed_trust`, in that order -- so a node_id listed in
    /// more than one place (e.g. a peer ALSO named in `blocked`, an
    /// operator's explicit override) resolves to the LAST list it appears
    /// in below, `blocked` always winning as the most restrictive outcome.
    /// Called once per config load/boot (Task 4/5 wire the call site); each
    /// call is idempotent and re-asserts config's view over whatever the DB
    /// currently holds for those node_ids, per `seed_trust`'s config-wins
    /// semantics.
    ///
    /// REVOCATION (final-review I-3): this function is AUTHORITATIVE for the
    /// config-derived levels (`verified`/`trusted`) -- before upserting the
    /// current config, any node_id still holding one of those levels that is
    /// no longer in `peers[]`/`trusted` is downgraded to `seen` (row kept,
    /// `first_seen` preserved, `updated_at` advanced). Without this pass, an
    /// operator deleting a peer from config would leave its durable
    /// `verified`/`trusted` row passing `fed_ingress`'s `accept_from` gate
    /// forever. Deliberately untouched: runtime-learned `seen` rows (not
    /// config-derived), and `blocked` rows (sticky by design -- unblocking
    /// is an explicit operator action, never an implicit config-diff side
    /// effect; a blocked node also removed from config stays blocked).
    /// Order matters: downgrade FIRST, then upsert -- so a node in the
    /// current config passes through with its configured level intact.
    pub fn seed_federation_trust(
        &self,
        fed: &crate::config::FederationConfig,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        let authorized: Vec<&str> = fed
            .peers
            .iter()
            .map(|p| p.node_id.as_str())
            .chain(fed.trusted.iter().map(|s| s.as_str()))
            .collect();
        let placeholders = (0..authorized.len())
            .map(|i| format!("?{}", i + 2))
            .collect::<Vec<_>>()
            .join(", ");
        self.conn.execute(
            &format!(
                "UPDATE node_trust SET level = 'seen', updated_at = ?1
                 WHERE level IN ('verified', 'trusted') AND node_id NOT IN ({placeholders})"
            ),
            rusqlite::params_from_iter(
                std::iter::once(ts(now)).chain(authorized.iter().map(|s| s.to_string())),
            ),
        )?;
        for peer in &fed.peers {
            self.seed_trust(&peer.node_id, &peer.trust, now)?;
        }
        for node_id in &fed.trusted {
            self.seed_trust(node_id, "trusted", now)?;
        }
        for node_id in &fed.blocked {
            self.seed_trust(node_id, "blocked", now)?;
        }
        Ok(())
    }

    // ---- RFDP peer advertisements (design §2/§3, cycle G) ----------------

    /// Upserts a verified peer advertisement, NEWER-`expires`-WINS (design
    /// §3): a row already on hand for `node_id` with an `expires` at or
    /// past `expires` is left untouched -- a replay, or a peer's own
    /// retransmit of an advert this store already holds a fresher (or
    /// equally fresh) copy of. `advert_cbor` is a fresh CBOR RE-ENCODE of
    /// the verified `Advert` struct (`fed::conn::receive_advert` calls
    /// `ciborium::into_writer` on the already-deserialized fields) --
    /// correction (final-review finding): this is NOT the literal bytes
    /// read off the wire, and a future gossip/forward path must not assume
    /// byte-for-byte fidelity with what the peer actually sent over the
    /// socket. It stays independently re-verifiable anyway:
    /// `advert::verify` reconstructs the signed message from
    /// `canonical_bytes(advert)` -- an explicit field tuple built from the
    /// struct's VALUES, not from any particular CBOR encoding of them --
    /// so any faithful re-encode, this one included, re-verifies exactly
    /// like the bytes as received would. Deliberately NOT re-encoded with
    /// a sanitized `name`, since mutating any signed field
    /// post-verification would make the stored signature meaningless to
    /// re-check later (Task 3's "verify on serve" invariant, design §3).
    /// `name` is its own column instead, holding the ALREADY-SANITIZED
    /// display value (`fed::conn::sanitize_advert_name`) -- the safe
    /// value for any surface that must never echo a peer-controlled string
    /// verbatim (this cycle's SSE `advert` event). Any caller that later
    /// decodes `advert_cbor` for its OTHER fields (services/protocols/
    /// security/expires) MUST NOT trust its embedded `.name` for display --
    /// re-sanitize it (or read this column instead) before rendering.
    pub fn upsert_peer_advert(
        &self,
        node_id: &str,
        advert_cbor: &[u8],
        name: &str,
        expires: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO peer_adverts (node_id, advert_cbor, name, expires, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(node_id) DO UPDATE SET
               advert_cbor = excluded.advert_cbor,
               name = excluded.name,
               expires = excluded.expires,
               received_at = excluded.received_at
             WHERE excluded.expires > peer_adverts.expires",
            params![node_id, advert_cbor, name, ts(expires), ts(received_at)],
        )?;
        Ok(())
    }

    /// Every unexpired (`expires > now`) stored advert, node_id ascending:
    /// `(node_id, advert_cbor, received_at)` -- backs Task 3's `GET
    /// /v1/discovery` peers listing and ctl `discovery` command, which
    /// re-verify `advert_cbor` on serve (defense against direct DB
    /// tampering, design §3) rather than trusting it just because it's in
    /// this table.
    pub fn list_peer_adverts(&self, now: DateTime<Utc>) -> rusqlite::Result<Vec<PeerAdvertRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, advert_cbor, received_at FROM peer_adverts
             WHERE expires > ?1 ORDER BY node_id",
        )?;
        let rows = stmt.query_map(params![ts(now)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                parse_ts(&row.get::<_, String>(2)?),
            ))
        })?;
        rows.collect()
    }

    /// Deletes expired adverts (`expires < now`), wired into the existing
    /// hourly retention sweep (`engine::pump`, alongside
    /// `purge_expired_challenges`). Returns the number of rows deleted.
    pub fn purge_expired_adverts(&self, now: DateTime<Utc>) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM peer_adverts WHERE expires < ?1",
            params![ts(now)],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use relay_core::{Endpoint, Envelope, Sender};

    #[test]
    fn parse_ts_defaults_corrupt_value_to_now_not_epoch() {
        let got = parse_ts("not-a-timestamp");
        // must be ~now, not the 1970 epoch (which would drop mail as expired)
        assert!(
            (Utc::now() - got).num_seconds().abs() < 5,
            "corrupt timestamp must default to ~now, got {got}"
        );
        // sanity: a valid value still round-trips
        assert_eq!(
            parse_ts("2026-08-23T00:00:00Z").to_rfc3339(),
            "2026-08-23T00:00:00+00:00"
        );
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.db")).unwrap();
        (dir, s)
    }

    fn env() -> Envelope {
        let now = Utc::now();
        Envelope::new(
            "mocka:chan".parse().unwrap(),
            Sender {
                native_ref: "!a".into(),
            },
            "text".into(),
            "hello".into(),
            now,
            now + Duration::hours(1),
            8,
        )
    }

    fn dest() -> Endpoint {
        "mockb:chan".parse().unwrap()
    }

    #[test]
    fn message_roundtrip() {
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        let got = s.get_message(e.id).unwrap().unwrap();
        assert_eq!(got.body, "hello");
        assert_eq!(got.id, e.id);
        assert!(s.get_message(uuid::Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn requeue_moves_a_dead_letter_back_to_pending_and_resets_attempts() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        // rack up attempts, then dead-letter it
        s.mark_attempting(id).unwrap();
        s.mark_attempting(id).unwrap();
        s.mark_terminal(id, "dead_letter", "RETRY_EXHAUSTED")
            .unwrap();

        assert!(s.requeue(id).unwrap(), "requeue should move the row");
        let del = s.deliveries_for_id(id).unwrap();
        assert_eq!(del.state, "pending");
        assert_eq!(
            del.attempt_count, 0,
            "attempts must reset so it isn't re-capped"
        );
        assert_eq!(del.reason, None);
        // it's due now
        assert_eq!(
            s.due_deliveries(now + Duration::seconds(1), 10)
                .unwrap()
                .len(),
            1
        );
        // requeue of a non-terminal (now pending) row is a no-op
        assert!(!s.requeue(id).unwrap());
    }

    #[test]
    fn purge_dead_letters_removes_only_dead_letter_rows() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let dead = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        let live = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        s.mark_terminal(dead, "dead_letter", "RETRY_EXHAUSTED")
            .unwrap();

        let (n, _orphans) = s.purge_dead_letters().unwrap();
        assert_eq!(n, 1, "only the dead_letter row is purged");
        assert!(s.deliveries_for_id(dead).is_none());
        assert!(
            s.deliveries_for_id(live).is_some(),
            "the pending row survives"
        );
    }

    #[test]
    fn due_deliveries_respect_next_attempt() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        let _future = s
            .insert_delivery(
                e.id,
                "general",
                &dest(),
                now + Duration::hours(1),
                e.expires_at,
                2,
            )
            .unwrap();
        let due = s.due_deliveries(now, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].destination, dest());
        assert_eq!(due[0].state, "pending");
    }

    #[test]
    fn state_transitions() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();

        s.mark_attempting(id).unwrap();
        assert!(s.due_deliveries(now, 10).unwrap().is_empty());
        let d = &s.deliveries_for(e.id).unwrap()[0];
        assert_eq!((d.state.as_str(), d.attempt_count), ("attempting", 1));

        s.mark_retry(id, now + Duration::seconds(5)).unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "pending");

        s.mark_attempting(id).unwrap();
        s.mark_delivered(id).unwrap();
        let d = &s.deliveries_for(e.id).unwrap()[0];
        assert_eq!((d.state.as_str(), d.attempt_count), ("delivered", 2));

        // a delivered row is terminal: a late/duplicate mark_retry or
        // mark_terminal (e.g. a stray plugin ack, or reclaim_stale racing a
        // fast delivery) must leave it 'delivered', not resurrect or
        // dead-letter it.
        s.mark_retry(id, now + Duration::seconds(30)).unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "delivered");
        s.mark_terminal(id, "dead_letter", "RETRY_EXHAUSTED")
            .unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "delivered");

        let id2 = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        s.mark_terminal(id2, "dead_letter", "RETRY_EXHAUSTED")
            .unwrap();
        let d2 = s
            .deliveries_for(e.id)
            .unwrap()
            .into_iter()
            .find(|d| d.id == id2)
            .unwrap();
        assert_eq!(d2.reason.as_deref(), Some("RETRY_EXHAUSTED"));

        // that same dead-lettered row is also terminal: mark_delivered must
        // not fire on it either (guarded to 'attempting' only).
        s.mark_delivered(id2).unwrap();
        assert_eq!(
            s.deliveries_for(e.id)
                .unwrap()
                .into_iter()
                .find(|d| d.id == id2)
                .unwrap()
                .state,
            "dead_letter"
        );
    }

    #[test]
    fn mark_delivered_ignores_rows_not_currently_attempting() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        // still 'pending': never entered 'attempting', so a stray delivered
        // ack must not apply.
        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        s.mark_delivered(id).unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "pending");
    }

    #[test]
    fn purge_terminal_deletes_old_terminal_rows_and_orphaned_messages_only() {
        let (_d, s) = store();
        let now = Utc::now();

        // delivered message: delivery and its now-orphaned message must both
        // be purged.
        let delivered_msg = env();
        s.insert_message(&delivered_msg).unwrap();
        let delivered_id = s
            .insert_delivery(
                delivered_msg.id,
                "general",
                &dest(),
                now,
                delivered_msg.expires_at,
                2,
            )
            .unwrap();
        s.mark_attempting(delivered_id).unwrap();
        s.mark_delivered(delivered_id).unwrap();

        // pending message: must survive purge untouched.
        let pending_msg = env();
        s.insert_message(&pending_msg).unwrap();
        let pending_id = s
            .insert_delivery(
                pending_msg.id,
                "general",
                &dest(),
                now,
                pending_msg.expires_at,
                2,
            )
            .unwrap();

        let (purged, orphans) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(purged, 1);
        assert!(
            orphans.is_empty(),
            "neither message in this test has attachments"
        );

        assert!(s.deliveries_for(delivered_msg.id).unwrap().is_empty());
        assert!(
            s.get_message(delivered_msg.id).unwrap().is_none(),
            "orphaned message must be purged alongside its terminal delivery"
        );

        let remaining = s.deliveries_for(pending_msg.id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, pending_id);
        assert_eq!(remaining[0].state, "pending");
        assert!(
            s.get_message(pending_msg.id).unwrap().is_some(),
            "message with a live pending delivery must survive purge"
        );
    }

    fn attachment_shas_for(s: &Store, message_id: Uuid) -> Vec<String> {
        let mut stmt = s
            .conn
            .prepare("SELECT sha256 FROM message_attachments WHERE message_id = ?1 ORDER BY sha256")
            .unwrap();
        stmt.query_map(params![message_id.to_string()], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap()
    }

    #[test]
    fn insert_attachment_refs_persists_shas_for_the_message() {
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        s.insert_attachment_refs(e.id, &["sha2".to_string(), "sha1".to_string()])
            .unwrap();
        assert_eq!(
            attachment_shas_for(&s, e.id),
            vec!["sha1".to_string(), "sha2".to_string()]
        );
    }

    #[test]
    fn purge_terminal_returns_orphan_shas_only_once_referencing_messages_are_gone() {
        let (_d, s) = store();
        let now = Utc::now();

        // delivered message with an attachment: once its message is purged,
        // nothing references the sha anymore, so it must come back as
        // orphaned (and the ref row itself must be cleaned up).
        let delivered_msg = env();
        s.insert_message(&delivered_msg).unwrap();
        s.insert_attachment_refs(delivered_msg.id, &["orphan-sha".to_string()])
            .unwrap();
        let delivered_id = s
            .insert_delivery(
                delivered_msg.id,
                "general",
                &dest(),
                now,
                delivered_msg.expires_at,
                2,
            )
            .unwrap();
        s.mark_attempting(delivered_id).unwrap();
        s.mark_delivered(delivered_id).unwrap();

        // pending message with an attachment: its message survives, so the
        // sha must NOT be reported as orphaned nor have its ref row deleted.
        let pending_msg = env();
        s.insert_message(&pending_msg).unwrap();
        s.insert_attachment_refs(pending_msg.id, &["surviving-sha".to_string()])
            .unwrap();
        s.insert_delivery(
            pending_msg.id,
            "general",
            &dest(),
            now,
            pending_msg.expires_at,
            2,
        )
        .unwrap();

        let (deleted, orphans) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(orphans, vec!["orphan-sha".to_string()]);

        assert!(
            attachment_shas_for(&s, delivered_msg.id).is_empty(),
            "orphaned attachment ref row must be deleted, not just reported"
        );
        assert_eq!(
            attachment_shas_for(&s, pending_msg.id),
            vec!["surviving-sha".to_string()],
            "a pending message's attachment ref must survive purge"
        );
    }

    /// Regression test for a real data-loss bug: a naive per-row
    /// `message_id NOT IN (SELECT id FROM messages)` anti-join reports a sha
    /// as orphaned the instant *any one* of the (possibly several) messages
    /// referencing it is purged — even while another message sharing that
    /// same sha (e.g. the same file forwarded twice) is still alive. That
    /// would have the pump `cas.remove` a blob a live message still depends
    /// on. `purge_terminal` must only ever report a sha once *no* surviving
    /// message references it, regardless of how many dead messages did.
    #[test]
    fn purge_terminal_keeps_a_sha_shared_by_a_surviving_message() {
        let (_d, s) = store();
        let now = Utc::now();

        // two independent messages that happen to reference the SAME sha.
        let msg1 = env();
        s.insert_message(&msg1).unwrap();
        s.insert_attachment_refs(msg1.id, &["shared-sha".to_string()])
            .unwrap();
        let id1 = s
            .insert_delivery(msg1.id, "general", &dest(), now, msg1.expires_at, 2)
            .unwrap();

        let msg2 = env();
        s.insert_message(&msg2).unwrap();
        s.insert_attachment_refs(msg2.id, &["shared-sha".to_string()])
            .unwrap();
        let id2 = s
            .insert_delivery(msg2.id, "general", &dest(), now, msg2.expires_at, 2)
            .unwrap();

        // terminate + purge msg1 only. msg2 (and its ref to the same sha) is
        // still alive: the shared sha must NOT be reported as orphaned, and
        // msg2's ref row for it must remain untouched.
        s.mark_attempting(id1).unwrap();
        s.mark_delivered(id1).unwrap();
        let (purged1, orphans1) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(purged1, 1);
        assert!(
            orphans1.is_empty(),
            "sha still referenced by msg2 must not be reported as orphaned: {orphans1:?}"
        );
        assert!(
            s.get_message(msg1.id).unwrap().is_none(),
            "msg1 must be purged"
        );
        assert!(
            s.get_message(msg2.id).unwrap().is_some(),
            "msg2 must survive"
        );
        assert_eq!(
            attachment_shas_for(&s, msg2.id),
            vec!["shared-sha".to_string()],
            "msg2's ref row for the shared sha must remain"
        );

        // now finish off msg2 too and purge again: nothing references the
        // sha anymore, so it must now come back as orphaned.
        s.mark_attempting(id2).unwrap();
        s.mark_delivered(id2).unwrap();
        let (purged2, orphans2) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(purged2, 1);
        assert_eq!(orphans2, vec!["shared-sha".to_string()]);
    }

    #[test]
    fn recover_and_reclaim_requeue_attempting() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        s.mark_attempting(id).unwrap();
        assert_eq!(s.recover().unwrap(), 1);
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "pending");

        s.mark_attempting(id).unwrap();
        assert_eq!(s.reclaim_stale(now + Duration::seconds(90)).unwrap(), 1);
        assert_eq!(s.reclaim_stale(now - Duration::seconds(90)).unwrap(), 0);
    }

    #[test]
    fn queue_counts_by_state() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        s.insert_delivery(e.id, "r", &dest(), now, e.expires_at, 2)
            .unwrap();
        let id2 = s
            .insert_delivery(e.id, "r", &dest(), now, e.expires_at, 2)
            .unwrap();
        s.mark_terminal(id2, "dead_letter", "POLICY_DENIED")
            .unwrap();
        let counts = s.queue_counts().unwrap();
        assert!(counts.contains(&("pending".to_string(), 1)));
        assert!(counts.contains(&("dead_letter".to_string(), 1)));
    }

    /// Finding 2 (whole-branch review): `insert_delivery`/`insert_dead_delivery`
    /// must stamp both `created_at` and `updated_at` at insert (not leave
    /// either at the zero-value `parse_ts` falls back to on a blank string).
    #[test]
    fn insert_delivery_and_insert_dead_delivery_stamp_created_and_updated_at() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let before = Utc::now();

        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        let dead_id = s
            .insert_dead_delivery(e.id, "general", &dest(), now, e.expires_at, "QUEUE_FULL")
            .unwrap();

        let del = s.deliveries_for_id(id).unwrap();
        assert!(
            del.created_at >= before,
            "created_at must be stamped at insert time"
        );
        assert_eq!(
            del.created_at, del.updated_at,
            "a freshly inserted row's created_at and updated_at must match"
        );

        let dead = s.deliveries_for_id(dead_id).unwrap();
        assert!(dead.created_at >= before);
        assert_eq!(dead.created_at, dead.updated_at);
    }

    /// `updated_at` must move forward on every state-mutating call
    /// (`mark_attempting`/`mark_delivered`/`mark_retry`/`mark_terminal`),
    /// while `created_at` stays fixed at the original insert time.
    #[test]
    fn mark_terminal_advances_updated_at_but_not_created_at() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        let inserted = s.deliveries_for_id(id).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        s.mark_terminal(id, "dead_letter", "POLICY_DENIED").unwrap();
        let after = s.deliveries_for_id(id).unwrap();

        assert_eq!(
            after.created_at, inserted.created_at,
            "created_at must never change after insert"
        );
        assert!(
            after.updated_at > inserted.created_at,
            "updated_at must advance past the original created_at on a mark_terminal write"
        );
    }

    #[test]
    fn list_deliveries_filters_by_state_newest_first_and_respects_limit() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();

        let pending_id = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2)
            .unwrap();
        let dead_id_1 = s
            .insert_dead_delivery(e.id, "general", &dest(), now, e.expires_at, "QUEUE_FULL")
            .unwrap();
        let dead_id_2 = s
            .insert_dead_delivery(e.id, "general", &dest(), now, e.expires_at, "POLICY_DENIED")
            .unwrap();

        let dead = s.list_deliveries(Some("dead_letter"), 100).unwrap();
        assert_eq!(dead.len(), 2, "must only return dead_letter rows: {dead:?}");
        assert_eq!(dead[0].id, dead_id_2, "newest (highest id) must come first");
        assert_eq!(dead[1].id, dead_id_1);
        assert!(dead.iter().all(|d| d.id != pending_id));

        let capped = s.list_deliveries(Some("dead_letter"), 1).unwrap();
        assert_eq!(capped.len(), 1, "limit must be respected");
        assert_eq!(capped[0].id, dead_id_2);

        let pending = s.list_deliveries(Some("pending"), 100).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, pending_id);

        let all = s.list_deliveries(None, 100).unwrap();
        assert_eq!(all.len(), 3, "state=None must list across every state");
    }

    /// Same shape as `store_open_migrates_a_pre_priority_database_without_
    /// losing_existing_rows` above, but for the created_at/updated_at
    /// migration this task adds: opens a DB that predates both `priority`
    /// and `created_at`/`updated_at` (i.e. a genuine pre-Task-4 v0.1 file)
    /// and confirms the existing row survives, migrated, with both new
    /// columns backfilled from `next_attempt`.
    #[test]
    fn store_open_migrates_a_pre_created_at_database_without_losing_existing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("older.db");

        let msg_id = Uuid::now_v7();
        let now = Utc::now();
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(PRE_PRIORITY_SCHEMA).unwrap();
            raw.execute(
                "INSERT INTO messages (id, envelope, created_at) VALUES (?1, ?2, ?3)",
                params![msg_id.to_string(), "{}", ts(now)],
            )
            .unwrap();
            raw.execute(
                "INSERT INTO deliveries
                   (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at)
                 VALUES (?1, 'general', 'mockb', 'chan', ?2, ?3)",
                params![msg_id.to_string(), ts(now), ts(now + Duration::hours(1))],
            )
            .unwrap();
        }

        let s = Store::open(&path).unwrap();

        let has_created_at: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('deliveries') WHERE name = 'created_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            has_created_at, 1,
            "migration must add the created_at column"
        );

        let due = s.due_deliveries(now + Duration::seconds(1), 10).unwrap();
        assert_eq!(
            due.len(),
            1,
            "the row that existed before migration must survive it"
        );
        assert_eq!(
            due[0].created_at, now,
            "pre-existing rows must backfill created_at from next_attempt"
        );
        assert_eq!(
            due[0].updated_at, now,
            "pre-existing rows must backfill updated_at from next_attempt"
        );

        // idempotent re-open (daemon restart).
        drop(s);
        let s2 = Store::open(&path).unwrap();
        assert_eq!(
            s2.due_deliveries(now + Duration::seconds(1), 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn pending_count_counts_pending_and_attempting_scoped_by_route() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let a = s
            .insert_delivery(e.id, "route-a", &dest(), now, e.expires_at, 2)
            .unwrap();
        s.insert_delivery(e.id, "route-a", &dest(), now, e.expires_at, 2)
            .unwrap();
        let b = s
            .insert_delivery(e.id, "route-b", &dest(), now, e.expires_at, 2)
            .unwrap();

        assert_eq!(s.pending_count(Some("route-a")).unwrap(), 2);
        assert_eq!(s.pending_count(Some("route-b")).unwrap(), 1);
        assert_eq!(
            s.pending_count(Some("route-c")).unwrap(),
            0,
            "unknown route counts zero"
        );
        assert_eq!(
            s.pending_count(None).unwrap(),
            3,
            "global count sums every route"
        );

        // 'attempting' still counts as in-flight for both scopes.
        s.mark_attempting(a).unwrap();
        assert_eq!(s.pending_count(Some("route-a")).unwrap(), 2);
        assert_eq!(s.pending_count(None).unwrap(), 3);

        // a terminal state (here, dead_letter) drops out of both counts.
        s.mark_terminal(b, "dead_letter", "QUEUE_FULL").unwrap();
        assert_eq!(s.pending_count(Some("route-b")).unwrap(), 0);
        assert_eq!(s.pending_count(None).unwrap(), 2);
    }

    #[test]
    fn insert_dead_delivery_lands_directly_in_dead_letter_with_the_given_reason() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s
            .insert_dead_delivery(e.id, "general", &dest(), now, e.expires_at, "QUEUE_FULL")
            .unwrap();

        let d = s.deliveries_for_id(id).unwrap();
        assert_eq!(d.state, "dead_letter");
        assert_eq!(d.reason.as_deref(), Some("QUEUE_FULL"));
        assert_eq!(
            s.pending_count(Some("general")).unwrap(),
            0,
            "a dead-lettered row must never count as in-flight"
        );
        let counts = s.queue_counts().unwrap();
        assert!(counts.contains(&("dead_letter".to_string(), 1)));
    }

    #[test]
    fn due_deliveries_returns_emergency_before_bulk_inserted_earlier() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();

        // two bulk (rank 3) rows inserted first...
        let bulk1 = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 3)
            .unwrap();
        let bulk2 = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 3)
            .unwrap();
        // ...then one emergency (rank 0) row inserted last, same next_attempt.
        let emergency = s
            .insert_delivery(e.id, "general", &dest(), now, e.expires_at, 0)
            .unwrap();

        let due = s.due_deliveries(now, 10).unwrap();
        assert_eq!(due.len(), 3);
        assert_eq!(
            due[0].id, emergency,
            "emergency (priority 0) must be scheduled first despite being inserted last: {due:?}"
        );
        assert_eq!(due[0].priority, 0);
        let remaining_ids: Vec<i64> = due[1..].iter().map(|d| d.id).collect();
        assert!(remaining_ids.contains(&bulk1) && remaining_ids.contains(&bulk2));
    }

    /// Schema captured verbatim as it existed before this task added
    /// `deliveries.priority` — used to simulate opening a real v0.1-era
    /// database file with `Store::open` and confirm the migration guard
    /// brings it up to date without data loss.
    const PRE_PRIORITY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  envelope TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL REFERENCES messages(id),
  route TEXT NOT NULL,
  dest_protocol TEXT NOT NULL,
  dest_endpoint TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  next_attempt TEXT NOT NULL,
  attempted_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(state, next_attempt);
CREATE TABLE IF NOT EXISTS message_attachments (
  message_id TEXT NOT NULL,
  sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_attachments_message_id
  ON message_attachments(message_id);
";

    #[test]
    fn store_open_migrates_a_pre_priority_database_without_losing_existing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");

        // Build a DB exactly the way a v0.1 daemon would have: no
        // `priority` column at all, plus one pre-existing row so the
        // migration's `ALTER TABLE ADD COLUMN` can be checked against real
        // data, not just an empty table.
        let msg_id = Uuid::now_v7();
        let now = Utc::now();
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(PRE_PRIORITY_SCHEMA).unwrap();
            raw.execute(
                "INSERT INTO messages (id, envelope, created_at) VALUES (?1, ?2, ?3)",
                params![msg_id.to_string(), "{}", ts(now)],
            )
            .unwrap();
            raw.execute(
                "INSERT INTO deliveries
                   (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at)
                 VALUES (?1, 'general', 'mockb', 'chan', ?2, ?3)",
                params![msg_id.to_string(), ts(now), ts(now + Duration::hours(1))],
            )
            .unwrap();
        }

        // Store::open must migrate this in place, not error or wipe it.
        let s = Store::open(&path).unwrap();

        let has_priority: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('deliveries') WHERE name = 'priority'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_priority, 1, "migration must add the priority column");

        // the pre-existing row must survive, backfilled to the default rank.
        let due = s.due_deliveries(now + Duration::seconds(1), 10).unwrap();
        assert_eq!(
            due.len(),
            1,
            "the row that existed before migration must survive it"
        );
        assert_eq!(
            due[0].priority, 2,
            "pre-existing rows must backfill to the default rank"
        );
        assert_eq!(due[0].message_id, msg_id);

        // and the migration is idempotent: reopening (e.g. a daemon restart)
        // must not error or re-run the ALTER TABLE.
        drop(s);
        let s2 = Store::open(&path).unwrap();
        assert_eq!(
            s2.due_deliveries(now + Duration::seconds(1), 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn create_challenge_basic() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);

        let id = s
            .create_challenge(
                "123456",
                "signal",
                "+1234567890",
                "lxmf",
                "abc123",
                "Jascha",
                now,
                expires,
            )
            .unwrap();

        assert!(id > 0);

        // Verify it can be found
        let challenge = s
            .find_active_challenge("signal", "+1234567890", "123456", now)
            .unwrap();
        assert!(challenge.is_some());
        let c = challenge.unwrap();
        assert_eq!(c.code, "123456");
        assert_eq!(c.target_protocol, "signal");
        assert_eq!(c.target_ref, "+1234567890");
        assert_eq!(c.requester_protocol, "lxmf");
        assert_eq!(c.requester_ref, "abc123");
        assert_eq!(c.display_name, "Jascha");
    }

    /// Finding 3 (whole-branch review, structural): `Challenge` derived
    /// `Debug`, so a future `{:?}` in any log line would leak the code —
    /// the field is meant to round-trip through SQL only (design §Security
    /// invariants: codes never leave the challenge lifecycle). The manual
    /// `Debug` impl must redact it while still rendering every other field.
    #[test]
    fn challenge_debug_redacts_code_but_keeps_other_fields() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);
        // 999888 is chosen to NOT be a substring of any other field below
        // (target_ref "+1234567890" would coincidentally contain "123456").
        s.create_challenge(
            "999888",
            "signal",
            "+1234567890",
            "lxmf",
            "abc123",
            "Jascha",
            now,
            expires,
        )
        .unwrap();
        let c = s
            .find_active_challenge("signal", "+1234567890", "999888", now)
            .unwrap()
            .unwrap();

        let debug = format!("{c:?}");
        assert!(
            !debug.contains("999888"),
            "the code must never appear in Debug output: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "Debug output must show a redaction marker: {debug}"
        );
        assert!(
            debug.contains("+1234567890"),
            "other fields must still render: {debug}"
        );
        assert!(
            debug.contains("signal"),
            "other fields must still render: {debug}"
        );
        assert!(
            debug.contains("Jascha"),
            "other fields must still render: {debug}"
        );
    }

    #[test]
    fn create_challenge_single_active_per_target() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);

        // Create first challenge
        let _id1 = s
            .create_challenge(
                "111111",
                "signal",
                "+1234567890",
                "lxmf",
                "abc123",
                "Jascha",
                now,
                expires,
            )
            .unwrap();

        // Create second challenge for same target (should delete first)
        let _id2 = s
            .create_challenge(
                "222222",
                "signal",
                "+1234567890",
                "lxmf",
                "xyz789",
                "Alice",
                now,
                expires,
            )
            .unwrap();

        // Old code should not be found
        let old = s
            .find_active_challenge("signal", "+1234567890", "111111", now)
            .unwrap();
        assert!(old.is_none());

        // New code should be found
        let new = s
            .find_active_challenge("signal", "+1234567890", "222222", now)
            .unwrap();
        assert!(new.is_some());
        assert_eq!(new.unwrap().code, "222222");
    }

    #[test]
    fn find_active_challenge_respects_expiry() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);

        s.create_challenge(
            "123456",
            "signal",
            "+1234567890",
            "lxmf",
            "abc123",
            "Jascha",
            now,
            expires,
        )
        .unwrap();

        // Should be found before expiry
        assert!(s
            .find_active_challenge("signal", "+1234567890", "123456", now)
            .unwrap()
            .is_some());

        // Should not be found after expiry
        let after_expiry = expires + Duration::seconds(1);
        assert!(s
            .find_active_challenge("signal", "+1234567890", "123456", after_expiry)
            .unwrap()
            .is_none());
    }

    #[test]
    fn find_active_challenge_requires_exact_code() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);

        s.create_challenge(
            "123456",
            "signal",
            "+1234567890",
            "lxmf",
            "abc123",
            "Jascha",
            now,
            expires,
        )
        .unwrap();

        // Wrong code
        assert!(s
            .find_active_challenge("signal", "+1234567890", "654321", now)
            .unwrap()
            .is_none());

        // Correct code
        assert!(s
            .find_active_challenge("signal", "+1234567890", "123456", now)
            .unwrap()
            .is_some());
    }

    #[test]
    fn find_active_challenge_requires_correct_target() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);

        s.create_challenge(
            "123456",
            "signal",
            "+1234567890",
            "lxmf",
            "abc123",
            "Jascha",
            now,
            expires,
        )
        .unwrap();

        // Different target protocol
        assert!(s
            .find_active_challenge("lxmf", "+1234567890", "123456", now)
            .unwrap()
            .is_none());

        // Different target ref
        assert!(s
            .find_active_challenge("signal", "+9876543210", "123456", now)
            .unwrap()
            .is_none());

        // Correct target
        assert!(s
            .find_active_challenge("signal", "+1234567890", "123456", now)
            .unwrap()
            .is_some());
    }

    #[test]
    fn delete_challenge() {
        let (_d, s) = store();
        let now = Utc::now();
        let expires = now + Duration::minutes(15);

        let id = s
            .create_challenge(
                "123456",
                "signal",
                "+1234567890",
                "lxmf",
                "abc123",
                "Jascha",
                now,
                expires,
            )
            .unwrap();

        // Should exist
        assert!(s
            .find_active_challenge("signal", "+1234567890", "123456", now)
            .unwrap()
            .is_some());

        // Delete it
        s.delete_challenge(id).unwrap();

        // Should no longer exist
        assert!(s
            .find_active_challenge("signal", "+1234567890", "123456", now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_challenges_excludes_expired_and_orders_by_id() {
        let (_d, s) = store();
        let now = Utc::now();

        s.create_challenge(
            "111111",
            "signal",
            "+1111111111",
            "lxmf",
            "a",
            "Alice",
            now,
            now + Duration::minutes(15),
        )
        .unwrap();
        s.create_challenge(
            "222222",
            "matrix",
            "+2222222222",
            "lxmf",
            "b",
            "Bob",
            now,
            now + Duration::minutes(15),
        )
        .unwrap();
        // already expired -- must not appear
        s.create_challenge(
            "333333",
            "signal",
            "+3333333333",
            "lxmf",
            "c",
            "Carol",
            now,
            now - Duration::seconds(1),
        )
        .unwrap();

        let list = s.list_challenges(now).unwrap();
        assert_eq!(
            list.len(),
            2,
            "the expired challenge must be excluded: {list:?}"
        );
        assert_eq!(list[0].display_name, "Alice");
        assert_eq!(list[1].display_name, "Bob");
    }

    #[test]
    fn list_challenges_empty() {
        let (_d, s) = store();
        assert!(s.list_challenges(Utc::now()).unwrap().is_empty());
    }

    #[test]
    fn purge_expired_challenges() {
        let (_d, s) = store();
        let now = Utc::now();

        // Create one expired challenge
        let expires_old = now - Duration::minutes(1);
        s.create_challenge(
            "111111",
            "signal",
            "+1111111111",
            "lxmf",
            "a",
            "A",
            now - Duration::minutes(16),
            expires_old,
        )
        .unwrap();

        // Create one active challenge
        let expires_new = now + Duration::minutes(15);
        s.create_challenge(
            "222222",
            "signal",
            "+2222222222",
            "lxmf",
            "b",
            "B",
            now,
            expires_new,
        )
        .unwrap();

        // Purge
        let deleted = s.purge_expired_challenges(now).unwrap();
        assert_eq!(deleted, 1);

        // Old challenge gone
        assert!(s
            .find_active_challenge("signal", "+1111111111", "111111", now)
            .unwrap()
            .is_none());

        // New challenge still exists
        assert!(s
            .find_active_challenge("signal", "+2222222222", "222222", now)
            .unwrap()
            .is_some());
    }

    #[test]
    fn insert_link_basic() {
        let (_d, s) = store();
        let now = Utc::now();

        let id = s
            .insert_link("signal", "+1234567890", "lxmf", "abc123", "Jascha", now)
            .unwrap();

        assert!(id > 0);

        let link = s.link_for_identity("signal", "+1234567890").unwrap();
        assert!(link.is_some());
        let l = link.unwrap();
        assert_eq!(l.a_protocol, "signal");
        assert_eq!(l.a_ref, "+1234567890");
        assert_eq!(l.b_protocol, "lxmf");
        assert_eq!(l.b_ref, "abc123");
        assert_eq!(l.display_name, "Jascha");
    }

    #[test]
    fn insert_link_unique_replace() {
        let (_d, s) = store();
        let now = Utc::now();
        let later = now + Duration::seconds(10);

        // Insert a link
        let id1 = s
            .insert_link("signal", "+1234567890", "lxmf", "abc123", "Jascha", now)
            .unwrap();

        // Insert an unrelated link to bump the autoincrement counter
        let _id_unrelated = s
            .insert_link("signal", "+9999999999", "lxmf", "xyz", "Other", now)
            .unwrap();

        // Replace the original link with new verified_at (should return the SAME id, not a new one)
        let id_replaced = s
            .insert_link(
                "signal",
                "+1234567890",
                "lxmf",
                "abc123",
                "Jascha Updated",
                later,
            )
            .unwrap();

        // CRITICAL: RETURNING id must give us the original link's id, not the unrelated link's id
        assert_eq!(
            id_replaced, id1,
            "replace-path must return the updated row's id, not a new row id"
        );

        // Should only have two links (original + unrelated)
        let links = s.list_links().unwrap();
        assert_eq!(links.len(), 2);

        let link = s
            .link_for_identity("signal", "+1234567890")
            .unwrap()
            .unwrap();
        assert!(link.verified_at > now);
        assert_eq!(link.id, id1);
    }

    #[test]
    fn link_for_identity_a_side() {
        let (_d, s) = store();
        let now = Utc::now();

        s.insert_link("signal", "+1234567890", "lxmf", "abc123", "Jascha", now)
            .unwrap();

        let link = s.link_for_identity("signal", "+1234567890").unwrap();
        assert!(link.is_some());
        assert_eq!(link.unwrap().display_name, "Jascha");
    }

    #[test]
    fn link_for_identity_b_side() {
        let (_d, s) = store();
        let now = Utc::now();

        s.insert_link("signal", "+1234567890", "lxmf", "abc123", "Jascha", now)
            .unwrap();

        let link = s.link_for_identity("lxmf", "abc123").unwrap();
        assert!(link.is_some());
        assert_eq!(link.unwrap().display_name, "Jascha");
    }

    #[test]
    fn link_for_identity_no_match() {
        let (_d, s) = store();
        let now = Utc::now();

        s.insert_link("signal", "+1234567890", "lxmf", "abc123", "Jascha", now)
            .unwrap();

        let link = s.link_for_identity("unknown", "notfound").unwrap();
        assert!(link.is_none());
    }

    #[test]
    fn delete_link() {
        let (_d, s) = store();
        let now = Utc::now();

        let id = s
            .insert_link("signal", "+1234567890", "lxmf", "abc123", "Jascha", now)
            .unwrap();

        // Should exist
        assert!(s
            .link_for_identity("signal", "+1234567890")
            .unwrap()
            .is_some());

        // Delete it
        let deleted = s.delete_link(id).unwrap();
        assert!(deleted);

        // Should not exist
        assert!(s
            .link_for_identity("signal", "+1234567890")
            .unwrap()
            .is_none());
    }

    #[test]
    fn delete_link_returns_false_for_nonexistent() {
        let (_d, s) = store();
        let deleted = s.delete_link(9999).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn list_links() {
        let (_d, s) = store();
        let now = Utc::now();

        // Add multiple links
        s.insert_link("signal", "+1111111111", "lxmf", "a", "Alice", now)
            .unwrap();
        s.insert_link("signal", "+2222222222", "lxmf", "b", "Bob", now)
            .unwrap();
        s.insert_link(
            "matrix",
            "@charlie:example.com",
            "telegram",
            "charlie_bot",
            "Charlie",
            now,
        )
        .unwrap();

        let links = s.list_links().unwrap();
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].display_name, "Alice");
        assert_eq!(links[1].display_name, "Bob");
        assert_eq!(links[2].display_name, "Charlie");
    }

    #[test]
    fn list_links_empty() {
        let (_d, s) = store();
        let links = s.list_links().unwrap();
        assert!(links.is_empty());
    }

    // ---- federation trust store (design §3, §112.7) ----------------------

    fn node_id(byte: u8) -> String {
        format!("rf:{}", hex::encode([byte; 32]))
    }

    fn peer(name: &str, node_id: &str, trust: &str) -> crate::config::PeerConfig {
        crate::config::PeerConfig {
            name: name.into(),
            node_id: node_id.into(),
            addr: "10.0.0.1:47000".into(),
            trust: trust.into(),
            messages_per_minute: 0,
            sealed_key: None,
        }
    }

    fn fed_cfg(
        peers: Vec<crate::config::PeerConfig>,
        trusted: Vec<String>,
        blocked: Vec<String>,
    ) -> crate::config::FederationConfig {
        crate::config::FederationConfig {
            listen: None,
            accept_from: "verified".into(),
            max_hops: 4,
            max_ttl_secs: 86_400,
            identity_exposure: "pseudonymous".into(),
            ingress_routes: vec![],
            peers,
            trusted,
            blocked,
        }
    }

    #[test]
    fn trust_level_of_unknown_node_is_none() {
        let (_d, s) = store();
        assert_eq!(s.trust_level(&node_id(1)).unwrap(), None);
    }

    #[test]
    fn record_seen_sets_level_seen_for_a_new_node() {
        let (_d, s) = store();
        let now = Utc::now();
        s.record_seen(&node_id(1), now).unwrap();
        assert_eq!(s.trust_level(&node_id(1)).unwrap().as_deref(), Some("seen"));
    }

    #[test]
    fn record_seen_never_raises_trust_beyond_seen() {
        // §112.7 MUST: discovery/handshake never raises trust beyond `seen`.
        // A node already seeded verified/trusted at config load must stay at
        // that level through any number of subsequent handshakes.
        let (_d, s) = store();
        let now = Utc::now();
        let id = node_id(1);
        s.seed_trust(&id, "trusted", now).unwrap();
        s.record_seen(&id, now + Duration::hours(1)).unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("trusted"));
    }

    #[test]
    fn record_seen_is_idempotent_for_an_already_seen_node() {
        let (_d, s) = store();
        let now = Utc::now();
        let id = node_id(1);
        s.record_seen(&id, now).unwrap();
        s.record_seen(&id, now + Duration::hours(1)).unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("seen"));
    }

    #[test]
    fn seed_trust_inserts_a_fresh_row_with_first_seen_and_updated_at_equal_to_now() {
        let (_d, s) = store();
        let now = Utc::now();
        let id = node_id(1);
        s.seed_trust(&id, "verified", now).unwrap();

        let rows = s.list_trust().unwrap();
        assert_eq!(rows.len(), 1);
        let (row_id, level, first_seen, updated_at) = &rows[0];
        assert_eq!(row_id, &id);
        assert_eq!(level, "verified");
        assert_eq!(*first_seen, now);
        assert_eq!(*updated_at, now);
    }

    /// The core config-wins-over-DB + first_seen-preservation matrix (design
    /// §3): a node first observed at runtime (`record_seen`, stamping
    /// `first_seen`) is then re-seeded from config on a later boot at a
    /// higher level -- the level must move to what config says, but
    /// `first_seen` must NOT reset to the reseed time; only `updated_at`
    /// advances. This is exactly what an `INSERT OR REPLACE` would get
    /// wrong (it would blow away `first_seen`), which is why `seed_trust`
    /// uses `ON CONFLICT DO UPDATE` instead.
    #[test]
    fn seed_trust_config_wins_over_runtime_seen_level_and_preserves_first_seen() {
        let (_d, s) = store();
        let id = node_id(1);
        let first_seen_at = Utc::now();
        s.record_seen(&id, first_seen_at).unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("seen"));

        let reseed_at = first_seen_at + Duration::hours(2);
        s.seed_trust(&id, "verified", reseed_at).unwrap();

        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("verified"));
        let (_, _, first_seen, updated_at) = s
            .list_trust()
            .unwrap()
            .into_iter()
            .find(|r| r.0 == id)
            .unwrap();
        assert_eq!(
            first_seen, first_seen_at,
            "first_seen must survive the level change"
        );
        assert_eq!(
            updated_at, reseed_at,
            "updated_at must advance to the reseed time"
        );
    }

    /// Same shape as above but re-seeding at a LOWER-sounding level than
    /// what's currently stored still overwrites -- `seed_trust` is a
    /// straight config-wins set, not a monotonic ratchet (only
    /// `record_seen` has the "never raise beyond seen" restriction; explicit
    /// config seeding is authoritative in either direction).
    #[test]
    fn seed_trust_overwrites_an_existing_level_in_either_direction() {
        let (_d, s) = store();
        let id = node_id(1);
        let t0 = Utc::now();
        s.seed_trust(&id, "trusted", t0).unwrap();
        let t1 = t0 + Duration::hours(1);
        s.seed_trust(&id, "verified", t1).unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("verified"));
    }

    #[test]
    fn list_trust_lists_every_node_ordered_by_node_id() {
        let (_d, s) = store();
        let now = Utc::now();
        s.seed_trust(&node_id(2), "trusted", now).unwrap();
        s.seed_trust(&node_id(1), "verified", now).unwrap();
        s.record_seen(&node_id(3), now).unwrap();

        let rows = s.list_trust().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, node_id(1));
        assert_eq!(rows[1].0, node_id(2));
        assert_eq!(rows[2].0, node_id(3));
        assert_eq!(rows[2].1, "seen");
    }

    #[test]
    fn seed_federation_trust_seeds_peers_at_their_own_trust_field() {
        let (_d, s) = store();
        let now = Utc::now();
        let fed = fed_cfg(
            vec![
                peer("phoenix", &node_id(1), "trusted"),
                peer("tucson", &node_id(2), "verified"),
            ],
            vec![],
            vec![],
        );
        s.seed_federation_trust(&fed, now).unwrap();
        assert_eq!(
            s.trust_level(&node_id(1)).unwrap().as_deref(),
            Some("trusted")
        );
        assert_eq!(
            s.trust_level(&node_id(2)).unwrap().as_deref(),
            Some("verified")
        );
    }

    #[test]
    fn seed_federation_trust_seeds_trusted_and_blocked_lists() {
        let (_d, s) = store();
        let now = Utc::now();
        let fed = fed_cfg(vec![], vec![node_id(1)], vec![node_id(2)]);
        s.seed_federation_trust(&fed, now).unwrap();
        assert_eq!(
            s.trust_level(&node_id(1)).unwrap().as_deref(),
            Some("trusted")
        );
        assert_eq!(
            s.trust_level(&node_id(2)).unwrap().as_deref(),
            Some("blocked")
        );
    }

    /// A node_id listed both as a `verified` peer AND in `blocked` (an
    /// operator override -- e.g. temporarily blocking a misbehaving
    /// configured peer without deleting its peer entry) must end up
    /// `blocked`: `seed_federation_trust` applies `blocked` last precisely
    /// so it wins any such conflict, the most restrictive outcome.
    #[test]
    fn seed_federation_trust_blocked_overrides_a_peer_entry_for_the_same_node() {
        let (_d, s) = store();
        let now = Utc::now();
        let id = node_id(1);
        let fed = fed_cfg(
            vec![peer("phoenix", &id, "trusted")],
            vec![],
            vec![id.clone()],
        );
        s.seed_federation_trust(&fed, now).unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("blocked"));
    }

    /// Re-running boot seeding (design §3: "re-seeded each boot") against a
    /// node the DB already has a runtime-learned `first_seen` for must not
    /// reset that `first_seen`, across multiple config-seed calls -- the
    /// full "config wins over DB on load" story end to end via the
    /// aggregate boot-seeding entry point, not just the underlying
    /// `seed_trust` primitive.
    #[test]
    fn seed_federation_trust_preserves_first_seen_across_repeated_boots() {
        let (_d, s) = store();
        let id = node_id(1);
        let first_seen_at = Utc::now();
        s.record_seen(&id, first_seen_at).unwrap();

        let boot1 = first_seen_at + Duration::hours(1);
        let fed = fed_cfg(vec![peer("phoenix", &id, "verified")], vec![], vec![]);
        s.seed_federation_trust(&fed, boot1).unwrap();

        let boot2 = boot1 + Duration::hours(1);
        s.seed_federation_trust(&fed, boot2).unwrap();

        let (_, level, first_seen, updated_at) = s
            .list_trust()
            .unwrap()
            .into_iter()
            .find(|r| r.0 == id)
            .unwrap();
        assert_eq!(level, "verified");
        assert_eq!(
            first_seen, first_seen_at,
            "first_seen must survive repeated re-seeding"
        );
        assert_eq!(updated_at, boot2);
    }

    /// Trust REVOCATION (final-review I-3): a node that was `verified` only
    /// because config said so must lose that level when config stops saying
    /// so -- a boot-time re-seed with the peer entry gone downgrades it to
    /// `seen` (never deletes the row: `first_seen` history is kept). Without
    /// this, deleting a peer from the config would leave its durable
    /// `verified` row passing `fed_ingress`'s accept_from gate forever.
    #[test]
    fn seed_federation_trust_downgrades_a_removed_verified_peer_to_seen() {
        let (_d, s) = store();
        let id = node_id(1);
        let first_seen_at = Utc::now();
        let boot1 = first_seen_at + Duration::hours(1);
        s.record_seen(&id, first_seen_at).unwrap();
        s.seed_federation_trust(
            &fed_cfg(vec![peer("phoenix", &id, "verified")], vec![], vec![]),
            boot1,
        )
        .unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("verified"));

        // Boot 2: the peer entry is gone from config entirely.
        let boot2 = boot1 + Duration::hours(1);
        s.seed_federation_trust(&fed_cfg(vec![], vec![], vec![]), boot2)
            .unwrap();

        let (_, level, first_seen, updated_at) = s
            .list_trust()
            .unwrap()
            .into_iter()
            .find(|r| r.0 == id)
            .unwrap();
        assert_eq!(
            level, "seen",
            "a removed peer's config-derived level must be revoked"
        );
        assert_eq!(
            first_seen, first_seen_at,
            "downgrade must preserve first_seen"
        );
        assert_eq!(updated_at, boot2, "downgrade must advance updated_at");
    }

    /// Same revocation for the `trusted: [...]` list: a node_id dropped from
    /// it loses `trusted` on the next re-seed.
    #[test]
    fn seed_federation_trust_downgrades_a_removed_trusted_list_entry_to_seen() {
        let (_d, s) = store();
        let id = node_id(1);
        let boot1 = Utc::now();
        s.seed_federation_trust(&fed_cfg(vec![], vec![id.clone()], vec![]), boot1)
            .unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("trusted"));

        s.seed_federation_trust(&fed_cfg(vec![], vec![], vec![]), boot1 + Duration::hours(1))
            .unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("seen"));
    }

    /// The downgrade must be scoped to REMOVED nodes only: a peer still in
    /// config keeps its level through the same re-seed that revokes its
    /// removed sibling.
    #[test]
    fn seed_federation_trust_downgrade_spares_a_still_configured_peer() {
        let (_d, s) = store();
        let now = Utc::now();
        let removed = node_id(1);
        let kept = node_id(2);
        let both = fed_cfg(
            vec![
                peer("phoenix", &removed, "verified"),
                peer("tucson", &kept, "trusted"),
            ],
            vec![],
            vec![],
        );
        s.seed_federation_trust(&both, now).unwrap();

        let only_kept = fed_cfg(vec![peer("tucson", &kept, "trusted")], vec![], vec![]);
        s.seed_federation_trust(&only_kept, now + Duration::hours(1))
            .unwrap();

        assert_eq!(s.trust_level(&removed).unwrap().as_deref(), Some("seen"));
        assert_eq!(
            s.trust_level(&kept).unwrap().as_deref(),
            Some("trusted"),
            "a still-configured peer must keep its config level through the downgrade pass"
        );
    }

    /// `blocked` is sticky by design: removing a blocked node_id from config
    /// does NOT unblock it (the downgrade pass only touches
    /// verified/trusted). Unblocking is a deliberate operator action (a
    /// future admin surface), never an implicit config-diff side effect.
    #[test]
    fn seed_federation_trust_blocked_stays_blocked_when_removed_from_config() {
        let (_d, s) = store();
        let now = Utc::now();
        let id = node_id(1);
        s.seed_federation_trust(&fed_cfg(vec![], vec![], vec![id.clone()]), now)
            .unwrap();
        assert_eq!(s.trust_level(&id).unwrap().as_deref(), Some("blocked"));

        s.seed_federation_trust(&fed_cfg(vec![], vec![], vec![]), now + Duration::hours(1))
            .unwrap();
        assert_eq!(
            s.trust_level(&id).unwrap().as_deref(),
            Some("blocked"),
            "blocked is sticky: config removal must not implicitly unblock"
        );
    }

    /// A runtime-learned `seen` row (never config-derived at all) is not the
    /// downgrade pass's business: it must pass through a re-seed untouched,
    /// `updated_at` included.
    #[test]
    fn seed_federation_trust_leaves_runtime_seen_rows_untouched() {
        let (_d, s) = store();
        let seen_at = Utc::now();
        let id = node_id(1);
        s.record_seen(&id, seen_at).unwrap();

        s.seed_federation_trust(
            &fed_cfg(vec![], vec![], vec![]),
            seen_at + Duration::hours(1),
        )
        .unwrap();

        let (_, level, first_seen, updated_at) = s
            .list_trust()
            .unwrap()
            .into_iter()
            .find(|r| r.0 == id)
            .unwrap();
        assert_eq!(level, "seen");
        assert_eq!(first_seen, seen_at);
        assert_eq!(
            updated_at, seen_at,
            "a runtime seen row must not even have updated_at touched"
        );
    }

    #[test]
    #[should_panic(expected = "invalid trust level")]
    fn seed_trust_debug_panics_on_an_invalid_level() {
        // Task 3 review carry-over: seed_trust must guard its level param.
        // debug_assert! only fires in debug builds, which is how `cargo
        // test` runs by default (and how CI/verification-before-completion
        // runs it here) — this is the intended trip-wire, not a release
        // behavior this test claims anything about.
        let (_d, s) = store();
        let _ = s.seed_trust(&node_id(1), "definitely-not-a-real-level", Utc::now());
    }

    // ---- fed ack -> delivery resolution (design §5 egress) ---------------

    fn fed_dest(peer_and_route: &str) -> Endpoint {
        Endpoint {
            protocol: "fed".into(),
            endpoint: peer_and_route.into(),
        }
    }

    #[test]
    fn deliveries_for_fed_ack_finds_the_row_addressed_to_that_peer() {
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        let now = Utc::now();
        s.insert_delivery(
            e.id,
            "general",
            &fed_dest("phoenix/regional-chat"),
            now,
            e.expires_at,
            2,
        )
        .unwrap();

        let rows = s.deliveries_for_fed_ack(e.id, "phoenix").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].destination, fed_dest("phoenix/regional-chat"));
    }

    #[test]
    fn deliveries_for_fed_ack_does_not_match_a_different_peer() {
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        let now = Utc::now();
        s.insert_delivery(
            e.id,
            "general",
            &fed_dest("phoenix/regional-chat"),
            now,
            e.expires_at,
            2,
        )
        .unwrap();

        assert!(s
            .deliveries_for_fed_ack(e.id, "seattle")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn deliveries_for_fed_ack_requires_the_slash_separator_not_just_a_prefix() {
        // A peer named "phoen" must not match a delivery actually addressed
        // to "phoenix/regional-chat" -- the LIKE pattern requires the '/'
        // separator, not a bare string-prefix match.
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        let now = Utc::now();
        s.insert_delivery(
            e.id,
            "general",
            &fed_dest("phoenix/regional-chat"),
            now,
            e.expires_at,
            2,
        )
        .unwrap();

        assert!(s.deliveries_for_fed_ack(e.id, "phoen").unwrap().is_empty());
    }

    #[test]
    fn deliveries_for_fed_ack_ignores_non_federation_deliveries() {
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        let now = Utc::now();
        // A normal (non-fed) delivery to a destination whose endpoint just
        // happens to look like "peer/route" must never be picked up here --
        // only dest_protocol = 'fed' rows are eligible.
        s.insert_delivery(
            e.id,
            "general",
            &Endpoint {
                protocol: "mocka".into(),
                endpoint: "phoenix/regional-chat".into(),
            },
            now,
            e.expires_at,
            2,
        )
        .unwrap();

        assert!(s
            .deliveries_for_fed_ack(e.id, "phoenix")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn deliveries_for_fed_ack_scopes_by_message_id_too() {
        let (_d, s) = store();
        let e1 = env();
        let mut e2 = env();
        e2.id = Uuid::now_v7();
        e2.body = "a different message".into();
        s.insert_message(&e1).unwrap();
        s.insert_message(&e2).unwrap();
        let now = Utc::now();
        s.insert_delivery(
            e1.id,
            "general",
            &fed_dest("phoenix/regional-chat"),
            now,
            e1.expires_at,
            2,
        )
        .unwrap();
        s.insert_delivery(
            e2.id,
            "general",
            &fed_dest("phoenix/regional-chat"),
            now,
            e2.expires_at,
            2,
        )
        .unwrap();

        let rows = s.deliveries_for_fed_ack(e1.id, "phoenix").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, e1.id);
    }

    // ---- RFDP peer advertisements (design §2/§3, cycle G) -----------------

    #[test]
    fn upsert_peer_advert_newer_expires_wins_older_or_equal_ignored() {
        let (_d, s) = store();
        let now = Utc::now();
        s.upsert_peer_advert("rf:aa", b"first", "Alice", now + Duration::hours(1), now)
            .unwrap();

        // Older expires: ignored entirely -- the first row survives as-is.
        s.upsert_peer_advert(
            "rf:aa",
            b"stale",
            "AliceOld",
            now + Duration::minutes(30),
            now,
        )
        .unwrap();
        let rows = s.list_peer_adverts(now).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, b"first".to_vec());

        // Equal expires: also ignored (strictly newer required to win).
        s.upsert_peer_advert("rf:aa", b"equal", "AliceEq", now + Duration::hours(1), now)
            .unwrap();
        assert_eq!(s.list_peer_adverts(now).unwrap()[0].1, b"first".to_vec());

        // Strictly newer expires: wins, replacing the whole row.
        s.upsert_peer_advert("rf:aa", b"newer", "AliceNew", now + Duration::hours(2), now)
            .unwrap();
        assert_eq!(s.list_peer_adverts(now).unwrap()[0].1, b"newer".to_vec());
    }

    #[test]
    fn upsert_peer_advert_two_distinct_node_ids_do_not_collide() {
        let (_d, s) = store();
        let now = Utc::now();
        s.upsert_peer_advert("rf:aa", b"a", "Alice", now + Duration::hours(1), now)
            .unwrap();
        s.upsert_peer_advert("rf:bb", b"b", "Bob", now + Duration::hours(1), now)
            .unwrap();
        let rows = s.list_peer_adverts(now).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "rf:aa");
        assert_eq!(rows[1].0, "rf:bb");
    }

    #[test]
    fn list_peer_adverts_excludes_expired_rows() {
        let (_d, s) = store();
        let now = Utc::now();
        s.upsert_peer_advert("rf:bb", b"live", "Bob", now + Duration::hours(1), now)
            .unwrap();
        s.upsert_peer_advert("rf:cc", b"dead", "Carol", now - Duration::hours(1), now)
            .unwrap();
        let rows = s.list_peer_adverts(now).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "rf:bb");
    }

    #[test]
    fn purge_expired_adverts_deletes_only_expired_rows() {
        let (_d, s) = store();
        let now = Utc::now();
        s.upsert_peer_advert("rf:dd", b"live", "Dave", now + Duration::hours(1), now)
            .unwrap();
        s.upsert_peer_advert("rf:ee", b"dead", "Eve", now - Duration::hours(1), now)
            .unwrap();

        let purged = s.purge_expired_adverts(now).unwrap();
        assert_eq!(purged, 1);

        let remaining = s.list_peer_adverts(now).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, "rf:dd");
        // A second purge with nothing left to remove is a clean no-op.
        assert_eq!(s.purge_expired_adverts(now).unwrap(), 0);
    }
}
