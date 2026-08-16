use chrono::{DateTime, Utc};
use relay_core::{Endpoint, Envelope};
use rusqlite::{params, Connection};
use std::path::Path;
use uuid::Uuid;

pub struct Store {
    conn: Connection,
}

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
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(state, priority, next_attempt);
CREATE TABLE IF NOT EXISTS message_attachments (
  message_id TEXT NOT NULL,
  sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_attachments_message_id
  ON message_attachments(message_id);
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
    Ok(())
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&Utc)).unwrap_or_default()
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
    pub fn insert_attachment_refs(&self, message_id: Uuid, shas: &[String]) -> rusqlite::Result<()> {
        for sha in shas {
            self.conn.execute(
                "INSERT INTO message_attachments (message_id, sha256) VALUES (?1, ?2)",
                params![message_id.to_string(), sha],
            )?;
        }
        Ok(())
    }

    pub fn get_message(&self, id: Uuid) -> rusqlite::Result<Option<Envelope>> {
        let mut stmt = self.conn.prepare("SELECT envelope FROM messages WHERE id = ?1")?;
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
        self.conn.execute(
            "INSERT INTO deliveries
               (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at, priority)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![message_id.to_string(), route, dest.protocol, dest.endpoint,
                    ts(next_attempt), ts(expires_at), priority],
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
        self.conn.execute(
            "INSERT INTO deliveries
               (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at,
                state, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'dead_letter', ?7)",
            params![message_id.to_string(), route, dest.protocol, dest.endpoint,
                    ts(next_attempt), ts(expires_at), reason],
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
            destination: Endpoint { protocol: row.get(3)?, endpoint: row.get(4)? },
            priority: row.get(5)?,
            attempt_count: row.get(6)?,
            state: row.get(7)?,
            reason: row.get(8)?,
            next_attempt: parse_ts(&row.get::<_, String>(9)?),
            expires_at: parse_ts(&row.get::<_, String>(10)?),
        })
    }

    const DELIVERY_COLS: &'static str =
        "id, message_id, route, dest_protocol, dest_endpoint, priority, attempt_count,
         state, reason, next_attempt, expires_at";

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
                attempt_count = attempt_count + 1, attempted_at = ?2
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
            "UPDATE deliveries SET state = 'delivered'
             WHERE id = ?1 AND state = 'attempting'",
            params![id])?;
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
            "UPDATE deliveries SET state = 'pending', next_attempt = ?2
             WHERE id = ?1 AND state IN ('pending', 'attempting')",
            params![id, ts(next_attempt)],
        )?;
        Ok(())
    }

    /// Guarded to 'pending' or 'attempting' for the same reason as
    /// `mark_retry`: called on fresh 'pending' rows (TTL expiry, policy
    /// denial, missing-message) as well as 'attempting' rows (retry
    /// exhaustion in `handle_result`), but never on a row already terminal.
    pub fn mark_terminal(&self, id: i64, state: &str, reason: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = ?2, reason = ?3
             WHERE id = ?1 AND state IN ('pending', 'attempting')",
            params![id, state, reason],
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
            let rows = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            rows
        };
        self.conn.execute(
            "DELETE FROM message_attachments WHERE message_id NOT IN (SELECT id FROM messages)",
            [],
        )?;
        Ok((deleted, orphans))
    }

    pub fn recover(&self) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending' WHERE state = 'attempting'", [])
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

    pub fn deliveries_for_id(&self, id: i64) -> Option<Delivery> {
        let sql = format!("SELECT {} FROM deliveries WHERE id = ?1", Self::DELIVERY_COLS);
        self.conn
            .prepare(&sql)
            .ok()?
            .query_row(params![id], Self::delivery_from_row)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use relay_core::{Endpoint, Envelope, Sender};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.db")).unwrap();
        (dir, s)
    }

    fn env() -> Envelope {
        let now = Utc::now();
        Envelope::new(
            "mocka:chan".parse().unwrap(),
            Sender { native_ref: "!a".into() },
            "text".into(), "hello".into(), now, now + Duration::hours(1), 8,
        )
    }

    fn dest() -> Endpoint { "mockb:chan".parse().unwrap() }

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
    fn due_deliveries_respect_next_attempt() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2).unwrap();
        let _future = s
            .insert_delivery(e.id, "general", &dest(), now + Duration::hours(1), e.expires_at, 2)
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
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2).unwrap();

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
        s.mark_terminal(id, "dead_letter", "RETRY_EXHAUSTED").unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "delivered");

        let id2 = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2).unwrap();
        s.mark_terminal(id2, "dead_letter", "RETRY_EXHAUSTED").unwrap();
        let d2 = s.deliveries_for(e.id).unwrap().into_iter().find(|d| d.id == id2).unwrap();
        assert_eq!(d2.reason.as_deref(), Some("RETRY_EXHAUSTED"));

        // that same dead-lettered row is also terminal: mark_delivered must
        // not fire on it either (guarded to 'attempting' only).
        s.mark_delivered(id2).unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap().into_iter()
            .find(|d| d.id == id2).unwrap().state, "dead_letter");
    }

    #[test]
    fn mark_delivered_ignores_rows_not_currently_attempting() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        // still 'pending': never entered 'attempting', so a stray delivered
        // ack must not apply.
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2).unwrap();
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
        let delivered_id = s.insert_delivery(
            delivered_msg.id, "general", &dest(), now, delivered_msg.expires_at, 2).unwrap();
        s.mark_attempting(delivered_id).unwrap();
        s.mark_delivered(delivered_id).unwrap();

        // pending message: must survive purge untouched.
        let pending_msg = env();
        s.insert_message(&pending_msg).unwrap();
        let pending_id = s.insert_delivery(
            pending_msg.id, "general", &dest(), now, pending_msg.expires_at, 2).unwrap();

        let (purged, orphans) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(purged, 1);
        assert!(orphans.is_empty(), "neither message in this test has attachments");

        assert!(s.deliveries_for(delivered_msg.id).unwrap().is_empty());
        assert!(s.get_message(delivered_msg.id).unwrap().is_none(),
            "orphaned message must be purged alongside its terminal delivery");

        let remaining = s.deliveries_for(pending_msg.id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, pending_id);
        assert_eq!(remaining[0].state, "pending");
        assert!(s.get_message(pending_msg.id).unwrap().is_some(),
            "message with a live pending delivery must survive purge");
    }

    fn attachment_shas_for(s: &Store, message_id: Uuid) -> Vec<String> {
        let mut stmt = s.conn
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
        s.insert_attachment_refs(e.id, &["sha2".to_string(), "sha1".to_string()]).unwrap();
        assert_eq!(attachment_shas_for(&s, e.id), vec!["sha1".to_string(), "sha2".to_string()]);
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
        s.insert_attachment_refs(delivered_msg.id, &["orphan-sha".to_string()]).unwrap();
        let delivered_id = s.insert_delivery(
            delivered_msg.id, "general", &dest(), now, delivered_msg.expires_at, 2).unwrap();
        s.mark_attempting(delivered_id).unwrap();
        s.mark_delivered(delivered_id).unwrap();

        // pending message with an attachment: its message survives, so the
        // sha must NOT be reported as orphaned nor have its ref row deleted.
        let pending_msg = env();
        s.insert_message(&pending_msg).unwrap();
        s.insert_attachment_refs(pending_msg.id, &["surviving-sha".to_string()]).unwrap();
        s.insert_delivery(pending_msg.id, "general", &dest(), now, pending_msg.expires_at, 2).unwrap();

        let (deleted, orphans) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(orphans, vec!["orphan-sha".to_string()]);

        assert!(attachment_shas_for(&s, delivered_msg.id).is_empty(),
            "orphaned attachment ref row must be deleted, not just reported");
        assert_eq!(attachment_shas_for(&s, pending_msg.id), vec!["surviving-sha".to_string()],
            "a pending message's attachment ref must survive purge");
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
        s.insert_attachment_refs(msg1.id, &["shared-sha".to_string()]).unwrap();
        let id1 = s.insert_delivery(msg1.id, "general", &dest(), now, msg1.expires_at, 2).unwrap();

        let msg2 = env();
        s.insert_message(&msg2).unwrap();
        s.insert_attachment_refs(msg2.id, &["shared-sha".to_string()]).unwrap();
        let id2 = s.insert_delivery(msg2.id, "general", &dest(), now, msg2.expires_at, 2).unwrap();

        // terminate + purge msg1 only. msg2 (and its ref to the same sha) is
        // still alive: the shared sha must NOT be reported as orphaned, and
        // msg2's ref row for it must remain untouched.
        s.mark_attempting(id1).unwrap();
        s.mark_delivered(id1).unwrap();
        let (purged1, orphans1) = s.purge_terminal(now + Duration::hours(1)).unwrap();
        assert_eq!(purged1, 1);
        assert!(orphans1.is_empty(),
            "sha still referenced by msg2 must not be reported as orphaned: {orphans1:?}");
        assert!(s.get_message(msg1.id).unwrap().is_none(), "msg1 must be purged");
        assert!(s.get_message(msg2.id).unwrap().is_some(), "msg2 must survive");
        assert_eq!(attachment_shas_for(&s, msg2.id), vec!["shared-sha".to_string()],
            "msg2's ref row for the shared sha must remain");

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
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 2).unwrap();
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
        s.insert_delivery(e.id, "r", &dest(), now, e.expires_at, 2).unwrap();
        let id2 = s.insert_delivery(e.id, "r", &dest(), now, e.expires_at, 2).unwrap();
        s.mark_terminal(id2, "dead_letter", "POLICY_DENIED").unwrap();
        let counts = s.queue_counts().unwrap();
        assert!(counts.contains(&("pending".to_string(), 1)));
        assert!(counts.contains(&("dead_letter".to_string(), 1)));
    }

    #[test]
    fn pending_count_counts_pending_and_attempting_scoped_by_route() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let a = s.insert_delivery(e.id, "route-a", &dest(), now, e.expires_at, 2).unwrap();
        s.insert_delivery(e.id, "route-a", &dest(), now, e.expires_at, 2).unwrap();
        let b = s.insert_delivery(e.id, "route-b", &dest(), now, e.expires_at, 2).unwrap();

        assert_eq!(s.pending_count(Some("route-a")).unwrap(), 2);
        assert_eq!(s.pending_count(Some("route-b")).unwrap(), 1);
        assert_eq!(s.pending_count(Some("route-c")).unwrap(), 0, "unknown route counts zero");
        assert_eq!(s.pending_count(None).unwrap(), 3, "global count sums every route");

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
        assert_eq!(s.pending_count(Some("general")).unwrap(), 0,
            "a dead-lettered row must never count as in-flight");
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
        let bulk1 = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 3).unwrap();
        let bulk2 = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 3).unwrap();
        // ...then one emergency (rank 0) row inserted last, same next_attempt.
        let emergency =
            s.insert_delivery(e.id, "general", &dest(), now, e.expires_at, 0).unwrap();

        let due = s.due_deliveries(now, 10).unwrap();
        assert_eq!(due.len(), 3);
        assert_eq!(due[0].id, emergency,
            "emergency (priority 0) must be scheduled first despite being inserted last: {due:?}");
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
            ).unwrap();
            raw.execute(
                "INSERT INTO deliveries
                   (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at)
                 VALUES (?1, 'general', 'mockb', 'chan', ?2, ?3)",
                params![msg_id.to_string(), ts(now), ts(now + Duration::hours(1))],
            ).unwrap();
        }

        // Store::open must migrate this in place, not error or wipe it.
        let s = Store::open(&path).unwrap();

        let has_priority: i64 = s.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('deliveries') WHERE name = 'priority'",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(has_priority, 1, "migration must add the priority column");

        // the pre-existing row must survive, backfilled to the default rank.
        let due = s.due_deliveries(now + Duration::seconds(1), 10).unwrap();
        assert_eq!(due.len(), 1, "the row that existed before migration must survive it");
        assert_eq!(due[0].priority, 2, "pre-existing rows must backfill to the default rank");
        assert_eq!(due[0].message_id, msg_id);

        // and the migration is idempotent: reopening (e.g. a daemon restart)
        // must not error or re-run the ALTER TABLE.
        drop(s);
        let s2 = Store::open(&path).unwrap();
        assert_eq!(s2.due_deliveries(now + Duration::seconds(1), 10).unwrap().len(), 1);
    }
}
