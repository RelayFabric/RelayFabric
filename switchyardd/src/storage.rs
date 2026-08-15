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
    pub attempt_count: u32,
    #[allow(dead_code)] // consumed by the admin API (Task 10); remove allow when used
    pub state: String,
    #[allow(dead_code)] // consumed by the admin API (Task 10); remove allow when used
    pub reason: Option<String>,
    #[allow(dead_code)] // consumed by the admin API (Task 10); remove allow when used
    pub next_attempt: DateTime<Utc>,
    #[allow(dead_code)] // consumed by the admin API (Task 10); remove allow when used
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
  attempt_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  next_attempt TEXT NOT NULL,
  attempted_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(state, next_attempt);
";

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

    pub fn insert_delivery(
        &self,
        message_id: Uuid,
        route: &str,
        dest: &Endpoint,
        next_attempt: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO deliveries
               (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![message_id.to_string(), route, dest.protocol, dest.endpoint,
                    ts(next_attempt), ts(expires_at)],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn delivery_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Delivery> {
        Ok(Delivery {
            id: row.get(0)?,
            message_id: row.get::<_, String>(1)?.parse().unwrap_or_default(),
            route: row.get(2)?,
            destination: Endpoint { protocol: row.get(3)?, endpoint: row.get(4)? },
            attempt_count: row.get(5)?,
            state: row.get(6)?,
            reason: row.get(7)?,
            next_attempt: parse_ts(&row.get::<_, String>(8)?),
            expires_at: parse_ts(&row.get::<_, String>(9)?),
        })
    }

    const DELIVERY_COLS: &'static str =
        "id, message_id, route, dest_protocol, dest_endpoint, attempt_count,
         state, reason, next_attempt, expires_at";

    pub fn due_deliveries(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> rusqlite::Result<Vec<Delivery>> {
        let sql = format!(
            "SELECT {} FROM deliveries
             WHERE state = 'pending' AND next_attempt <= ?1
             ORDER BY next_attempt LIMIT ?2",
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

    pub fn mark_delivered(&self, id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'delivered' WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn mark_retry(&self, id: i64, next_attempt: DateTime<Utc>) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending', next_attempt = ?2 WHERE id = ?1",
            params![id, ts(next_attempt)],
        )?;
        Ok(())
    }

    pub fn mark_terminal(&self, id: i64, state: &str, reason: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = ?2, reason = ?3 WHERE id = ?1",
            params![id, state, reason],
        )?;
        Ok(())
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

    #[allow(dead_code)] // consumed by the admin API (Task 10); remove allow when used
    pub fn queue_counts(&self) -> rusqlite::Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM deliveries GROUP BY state")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    #[allow(dead_code)] // consumed by the admin API (Task 10); remove allow when used
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
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();
        let _future = s
            .insert_delivery(e.id, "general", &dest(), now + Duration::hours(1), e.expires_at)
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
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();

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

        let id2 = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();
        s.mark_terminal(id2, "dead_letter", "RETRY_EXHAUSTED").unwrap();
        let d2 = s.deliveries_for(e.id).unwrap().into_iter().find(|d| d.id == id2).unwrap();
        assert_eq!(d2.reason.as_deref(), Some("RETRY_EXHAUSTED"));
    }

    #[test]
    fn recover_and_reclaim_requeue_attempting() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();
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
        s.insert_delivery(e.id, "r", &dest(), now, e.expires_at).unwrap();
        let id2 = s.insert_delivery(e.id, "r", &dest(), now, e.expires_at).unwrap();
        s.mark_terminal(id2, "dead_letter", "POLICY_DENIED").unwrap();
        let counts = s.queue_counts().unwrap();
        assert!(counts.contains(&("pending".to_string(), 1)));
        assert!(counts.contains(&("dead_letter".to_string(), 1)));
    }
}
