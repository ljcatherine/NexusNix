//! SQLite persistence for agent sessions (local only; nothing is uploaded).

use crate::memory::{CompactionRecord, TaskMemory};
use crate::now_rfc3339;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionRow {
    pub id: String,
    pub title: String,
    pub provider: String,
    /// Provider-side session/thread id for resume, if any.
    pub provider_session: Option<String>,
    pub workspace: String,
    pub mode: String,
    pub created: String,
    pub updated: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageRow {
    pub role: String,
    pub content: String,
    pub provider: String,
    pub at: String,
}

pub struct Store {
    db: Connection,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> rusqlite::Result<Self> {
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, title TEXT, provider TEXT, provider_session TEXT,
               workspace TEXT, mode TEXT, created TEXT, updated TEXT, status TEXT, memory TEXT);
             CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT REFERENCES sessions(id) ON DELETE CASCADE,
               role TEXT, content TEXT, provider TEXT, at TEXT);
             CREATE TABLE IF NOT EXISTS compactions(id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT REFERENCES sessions(id) ON DELETE CASCADE,
               at TEXT, by TEXT, replaced INTEGER, summary TEXT);
             CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT REFERENCES sessions(id) ON DELETE CASCADE,
               at TEXT, kind TEXT, detail TEXT);",
        )?;
        Ok(Self { db })
    }

    pub fn create(&self, title: &str, provider: &str, workspace: &str, mode: &str) -> rusqlite::Result<SessionRow> {
        let now = now_rfc3339();
        let row = SessionRow {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.into(),
            provider: provider.into(),
            provider_session: None,
            workspace: workspace.into(),
            mode: mode.into(),
            created: now.clone(),
            updated: now,
            status: "idle".into(),
        };
        self.db.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL)",
            params![row.id, row.title, row.provider, row.provider_session, row.workspace, row.mode, row.created, row.updated, row.status],
        )?;
        Ok(row)
    }

    pub fn list(&self, workspace: Option<&str>) -> rusqlite::Result<Vec<SessionRow>> {
        let mut st = self.db.prepare(
            "SELECT id,title,provider,provider_session,workspace,mode,created,updated,status FROM sessions
             WHERE ?1 IS NULL OR workspace = ?1 ORDER BY updated DESC LIMIT 500",
        )?;
        let rows = st.query_map(params![workspace], |r| {
            Ok(SessionRow {
                id: r.get(0)?,
                title: r.get(1)?,
                provider: r.get(2)?,
                provider_session: r.get(3)?,
                workspace: r.get(4)?,
                mode: r.get(5)?,
                created: r.get(6)?,
                updated: r.get(7)?,
                status: r.get(8)?,
            })
        })?;
        rows.collect()
    }

    pub fn set_provider_session(&self, id: &str, provider: &str, ps: &str) -> rusqlite::Result<()> {
        self.db.execute("UPDATE sessions SET provider=?2, provider_session=?3, updated=?4 WHERE id=?1", params![id, provider, ps, now_rfc3339()])?;
        Ok(())
    }

    pub fn set_status(&self, id: &str, status: &str) -> rusqlite::Result<()> {
        self.db.execute("UPDATE sessions SET status=?2, updated=?3 WHERE id=?1", params![id, status, now_rfc3339()])?;
        Ok(())
    }

    pub fn rename(&self, id: &str, title: &str) -> rusqlite::Result<()> {
        self.db.execute("UPDATE sessions SET title=?2 WHERE id=?1", params![id, title])?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM sessions WHERE id=?1", params![id])?;
        Ok(())
    }

    pub fn add_message(&self, session: &str, role: &str, content: &str, provider: &str) -> rusqlite::Result<()> {
        let now = now_rfc3339();
        self.db.execute("INSERT INTO messages(session,role,content,provider,at) VALUES(?1,?2,?3,?4,?5)", params![session, role, content, provider, now])?;
        self.db.execute("UPDATE sessions SET updated=?2 WHERE id=?1", params![session, now])?;
        Ok(())
    }

    pub fn messages(&self, session: &str) -> rusqlite::Result<Vec<MessageRow>> {
        let mut st = self.db.prepare("SELECT role,content,provider,at FROM messages WHERE session=?1 ORDER BY id")?;
        let rows = st.query_map(params![session], |r| Ok(MessageRow { role: r.get(0)?, content: r.get(1)?, provider: r.get(2)?, at: r.get(3)? }))?;
        rows.collect()
    }

    pub fn log_activity(&self, session: &str, kind: &str, detail: &str) -> rusqlite::Result<()> {
        self.db.execute("INSERT INTO activity(session,at,kind,detail) VALUES(?1,?2,?3,?4)", params![session, now_rfc3339(), kind, detail])?;
        Ok(())
    }

    pub fn activity(&self, session: &str) -> rusqlite::Result<Vec<(String, String, String)>> {
        let mut st = self.db.prepare("SELECT at,kind,detail FROM activity WHERE session=?1 ORDER BY id")?;
        let rows = st.query_map(params![session], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    pub fn memory(&self, session: &str) -> rusqlite::Result<TaskMemory> {
        let v: Option<Option<String>> = self.db.query_row("SELECT memory FROM sessions WHERE id=?1", params![session], |r| r.get(0)).optional()?;
        Ok(v.flatten().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default())
    }

    pub fn set_memory(&self, session: &str, m: &TaskMemory) -> rusqlite::Result<()> {
        let json = serde_json::to_string(m).unwrap_or_default();
        self.db.execute("UPDATE sessions SET memory=?2 WHERE id=?1", params![session, json])?;
        Ok(())
    }

    pub fn add_compaction(&self, session: &str, c: &CompactionRecord) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO compactions(session,at,by,replaced,summary) VALUES(?1,?2,?3,?4,?5)",
            params![session, c.at, c.by, c.replaced_messages as i64, c.summary],
        )?;
        Ok(())
    }

    pub fn compactions(&self, session: &str) -> rusqlite::Result<Vec<CompactionRecord>> {
        let mut st = self.db.prepare("SELECT at,by,replaced,summary FROM compactions WHERE session=?1 ORDER BY id")?;
        let rows = st.query_map(params![session], |r| {
            Ok(CompactionRecord { at: r.get(0)?, by: r.get(1)?, replaced_messages: r.get::<_, i64>(2)? as usize, summary: r.get(3)? })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("s.db");
        let id = {
            let s = Store::open(&path).unwrap();
            let row = s.create("Fix bug", "codex", "C:/ws", "Agent").unwrap();
            s.add_message(&row.id, "user", "hi", "codex").unwrap();
            s.add_message(&row.id, "assistant", "hello", "codex").unwrap();
            s.set_provider_session(&row.id, "codex", "thread-1").unwrap();
            s.set_memory(&row.id, &TaskMemory { objective: "x".into(), ..Default::default() }).unwrap();
            s.add_compaction(&row.id, &CompactionRecord { at: "t".into(), by: "nexus".into(), replaced_messages: 2, summary: "s".into() }).unwrap();
            s.log_activity(&row.id, "command", "cargo test").unwrap();
            row.id
        };
        let s = Store::open(&path).unwrap();
        let l = s.list(Some("C:/ws")).unwrap();
        assert_eq!(l[0].provider_session.as_deref(), Some("thread-1"));
        assert_eq!(s.messages(&id).unwrap().len(), 2);
        assert_eq!(s.memory(&id).unwrap().objective, "x");
        assert_eq!(s.compactions(&id).unwrap()[0].replaced_messages, 2);
        assert_eq!(s.activity(&id).unwrap().len(), 1);
        s.delete(&id).unwrap();
        assert!(s.list(None).unwrap().is_empty());
        assert!(s.messages(&id).unwrap().is_empty());
    }
}
