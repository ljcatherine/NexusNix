//! Durable task memory and compaction records.
//!
//! The task memory is a structured, user-visible record of what a session is
//! doing. It survives provider context compaction and provider switches. A
//! compaction record stores the summary that replaced older turns; it is a
//! summary, not the original text, and the UI says so.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskMemory {
    pub objective: String,
    pub plan: Vec<String>,
    pub completed: Vec<String>,
    pub decisions: Vec<String>,
    pub code_locations: Vec<String>,
    pub pending_changes: Vec<String>,
    pub failed_attempts: Vec<String>,
    pub next_steps: Vec<String>,
}

impl TaskMemory {
    pub fn is_empty(&self) -> bool {
        self == &TaskMemory::default()
    }

    /// Markdown block prepended to prompts when switching providers or resuming
    /// after compaction.
    pub fn render(&self) -> String {
        let mut s = String::from("Task memory (maintained by Nexus; may be summarized):\n");
        if !self.objective.is_empty() {
            s.push_str(&format!("Objective: {}\n", self.objective));
        }
        for (title, items) in [
            ("Plan", &self.plan),
            ("Completed", &self.completed),
            ("Decisions", &self.decisions),
            ("Relevant code", &self.code_locations),
            ("Pending changes", &self.pending_changes),
            ("Failed attempts", &self.failed_attempts),
            ("Next steps", &self.next_steps),
        ] {
            if !items.is_empty() {
                s.push_str(&format!("{title}:\n"));
                for i in items {
                    s.push_str(&format!("- {i}\n"));
                }
            }
        }
        s
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactionRecord {
    pub at: String,
    /// Who compacted: "codex" (native), "claude" (native), "nexus" (local summary).
    pub by: String,
    /// Number of messages the summary replaced in the prompt (originals stay in
    /// the local transcript).
    pub replaced_messages: usize,
    pub summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renders_nonempty_sections_only() {
        let m = TaskMemory { objective: "Ship M2".into(), next_steps: vec!["tests".into()], ..Default::default() };
        let r = m.render();
        assert!(r.contains("Objective: Ship M2") && r.contains("Next steps:\n- tests") && !r.contains("Decisions"));
        assert!(TaskMemory::default().is_empty());
    }
}
