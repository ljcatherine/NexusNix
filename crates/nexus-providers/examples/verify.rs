//! Live provider verification: `cargo run -p nexus-providers --example verify`.
//! Codex: initialize + account/read + model/list (no model usage).
//! Claude Code: `auth status`, then (only if signed in) one tiny headless turn.

use nexus_providers::{claude::ClaudeCodeProvider, codex::CodexProvider, Provider};

fn main() {
    let only = std::env::args().nth(1);
    let providers: Vec<Box<dyn Provider>> = vec![Box::new(CodexProvider), Box::new(ClaudeCodeProvider)];
    for p in providers {
        if only.as_deref().is_some_and(|o| o != p.id()) {
            continue;
        }
        let c = p.verify();
        println!("{}: {}", p.name(), c.label());
        if let nexus_providers::Connection::Connected { models, .. } = &c {
            println!("  models: {}", models.join(", "));
        }
    }
}
