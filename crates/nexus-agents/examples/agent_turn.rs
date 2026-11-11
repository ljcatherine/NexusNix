//! Live Agent-mode acceptance in a scratch folder:
//! `cargo run -p nexus-agents --example agent_turn -- <scratch-dir>`
//! Creates a tiny project, snapshots it, asks Codex to edit it with
//! workspace-write, then prints the reviewable change set and reverts it.

use nexus_agents::snapshot::Snapshot;
use nexus_providers::{claude::ClaudeCodeProvider, codex::CodexProvider, Event, EventSink, Mode, Provider, ToolPolicy, TurnRequest};
use nexus_workspaces::changes::HunkState;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("scratch dir"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("greet.py"), "def greet(name):\n    return 'hello ' + name\n").unwrap();
    let snap = Snapshot::capture(&dir);
    let (tx, rx) = channel();
    let req = TurnRequest {
        workspace: dir.clone(),
        mode: if std::env::var("NEXUS_MODE").as_deref() == Ok("bypass") { Mode::Bypass } else { Mode::Agent },
        prompt: std::env::var("NEXUS_PROMPT").unwrap_or_else(|_| "In greet.py, change the greeting from 'hello ' to 'hi '. Edit only that file. Do not run any commands.".into()),
        attachments: vec![],
        media: vec![],
        resume: None,
        model: None,
        policy: ToolPolicy { write_files: true, run_commands: false, network: false },
        instructions: None,
        safety: Some("NEXUS SAFETY RULE: the Debian server is read-only; never connect to it.".into()),
    };
    let provider: Box<dyn Provider> = if std::env::var("NEXUS_PROVIDER").as_deref() == Ok("claude") { Box::new(ClaudeCodeProvider) } else { Box::new(CodexProvider) };
    let _h = provider.start(req, EventSink::new(tx, Arc::new(|| {}))).expect("start");
    loop {
        match rx.recv_timeout(Duration::from_secs(300)) {
            Ok(Event::Done { summary }) => {
                println!("DONE {summary:?}");
                break;
            }
            Ok(Event::Tool { kind, title, detail }) => println!("tool {kind}: {title} {detail}"),
            Ok(Event::Approval { kind, .. }) => println!("approval requested: {kind:?}"),
            Ok(Event::Error(e)) => println!("ERROR {e}"),
            Ok(Event::Log(l)) => println!("log {l}"),
            Ok(_) => {}
            Err(_) => {
                println!("TIMEOUT");
                break;
            }
        }
    }
    let mut set = snap.diff("agent", "codex");
    println!("changed files: {:?}", set.files.iter().map(|f| (&f.rel, f.stats())).collect::<Vec<_>>());
    for f in &mut set.files {
        print!("{}", f.unified());
        f.set_all(HunkState::Rejected);
        if let Some(orig) = f.result() {
            std::fs::write(dir.join(&f.rel), orig).unwrap();
        }
    }
    println!("after reject: {:?}", std::fs::read_to_string(dir.join("greet.py")).unwrap());
}
