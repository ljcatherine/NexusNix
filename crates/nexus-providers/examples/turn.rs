//! Live end-to-end turn: `cargo run -p nexus-providers --example turn -- codex "question"`.
//! Runs in Ask mode (read-only sandbox) in the current directory.

use nexus_providers::{claude::ClaudeCodeProvider, codex::CodexProvider, Event, EventSink, Mode, Provider, ToolPolicy, TurnRequest};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next().unwrap_or_else(|| "codex".into());
    let prompt = args.next().unwrap_or_else(|| "Reply with exactly the word: pong".into());
    let provider: Box<dyn Provider> = if which == "claude" { Box::new(ClaudeCodeProvider) } else { Box::new(CodexProvider) };
    let (tx, rx) = channel();
    let req = TurnRequest {
        workspace: std::env::current_dir().unwrap(),
        mode: Mode::Ask,
        prompt,
        attachments: vec![],
        // NEXUS_MEDIA=a.png;b.pdf attaches images/PDFs.
        media: std::env::var("NEXUS_MEDIA")
            .unwrap_or_default()
            .split(';')
            .filter(|p| !p.is_empty())
            .map(|p| nexus_providers::Media { path: p.into(), mime: nexus_providers::media_type(&std::fs::read(p).unwrap()).expect("image or PDF").into() })
            .collect(),
        resume: None,
        model: None,
        policy: ToolPolicy::READ_ONLY,
        instructions: None,
        safety: None,
    };
    let start = Instant::now();
    let _h = provider.start(req, EventSink::new(tx, Arc::new(|| {}))).expect("start");
    let mut text = String::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(180)) {
            Ok(Event::Text(t)) => text.push_str(&t),
            Ok(Event::Done { summary }) => {
                println!("DONE ({summary:?}) in {:.1}s", start.elapsed().as_secs_f32());
                break;
            }
            Ok(Event::Error(e)) => println!("ERROR: {e}"),
            Ok(other) => println!("event: {other:?}"),
            Err(_) => {
                println!("TIMEOUT");
                break;
            }
        }
    }
    println!("TEXT: {text}");
}
