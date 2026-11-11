//! `cargo run -p nexus-providers --example codex_sandbox` — print Codex's
//! Windows sandbox readiness (read-only query).
fn main() {
    match nexus_providers::codex::windows_sandbox_readiness() {
        Ok(s) => println!("windows sandbox: {s}"),
        Err(e) => println!("error: {e}"),
    }
}
