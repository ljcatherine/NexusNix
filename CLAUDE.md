@AGENTS.md

Claude-specific notes:
- Build/test: `nix build` (package + full test suite), or inside `nix develop`:
  `cargo build --workspace`, `cargo test --workspace`, run with `cargo run -p nexus-app`.
- Secret Service tests: `cargo test -p nexus-access -- --ignored` in a desktop session.
- Log every session in `docs/log/YYYY-MM-DD.md` and update `docs/STATUS.md`.
