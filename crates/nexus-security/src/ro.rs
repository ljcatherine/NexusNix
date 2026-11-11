//! `nexus-ro/1`: the structured request form for hosts that enforce the catalog
//! server-side with the `nexus-ro` forced-command helper.
//!
//! The client never sends shell text. It sends `nexus-ro/1 <hex(JSON)>` where the
//! JSON is a [`CatalogCommand`]. The helper decodes it, validates it again against
//! its **own** read roots (the client's roots are not trusted), resolves paths
//! with `realpath` semantics and turns it into a [`Plan`]: a fixed program with an
//! argv list (no shell, except the constant metrics script) or an in-process
//! file read or hash.

use crate::catalog::{validate_remote_path, CatalogCommand, CatalogError, ReadRoots, METRICS_SCRIPT};
use crate::sensitive::is_sensitive_path;

pub const RO_PREFIX: &str = "nexus-ro/1 ";
/// Largest accepted request (hex-encoded JSON).
pub const MAX_REQUEST: usize = 64 * 1024;
/// Exit code and stderr tag used for every refusal.
pub const DENIED_EXIT: i32 = 126;

/// Git configuration that disables optional locks, monitors, maintenance,
/// pagers and external diff/textconv programs (same as the shell catalog).
pub const GIT_SAFE_ARGS: [&str; 14] = [
    "--no-optional-locks",
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", "gc.auto=0",
    "-c", "maintenance.auto=false",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "--no-pager",
];

/// What the client asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Catalog(CatalogCommand),
}

/// What the helper will do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Run `program` with exactly `args` (no shell), stdin closed.
    Spawn {
        program: &'static str,
        args: Vec<String>,
        /// Stop forwarding stdout after this many lines.
        max_lines: Option<usize>,
        /// Send the child's stderr to stdout (journalctl output).
        merge_stderr: bool,
    },
    ReadFile { path: String, max_bytes: u32 },
    HashFile { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoError {
    #[error("interactive shell or plain command refused; only nexus-ro/1 requests are accepted")]
    NotARequest,
    #[error("malformed request")]
    Malformed,
    #[error("{0}")]
    Catalog(#[from] CatalogError),
    #[error("path does not exist or cannot be resolved")]
    Unresolvable,
}

impl RoError {
    /// Short machine tag for the `nexus_denied\t<tag>` stderr line.
    pub fn tag(&self) -> &'static str {
        match self {
            RoError::NotARequest => "not_a_request",
            RoError::Malformed => "malformed",
            RoError::Catalog(CatalogError::OutsideRoots) => "outside_roots",
            RoError::Catalog(CatalogError::Sensitive) => "sensitive",
            RoError::Catalog(_) => "invalid",
            RoError::Unresolvable => "unresolvable",
        }
    }
}

/// Client side: encode a catalog command. It is validated against the client's
/// roots first so obvious mistakes fail locally.
pub fn encode_request(cmd: &CatalogCommand, roots: &ReadRoots) -> Result<String, CatalogError> {
    cmd.render(roots)?;
    let json = serde_json::to_vec(cmd).map_err(|_| CatalogError::InvalidParameter)?;
    Ok(format!("{RO_PREFIX}{}", hex::encode(json)))
}

/// Helper side: decode `SSH_ORIGINAL_COMMAND`.
pub fn decode_request(original: Option<&str>) -> Result<Request, RoError> {
    let Some(original) = original else { return Err(RoError::NotARequest) };
    let o = original.trim();
    let Some(hexpart) = o.strip_prefix(RO_PREFIX) else { return Err(RoError::NotARequest) };
    if hexpart.len() > MAX_REQUEST {
        return Err(RoError::Malformed);
    }
    let bytes = hex::decode(hexpart).map_err(|_| RoError::Malformed)?;
    let cmd: CatalogCommand = serde_json::from_slice(&bytes).map_err(|_| RoError::Malformed)?;
    Ok(Request::Catalog(cmd))
}

/// Helper side: validate against the server's roots and build the plan.
/// `resolve` is `realpath -e` (injected so this is testable anywhere).
pub fn plan(req: &Request, roots: &ReadRoots, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Plan, RoError> {
    let Request::Catalog(cmd) = req;
    // Same lexical validation (units, counts, roots, sensitive names) as the shell form.
    cmd.render(roots)?;
    let checked = |p: &str| -> Result<String, RoError> {
        let real = resolve(p).ok_or(RoError::Unresolvable)?;
        validate_remote_path(&real, roots)?;
        if is_sensitive_path(&real) {
            return Err(CatalogError::Sensitive.into());
        }
        Ok(real)
    };
    let spawn = |program: &'static str, args: Vec<String>| Plan::Spawn { program, args, max_lines: None, merge_stderr: false };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let git = |repo: &str, rest: &[&str]| -> Result<Plan, RoError> {
        let real = checked(repo)?;
        let mut a = s(&GIT_SAFE_ARGS);
        a.push("-C".into());
        a.push(real);
        a.extend(rest.iter().map(|x| x.to_string()));
        Ok(spawn("git", a))
    };
    Ok(match cmd {
        CatalogCommand::Metrics => spawn("sh", vec!["-c".into(), METRICS_SCRIPT.into()]),
        CatalogCommand::Uname => spawn("uname", s(&["-a"])),
        // Constant path (a symlink to /usr/lib/os-release on Debian); resolved
        // because the helper opens files without following symlinks.
        CatalogCommand::OsRelease => Plan::ReadFile { path: resolve("/etc/os-release").ok_or(RoError::Unresolvable)?, max_bytes: 64 * 1024 },
        CatalogCommand::Uptime => spawn("uptime", vec![]),
        CatalogCommand::ProcessList => spawn("ps", s(&["-eo", "pid,user,pcpu,pmem,etime,comm", "--sort=-pcpu", "--no-headers"])),
        CatalogCommand::DiskUsage => spawn("df", s(&["-hPT", "-x", "tmpfs", "-x", "devtmpfs"])),
        CatalogCommand::MemoryInfo => spawn("free", s(&["-b"])),
        CatalogCommand::NetworkAddresses => spawn("ip", s(&["-brief", "address"])),
        CatalogCommand::ListeningSockets => spawn("ss", s(&["-tulnH"])),
        CatalogCommand::ServiceList => spawn("systemctl", s(&["--no-legend", "--no-pager", "--plain", "list-units", "--type=service", "--all"])),
        CatalogCommand::UserServiceList => spawn("systemctl", s(&["--user", "--no-legend", "--no-pager", "--plain", "list-units", "--type=service", "--all"])),
        CatalogCommand::ServiceStatus { unit } => spawn("systemctl", vec!["--no-pager".into(), "--lines=0".into(), "status".into(), "--".into(), unit.clone()]),
        CatalogCommand::UserServiceStatus { unit } => {
            spawn("systemctl", vec!["--user".into(), "--no-pager".into(), "--lines=0".into(), "status".into(), "--".into(), unit.clone()])
        }
        CatalogCommand::ServiceLogs { unit, lines } | CatalogCommand::UserServiceLogs { unit, lines } => {
            let mut a = Vec::new();
            if matches!(cmd, CatalogCommand::UserServiceLogs { .. }) {
                a.push("--user".to_string());
            }
            a.extend(["--no-pager".into(), "--output=short-iso".into(), format!("--lines={lines}"), "--unit".into(), unit.clone()]);
            Plan::Spawn { program: "journalctl", args: a, max_lines: None, merge_stderr: true }
        }
        CatalogCommand::ListDirectory { path } => spawn("ls", vec!["-la".into(), "--time-style=+%s".into(), "--".into(), checked(path)?]),
        CatalogCommand::ReadFile { path, max_bytes } => Plan::ReadFile { path: checked(path)?, max_bytes: *max_bytes },
        CatalogCommand::HashFile { path } => Plan::HashFile { path: checked(path)? },
        CatalogCommand::FindFiles { root, max_depth } => {
            let mut a = vec![checked(root)?, "-maxdepth".into(), max_depth.to_string()];
            a.extend(s(&["(", "-name", ".git", "-o", "-name", "node_modules", "-o", "-name", "target", "-o", "-name", ".ssh", ")", "-prune", "-o", "-type", "f", "-size", "-2M", "-printf", "%P\t%s\t%T@\n"]));
            Plan::Spawn { program: "find", args: a, max_lines: Some(20_000), merge_stderr: false }
        }
        CatalogCommand::GitStatus { repo } => git(repo, &["status", "--porcelain=v2", "--branch"])?,
        CatalogCommand::GitLog { repo, count } => {
            let n = format!("--max-count={count}");
            git(repo, &["log", "--no-color", &n, "--format=%H%x09%an%x09%at%x09%s"])?
        }
        CatalogCommand::GitDiff { repo } => git(repo, &["diff", "--no-color", "--no-ext-diff", "--no-textconv"])?,
        CatalogCommand::GitShowFile { repo, rev, path } => {
            let spec = format!("{rev}:{path}");
            git(repo, &["show", "--no-textconv", &spec])?
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> ReadRoots {
        ReadRoots::for_home("/home/debian")
    }

    fn ident(p: &str) -> Option<String> {
        Some(p.to_string())
    }

    fn roundtrip(c: CatalogCommand) -> Plan {
        let line = encode_request(&c, &roots()).unwrap();
        assert!(line.starts_with(RO_PREFIX));
        assert!(line.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'/' || b == b'-'), "{line}");
        let req = decode_request(Some(&line)).unwrap();
        assert_eq!(req, Request::Catalog(c));
        plan(&req, &roots(), &ident).unwrap()
    }

    #[test]
    fn encodes_and_plans_without_a_shell() {
        let cases = vec![
            CatalogCommand::Uname,
            CatalogCommand::OsRelease,
            CatalogCommand::ServiceStatus { unit: "nexus-gateway.service".into() },
            CatalogCommand::ServiceLogs { unit: "minecraft".into(), lines: 100 },
            CatalogCommand::ListDirectory { path: "/home/debian/projects".into() },
            CatalogCommand::FindFiles { root: "/home/debian/p".into(), max_depth: 6 },
            CatalogCommand::GitStatus { repo: "/home/debian/p".into() },
            CatalogCommand::GitShowFile { repo: "/home/debian/p".into(), rev: "HEAD".into(), path: "src/a.rs".into() },
        ];
        let forbidden = ["rm", "mv", "cp", "tee", "dd", "chmod", "chown", "mkdir", "touch", "restart", "start", "stop", "reload", "enable", "disable", "kill", "-delete", "-exec", "-execdir", "-fprintf", "-fprint", "-fls", "-ok", "commit", "push", "fetch", "pull", "checkout", "reset", "gc"];
        for c in cases {
            match roundtrip(c.clone()) {
                Plan::Spawn { program, args, .. } => {
                    assert_ne!(program, "sh", "{c:?}");
                    assert_ne!(program, "bash", "{c:?}");
                    for a in &args {
                        assert!(!forbidden.contains(&a.as_str()), "{c:?} has {a}");
                    }
                }
                Plan::ReadFile { .. } | Plan::HashFile { .. } => {}
            }
        }
        // The only shell use is the constant metrics script.
        assert_eq!(roundtrip(CatalogCommand::Metrics), Plan::Spawn { program: "sh", args: vec!["-c".into(), METRICS_SCRIPT.into()], max_lines: None, merge_stderr: false });
    }

    #[test]
    fn git_runs_with_safe_flags_and_resolved_repo() {
        let req = Request::Catalog(CatalogCommand::GitDiff { repo: "/home/debian/link".into() });
        let p = plan(&req, &roots(), &|_| Some("/srv/real".into())).unwrap();
        let Plan::Spawn { program, args, .. } = p else { panic!() };
        assert_eq!(program, "git");
        assert_eq!(&args[..14], &GIT_SAFE_ARGS.map(String::from));
        assert_eq!(args[14..16], ["-C".to_string(), "/srv/real".to_string()]);
    }

    #[test]
    fn refuses_plain_commands_and_shells() {
        for o in [None, Some(""), Some("bash"), Some("id"), Some("touch /tmp/x"), Some("nexus-ro/1"), Some("scp -t /tmp"), Some("rsync --server . /")] {
            assert_eq!(decode_request(o), Err(RoError::NotARequest), "{o:?}");
        }
        assert_eq!(decode_request(Some("nexus-ro/1 zz")), Err(RoError::Malformed));
        assert_eq!(decode_request(Some(&format!("nexus-ro/1 {}", hex::encode(br#"{"command":"rm_rf"}"#)))), Err(RoError::Malformed));
        let huge = format!("nexus-ro/1 {}", "0".repeat(MAX_REQUEST + 2));
        assert_eq!(decode_request(Some(&huge)), Err(RoError::Malformed));
    }

    #[test]
    fn server_roots_win_over_client_roots() {
        // A client with wide roots asks for /etc/passwd; the server's roots refuse it.
        let wide = ReadRoots(vec!["/".into()]);
        let line = encode_request(&CatalogCommand::ReadFile { path: "/etc/passwd".into(), max_bytes: 100 }, &wide).unwrap();
        let req = decode_request(Some(&line)).unwrap();
        assert_eq!(plan(&req, &roots(), &ident), Err(RoError::Catalog(CatalogError::OutsideRoots)));
    }

    #[test]
    fn symlinks_are_checked_after_resolution() {
        let req = Request::Catalog(CatalogCommand::ReadFile { path: "/home/debian/innocent".into(), max_bytes: 100 });
        assert_eq!(plan(&req, &roots(), &|_| Some("/etc/passwd".into())).unwrap_err().tag(), "outside_roots");
        assert_eq!(plan(&req, &roots(), &|_| Some("/home/debian/.ssh/id_ed25519".into())).unwrap_err().tag(), "sensitive");
        assert_eq!(plan(&req, &roots(), &|_| None), Err(RoError::Unresolvable));
    }

    #[test]
    fn injection_in_parameters_is_refused_before_planning() {
        let bad = [
            CatalogCommand::ServiceLogs { unit: "x; rm -rf /".into(), lines: 10 },
            CatalogCommand::ServiceStatus { unit: "--now".into() },
            CatalogCommand::GitShowFile { repo: "/home/debian/p".into(), rev: "--output=/tmp/x".into(), path: "a".into() },
            CatalogCommand::GitShowFile { repo: "/home/debian/p".into(), rev: "HEAD".into(), path: "-x".into() },
            CatalogCommand::ReadFile { path: "/home/debian/../../etc/shadow".into(), max_bytes: 10 },
            CatalogCommand::FindFiles { root: "/home/debian".into(), max_depth: 99 },
        ];
        for c in bad {
            assert!(plan(&Request::Catalog(c.clone()), &roots(), &ident).is_err(), "{c:?}");
        }
    }

    #[test]
    fn refuses_sftp_subsystem_commands() {
        for original in ["sftp", "internal-sftp", "/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server", "/usr/lib/sftp-server", "internal-sftp -R"] {
            assert_eq!(decode_request(Some(original)), Err(RoError::NotARequest), "{original}");
        }
    }
}
