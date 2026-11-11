//! The fixed catalog of observational commands allowed on read-only hosts
//! (always including Debian).
//!
//! There is no free-text command path here. Each variant renders to a command
//! line built from constant program names and flags; the only variable parts
//! (unit names, paths, counts) are validated against strict patterns and passed
//! as single-quoted POSIX words. Every command is reviewed to be free of
//! persistent side effects:
//! * Git runs with `--no-optional-locks`, `core.fsmonitor=false`,
//!   `core.untrackedCache=false`, `gc.auto=0` and `maintenance.auto=false` so it
//!   does not refresh the index, run hooks/monitors or start maintenance.
//! * File reads resolve symlinks first and refuse anything outside the
//!   configured read roots or matching sensitive-file patterns.
//! * No command takes `sudo`, writes to a path, or spawns an editor/pager.

use crate::sensitive::is_sensitive_path;
use crate::shell::quote;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// The iOS app's read-only `/proc` metrics script (`HostMetricsCommand.swift`),
/// unchanged so both apps read identical data.
pub const METRICS_SCRIPT: &str = r#"printf 'nexus_metrics\t1\n'
if [ -r /proc/sys/kernel/random/boot_id ]; then
  IFS= read -r boot_id < /proc/sys/kernel/random/boot_id
  printf 'boot_id\t%s\n' "$boot_id"
fi
if [ -r /proc/uptime ]; then awk '{ print "uptime\t" $1 }' /proc/uptime; fi
if [ -r /proc/loadavg ]; then awk '{ print "load\t" $1 "\t" $2 "\t" $3 }' /proc/loadavg; fi
if [ -r /proc/stat ]; then awk '$1 ~ /^cpu[0-9]+$/ { count++ } END { if (count > 0) print "cpu_count\t" count }' /proc/stat; fi
if [ -r /proc/stat ]; then
  read_cpu() { awk '/^cpu / { total=0; for (i=2; i<=9; i++) total += $i; idle=$5+$6; printf "%.0f %.0f\n", total, idle; exit }' /proc/stat; }
  cpu_before=$(read_cpu)
  sleep 1
  cpu_after=$(read_cpu)
  if [ -n "$cpu_before" ] && [ -n "$cpu_after" ]; then
    awk -v before="$cpu_before" -v after="$cpu_after" 'BEGIN { split(before,b," "); split(after,a," "); dt=a[1]-b[1]; di=a[2]-b[2]; if (dt>0 && di>=0 && di<=dt) printf "cpu_utilization\t%.2f\n", (dt-di)*100/dt }'
  fi
fi
if [ -r /proc/meminfo ]; then awk '/^MemTotal:/ { total=$2 } /^MemAvailable:/ { available=$2; has_available=1 } END { if (total > 0 && has_available) printf "memory\t%.0f\t%.0f\n", total * 1024, available * 1024 }' /proc/meminfo; fi
df -Pk / 2>/dev/null | awk 'NR == 2 { printf "filesystem\t%.0f\t%.0f\t%.0f\n", $2 * 1024, $3 * 1024, $4 * 1024 }'
if [ -r /proc/net/dev ]; then awk 'NR > 2 { interface=$1; sub(/:$/, "", interface); if (interface != "lo") printf "network\t%s\t%s\t%s\n", interface, $2, $10 }' /proc/net/dev; fi
if command -v nvidia-smi >/dev/null 2>&1; then
  printf 'nvidia_tool\tavailable\n'
  nvidia-smi --query-gpu=index,utilization.gpu,memory.total,memory.used,temperature.gpu --format=csv,noheader,nounits 2>/dev/null |
    awk -F, '{ for (i=1; i<=5; i++) gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i); if ($1 ~ /^[0-9]+$/) printf "nvidia\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5 }'
else
  printf 'nvidia_tool\tunavailable\n'
fi"#;

const GIT_SAFE: &str = "git --no-optional-locks -c core.fsmonitor=false -c core.untrackedCache=false -c gc.auto=0 -c maintenance.auto=false -c core.pager=cat -c diff.external= --no-pager";

/// A catalog command with validated parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CatalogCommand {
    Metrics,
    Uname,
    OsRelease,
    Uptime,
    ProcessList,
    DiskUsage,
    MemoryInfo,
    NetworkAddresses,
    ListeningSockets,
    ServiceList,
    ServiceStatus { unit: String },
    ServiceLogs { unit: String, lines: u32 },
    UserServiceList,
    UserServiceStatus { unit: String },
    UserServiceLogs { unit: String, lines: u32 },
    ListDirectory { path: String },
    ReadFile { path: String, max_bytes: u32 },
    HashFile { path: String },
    FindFiles { root: String, max_depth: u8 },
    GitStatus { repo: String },
    GitLog { repo: String, count: u32 },
    GitDiff { repo: String },
    GitShowFile { repo: String, rev: String, path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error("Invalid unit name")]
    InvalidUnit,
    #[error("Invalid or disallowed path: {0}")]
    InvalidPath(String),
    #[error("Path is outside the authorized read roots")]
    OutsideRoots,
    #[error("Refusing to read a sensitive file")]
    Sensitive,
    #[error("Invalid parameter")]
    InvalidParameter,
}

/// Read roots for path-taking catalog commands on a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadRoots(pub Vec<String>);

impl ReadRoots {
    /// The Debian account's home (from the site file) plus the system log
    /// and service directories.
    pub fn debian_default() -> Self {
        Self::for_home(&format!("/home/{}", nexus_core::site::site().debian_user))
    }

    /// `home` plus `/var/log`, `/srv` and `/opt`.
    pub fn for_home(home: &str) -> Self {
        Self(vec![home.into(), "/var/log".into(), "/srv".into(), "/opt".into()])
    }
}

fn unit_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9@._:\\-]{0,127}$").unwrap())
}

fn rev_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(HEAD(~[0-9]{1,4})?|[0-9a-f]{7,40})$").unwrap())
}

fn validate_unit(u: &str) -> Result<(), CatalogError> {
    if unit_re().is_match(u) { Ok(()) } else { Err(CatalogError::InvalidUnit) }
}

/// Validate an absolute POSIX path lexically against the read roots.
pub fn validate_remote_path(p: &str, roots: &ReadRoots) -> Result<(), CatalogError> {
    if !p.starts_with('/') || p.len() > 4096 || p.contains('\0') || p.chars().any(|c| c.is_control()) {
        return Err(CatalogError::InvalidPath(p.into()));
    }
    if p.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(CatalogError::InvalidPath(p.into()));
    }
    if is_sensitive_path(p) {
        return Err(CatalogError::Sensitive);
    }
    let trimmed = p.trim_end_matches('/');
    let inside = roots.0.iter().any(|r| {
        let r = r.trim_end_matches('/');
        trimmed == r || trimmed.starts_with(&format!("{r}/"))
    });
    if inside { Ok(()) } else { Err(CatalogError::OutsideRoots) }
}

fn validate_rel(p: &str) -> Result<(), CatalogError> {
    if p.is_empty() || p.starts_with('/') || p.starts_with('-') || p.contains('\0') || p.split('/').any(|s| s == "..") || is_sensitive_path(p) {
        return Err(CatalogError::InvalidPath(p.into()));
    }
    Ok(())
}

/// Shell snippet that resolves `$p` and refuses if it escapes the roots or is
/// sensitive by name after resolution. Every interpolated word is quoted.
fn resolve_guard(path: &str, roots: &ReadRoots) -> String {
    let cases: Vec<String> = roots
        .0
        .iter()
        .map(|r| {
            let r = r.trim_end_matches('/');
            format!("{q}|{q}/*", q = quote(r))
        })
        .collect();
    format!(
        "p=$(realpath -e -- {path}) || exit 2; case \"$p\" in {cases}) ;; *) printf 'nexus_denied\\toutside_roots\\n' >&2; exit 3;; esac; case \"$p\" in */.ssh/*|*/.gnupg/*|*.pem|*.key|*/.env|*/id_rsa|*/id_ed25519|*/shadow|*.env) printf 'nexus_denied\\tsensitive\\n' >&2; exit 3;; esac; ",
        path = quote(path),
        cases = cases.join("|"),
    )
}

impl CatalogCommand {
    /// Short label for UIs and audit logs.
    pub fn label(&self) -> String {
        match self {
            CatalogCommand::Metrics => "host metrics".into(),
            CatalogCommand::ServiceStatus { unit } | CatalogCommand::UserServiceStatus { unit } => format!("status {unit}"),
            CatalogCommand::ServiceLogs { unit, lines } | CatalogCommand::UserServiceLogs { unit, lines } => format!("logs {unit} ({lines} lines)"),
            CatalogCommand::ListDirectory { path } => format!("ls {path}"),
            CatalogCommand::ReadFile { path, .. } => format!("read {path}"),
            CatalogCommand::HashFile { path } => format!("sha256 {path}"),
            CatalogCommand::FindFiles { root, .. } => format!("find {root}"),
            CatalogCommand::GitStatus { repo } => format!("git status {repo}"),
            CatalogCommand::GitLog { repo, .. } => format!("git log {repo}"),
            CatalogCommand::GitDiff { repo } => format!("git diff {repo}"),
            CatalogCommand::GitShowFile { repo, rev, path } => format!("git show {rev}:{path} in {repo}"),
            other => format!("{other:?}").to_lowercase(),
        }
    }

    /// Validate parameters and render the exact remote command line.
    pub fn render(&self, roots: &ReadRoots) -> Result<String, CatalogError> {
        let body = match self {
            CatalogCommand::Metrics => METRICS_SCRIPT.to_string(),
            CatalogCommand::Uname => "uname -a".into(),
            CatalogCommand::OsRelease => "cat /etc/os-release".into(),
            CatalogCommand::Uptime => "uptime".into(),
            CatalogCommand::ProcessList => "ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pcpu --no-headers".into(),
            CatalogCommand::DiskUsage => "df -hPT -x tmpfs -x devtmpfs".into(),
            CatalogCommand::MemoryInfo => "free -b".into(),
            CatalogCommand::NetworkAddresses => "ip -brief address".into(),
            CatalogCommand::ListeningSockets => "ss -tulnH".into(),
            CatalogCommand::ServiceList => "systemctl --no-legend --no-pager --plain list-units --type=service --all".into(),
            CatalogCommand::UserServiceList => "systemctl --user --no-legend --no-pager --plain list-units --type=service --all".into(),
            CatalogCommand::ServiceStatus { unit } => {
                validate_unit(unit)?;
                format!("systemctl --no-pager --lines=0 status -- {}", quote(unit))
            }
            CatalogCommand::UserServiceStatus { unit } => {
                validate_unit(unit)?;
                format!("systemctl --user --no-pager --lines=0 status -- {}", quote(unit))
            }
            CatalogCommand::ServiceLogs { unit, lines } | CatalogCommand::UserServiceLogs { unit, lines } => {
                validate_unit(unit)?;
                if *lines == 0 || *lines > 2000 {
                    return Err(CatalogError::InvalidParameter);
                }
                let user = if matches!(self, CatalogCommand::UserServiceLogs { .. }) { "--user " } else { "" };
                format!("journalctl {user}--no-pager --output=short-iso --lines={lines} --unit {} 2>&1", quote(unit))
            }
            CatalogCommand::ListDirectory { path } => {
                validate_remote_path(path, roots)?;
                format!("{}ls -la --time-style=+%s -- \"$p\"", resolve_guard(path, roots))
            }
            CatalogCommand::ReadFile { path, max_bytes } => {
                validate_remote_path(path, roots)?;
                if *max_bytes == 0 || *max_bytes > 8 * 1024 * 1024 {
                    return Err(CatalogError::InvalidParameter);
                }
                format!("{}[ -f \"$p\" ] || exit 4; head -c {max_bytes} -- \"$p\"", resolve_guard(path, roots))
            }
            CatalogCommand::HashFile { path } => {
                validate_remote_path(path, roots)?;
                format!("{}[ -f \"$p\" ] || exit 4; sha256sum -- \"$p\"", resolve_guard(path, roots))
            }
            CatalogCommand::FindFiles { root, max_depth } => {
                validate_remote_path(root, roots)?;
                if *max_depth == 0 || *max_depth > 12 {
                    return Err(CatalogError::InvalidParameter);
                }
                format!(
                    "{}find \"$p\" -maxdepth {max_depth} \\( -name .git -o -name node_modules -o -name target -o -name .ssh \\) -prune -o -type f -size -2M -printf '%P\\t%s\\t%T@\\n' | head -n 20000",
                    resolve_guard(root, roots)
                )
            }
            CatalogCommand::GitStatus { repo } => {
                validate_remote_path(repo, roots)?;
                format!("{GIT_SAFE} -C {} status --porcelain=v2 --branch", quote(repo))
            }
            CatalogCommand::GitLog { repo, count } => {
                validate_remote_path(repo, roots)?;
                if *count == 0 || *count > 500 {
                    return Err(CatalogError::InvalidParameter);
                }
                format!("{GIT_SAFE} -C {} log --no-color --max-count={count} --format=%H%x09%an%x09%at%x09%s", quote(repo))
            }
            CatalogCommand::GitDiff { repo } => {
                validate_remote_path(repo, roots)?;
                format!("{GIT_SAFE} -C {} diff --no-color --no-ext-diff --no-textconv", quote(repo))
            }
            CatalogCommand::GitShowFile { repo, rev, path } => {
                validate_remote_path(repo, roots)?;
                validate_rel(path)?;
                if !rev_re().is_match(rev) {
                    return Err(CatalogError::InvalidParameter);
                }
                format!("{GIT_SAFE} -C {} show --no-textconv {}", quote(repo), quote(&format!("{rev}:{path}")))
            }
        };
        Ok(wrap_timeout(&body, 30))
    }
}

/// Bound runtime with coreutils `timeout`, as the iOS app does. The whole body is
/// passed as one quoted argument to `sh -c`.
fn wrap_timeout(body: &str, seconds: u32) -> String {
    format!(
        "LC_ALL=C timeout -s TERM -k 2s {seconds}s sh -c {}",
        quote(body)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> ReadRoots {
        ReadRoots::for_home("/home/debian")
    }

    #[test]
    fn every_command_is_wrapped_and_has_no_mutating_programs() {
        let cmds = vec![
            CatalogCommand::Metrics,
            CatalogCommand::Uname,
            CatalogCommand::OsRelease,
            CatalogCommand::Uptime,
            CatalogCommand::ProcessList,
            CatalogCommand::DiskUsage,
            CatalogCommand::MemoryInfo,
            CatalogCommand::NetworkAddresses,
            CatalogCommand::ListeningSockets,
            CatalogCommand::ServiceList,
            CatalogCommand::UserServiceList,
            CatalogCommand::ServiceStatus { unit: "nexus-gateway.service".into() },
            CatalogCommand::ServiceLogs { unit: "minecraft".into(), lines: 100 },
            CatalogCommand::ListDirectory { path: "/home/debian/projects".into() },
            CatalogCommand::ReadFile { path: "/home/debian/a.txt".into(), max_bytes: 1024 },
            CatalogCommand::HashFile { path: "/home/debian/a.txt".into() },
            CatalogCommand::FindFiles { root: "/home/debian/p".into(), max_depth: 6 },
            CatalogCommand::GitStatus { repo: "/home/debian/p".into() },
            CatalogCommand::GitLog { repo: "/home/debian/p".into(), count: 20 },
            CatalogCommand::GitDiff { repo: "/home/debian/p".into() },
            CatalogCommand::GitShowFile { repo: "/home/debian/p".into(), rev: "HEAD".into(), path: "src/a.rs".into() },
        ];
        let forbidden = [
            "sudo", " rm ", "rm -", "mv ", "cp ", "tee ", "dd ", "chmod", "chown", "mkdir", "touch", "restart", " start ", " stop ",
            "reload", "enable", "disable", "apt", "dpkg", "reboot", "shutdown", "kill", "-delete", "-exec", "git commit",
            "git push", "git fetch", "git pull", "git checkout", "git reset", "git gc", "sed -i",
        ];
        // A redirect into a file: `>` or `>>` followed by a path/variable/word.
        let file_redirect = Regex::new(r#">{1,2}\s*[/~$A-Za-z_"']"#).unwrap();
        for c in cmds {
            let line = c.render(&roots()).unwrap();
            assert!(line.starts_with("LC_ALL=C timeout"), "{line}");
            let cleaned = line.replace(">&2", "").replace("2>&1", "").replace("2>/dev/null", "").replace(">/dev/null", "");
            assert!(!file_redirect.is_match(&cleaned), "{c:?} redirects to a file: {line}");
            for f in forbidden {
                // Redirect to stderr (`>&2`) is the only redirect allowed.
                let cleaned = line.replace(">&2", "").replace("2>&1", "").replace("2>/dev/null", "").replace(">/dev/null", "");
                assert!(!cleaned.contains(f), "{c:?} contains {f}: {line}");
            }
        }
    }

    #[test]
    fn git_commands_disable_writes_and_hooks() {
        let line = CatalogCommand::GitStatus { repo: "/home/debian/p".into() }.render(&roots()).unwrap();
        for f in ["--no-optional-locks", "core.fsmonitor=false", "gc.auto=0", "maintenance.auto=false"] {
            assert!(line.contains(f));
        }
    }

    #[test]
    fn rejects_injection_in_units_and_paths() {
        for u in ["a;rm -rf /", "-H evil", "x y", "$(id)", "a`b`", "", "../x"] {
            assert!(CatalogCommand::ServiceStatus { unit: u.into() }.render(&roots()).is_err(), "{u}");
        }
        for p in ["/home/debian/../../etc/shadow", "relative", "/etc/passwd", "/home/debian/.ssh/id_ed25519", "/home/debian/x\n", "/home/debianX/a"] {
            assert!(CatalogCommand::ReadFile { path: p.into(), max_bytes: 10 }.render(&roots()).is_err(), "{p:?}");
        }
        assert!(CatalogCommand::GitShowFile { repo: "/home/debian/p".into(), rev: "HEAD;id".into(), path: "a".into() }.render(&roots()).is_err());
        assert!(CatalogCommand::GitShowFile { repo: "/home/debian/p".into(), rev: "HEAD".into(), path: "../a".into() }.render(&roots()).is_err());
        assert!(CatalogCommand::ServiceLogs { unit: "a".into(), lines: 100_000 }.render(&roots()).is_err());
    }

    #[test]
    fn quoted_path_with_quote_cannot_break_out() {
        let line = CatalogCommand::ReadFile { path: "/home/debian/it's.txt".into(), max_bytes: 10 }.render(&roots()).unwrap();
        // The inner quote is escaped inside the sh -c word.
        assert!(line.contains("it'\\''"));
    }
}
