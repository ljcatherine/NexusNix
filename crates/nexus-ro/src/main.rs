//! `nexus-ro`: SSH forced-command helper for read-only hosts.
//!
//! Installed on the server as
//! `restrict,command="/usr/local/bin/nexus-ro [--root DIR]..." ssh-ed25519 ...`
//! in `authorized_keys`. sshd runs it for every session of that key, whatever
//! the client asked for, and puts the client's command in `SSH_ORIGINAL_COMMAND`.
//! The helper accepts only `nexus-ro/1` catalog requests.
//!
//! It writes no files. Refusals go to stderr as `nexus_denied\t<tag>\t<reason>`
//! with exit code 126.

use nexus_security::catalog::ReadRoots;
use nexus_security::ro::{decode_request, plan, DENIED_EXIT};

fn roots_from_args() -> Result<ReadRoots, String> {
    let mut roots = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => {
                let r = args.next().ok_or("--root needs a directory")?;
                if !r.starts_with('/') || r.split('/').any(|s| s == ".." || s == ".") {
                    return Err(format!("invalid --root {r}"));
                }
                roots.push(r);
            }
            "--version" => {
                println!("nexus-ro {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    // Default: the home of the account the helper runs as (the restricted
    // SSH user), plus /var/log, /srv and /opt.
    let home = std::env::var("HOME").ok().filter(|h| h.starts_with('/') && !h.contains("..")).unwrap_or_else(|| "/nonexistent".into());
    Ok(if roots.is_empty() { ReadRoots::for_home(&home) } else { ReadRoots(roots) })
}

fn deny(tag: &str, reason: &str) -> ! {
    eprintln!("nexus_denied\t{tag}\t{reason}");
    std::process::exit(DENIED_EXIT);
}

fn main() {
    let roots = match roots_from_args() {
        Ok(r) => r,
        Err(e) => deny("config", &e),
    };
    let original = std::env::var("SSH_ORIGINAL_COMMAND").ok();
    let req = match decode_request(original.as_deref()) {
        Ok(r) => r,
        Err(e) => deny(e.tag(), &e.to_string()),
    };
    let resolve = |p: &str| std::fs::canonicalize(p).ok().and_then(|p| p.to_str().map(String::from));
    let plan = match plan(&req, &roots, &resolve) {
        Ok(p) => p,
        Err(e) => deny(e.tag(), &e.to_string()),
    };
    std::process::exit(exec::run(plan));
}

#[cfg(unix)]
mod exec {
    use super::deny;
    use nexus_security::ro::Plan;
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    const PASS_ENV: [&str; 6] = ["HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "TZ"];

    fn base(program: &str) -> Command {
        let mut c = Command::new(program);
        c.env_clear();
        for k in PASS_ENV {
            if let Some(v) = std::env::var_os(k) {
                c.env(k, v);
            }
        }
        c.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("SYSTEMD_PAGER", "")
            .env("PAGER", "cat")
            .stdin(Stdio::null());
        c
    }

    /// Open a resolved path without following a symlink swapped in after
    /// resolution, and confirm the opened file is the one that was checked.
    fn open_checked(path: &str) -> std::fs::File {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc_o_nofollow())
            .open(path)
            .unwrap_or_else(|e| deny("unresolvable", &e.to_string()));
        let meta = f.metadata().unwrap_or_else(|e| deny("unresolvable", &e.to_string()));
        if !meta.is_file() {
            deny("not_a_file", path);
        }
        use std::os::fd::AsRawFd;
        if let Ok(link) = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())) {
            if link.to_str() != Some(path) {
                deny("changed", "file changed during the check");
            }
        }
        f
    }

    /// O_NOFOLLOW on Linux (all architectures Debian ships use 0o400000 except
    /// a few that are not relevant here; x86_64 and aarch64 use this value).
    const fn libc_o_nofollow() -> i32 {
        0o400000
    }

    pub fn run(plan: Plan) -> i32 {
        match plan {
            Plan::ReadFile { path, max_bytes } => {
                let f = open_checked(&path);
                let mut buf = Vec::new();
                if let Err(e) = f.take(max_bytes as u64).read_to_end(&mut buf) {
                    deny("read_failed", &e.to_string());
                }
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(&buf);
                let _ = out.flush();
                0
            }
            Plan::HashFile { path } => {
                let mut f = open_checked(&path);
                let mut h = Sha256::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match f.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => h.update(&buf[..n]),
                        Err(e) => deny("read_failed", &e.to_string()),
                    }
                }
                println!("{}  {}", hex::encode(h.finalize()), path);
                0
            }
            Plan::Spawn { program, args, max_lines, merge_stderr } => {
                let mut c = base("timeout");
                c.args(["-s", "TERM", "-k", "2s", "30s", program]).args(&args);
                if merge_stderr {
                    let fd = std::io::stdout().as_fd().try_clone_to_owned().unwrap_or_else(|e| deny("io", &e.to_string()));
                    c.stdout(Stdio::inherit()).stderr(Stdio::from(fd));
                } else if max_lines.is_some() {
                    c.stdout(Stdio::piped()).stderr(Stdio::inherit());
                } else {
                    c.stdout(Stdio::inherit()).stderr(Stdio::inherit());
                }
                let mut child = c.spawn().unwrap_or_else(|e| deny("spawn_failed", &format!("{program}: {e}")));
                if let (Some(limit), Some(stdout)) = (max_lines, child.stdout.take()) {
                    let mut r = BufReader::new(stdout);
                    let mut out = std::io::stdout().lock();
                    let mut line = Vec::new();
                    let mut n = 0;
                    while n < limit {
                        line.clear();
                        match r.read_until(b'\n', &mut line) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                let _ = out.write_all(&line);
                                n += 1;
                            }
                        }
                    }
                    let _ = out.flush();
                    if n >= limit {
                        let _ = child.kill();
                    }
                }
                match child.wait() {
                    Ok(s) => s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0)),
                    Err(e) => deny("wait_failed", &e.to_string()),
                }
            }
        }
    }
}

#[cfg(not(unix))]
mod exec {
    use nexus_security::ro::Plan;
    pub fn run(_: Plan) -> i32 {
        super::deny("unsupported", "nexus-ro runs only on the Linux server");
    }
}
