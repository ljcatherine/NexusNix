//! The single authorization gate for Nexus Desktop.

use crate::audit::{AuditEvent, AuditSink, Outcome};
use nexus_core::{Device, HostRole};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What an operation wants to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Read,
    ListDirectory,
    WriteFile,
    DeleteFile,
    /// A fixed, validated command from [`crate::catalog`].
    ExecuteCatalogCommand,
    ExecuteArbitraryCommand,
    InteractiveShell,
    ServiceControl,
    GitRead,
    GitWrite,
    DebugAttach,
    /// A gateway call that persists state on the gateway host.
    GatewayMutation,
    /// A gateway call that only reads.
    GatewayRead,
    /// Inference through the gateway (no gateway-side persistence documented).
    GatewayInference,
    ModelControl,
}

impl Capability {
    pub const ALL: [Capability; 15] = [
        Capability::Read,
        Capability::ListDirectory,
        Capability::WriteFile,
        Capability::DeleteFile,
        Capability::ExecuteCatalogCommand,
        Capability::ExecuteArbitraryCommand,
        Capability::InteractiveShell,
        Capability::ServiceControl,
        Capability::GitRead,
        Capability::GitWrite,
        Capability::DebugAttach,
        Capability::GatewayMutation,
        Capability::GatewayRead,
        Capability::GatewayInference,
        Capability::ModelControl,
    ];

    /// Capabilities that cannot change state on the target.
    pub fn is_observational(self) -> bool {
        matches!(
            self,
            Capability::Read
                | Capability::ListDirectory
                | Capability::ExecuteCatalogCommand
                | Capability::GitRead
                | Capability::GatewayRead
                | Capability::GatewayInference
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            Capability::Read => "read files",
            Capability::ListDirectory => "list directories",
            Capability::WriteFile => "write files",
            Capability::DeleteFile => "delete files",
            Capability::ExecuteCatalogCommand => "run read-only catalog commands",
            Capability::ExecuteArbitraryCommand => "run arbitrary commands",
            Capability::InteractiveShell => "open an interactive shell",
            Capability::ServiceControl => "start/stop/restart services",
            Capability::GitRead => "read Git state",
            Capability::GitWrite => "modify Git state",
            Capability::DebugAttach => "attach a debugger",
            Capability::GatewayMutation => "change gateway state",
            Capability::GatewayRead => "read gateway state",
            Capability::GatewayInference => "send inference requests",
            Capability::ModelControl => "load/unload models",
        }
    }
}

/// The only capabilities Debian ever allows. A compile-time constant.
pub const DEBIAN_ALLOWED: [Capability; 6] = [
    Capability::Read,
    Capability::ListDirectory,
    Capability::ExecuteCatalogCommand,
    Capability::GitRead,
    Capability::GatewayRead,
    Capability::GatewayInference,
];

/// Who is asking. Agents get the intersection of host and agent grants and can
/// never use escalations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    User,
    Agent { session: String, provider: String },
}

impl Origin {
    pub fn is_agent(&self) -> bool {
        matches!(self, Origin::Agent { .. })
    }
}

/// The object of an operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// A local Windows workspace, identified by its canonical root path.
    LocalWorkspace { root: String },
    /// A remote host. `key` is the device id.
    Host { key: String },
    /// The Nexus gateway. It runs on Debian, so it is treated as Debian.
    Gateway,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub target: Target,
    pub capability: Capability,
    /// Human-readable exact description (command line, path, route).
    pub summary: String,
    pub origin: Origin,
}

impl Operation {
    pub fn user(target: Target, capability: Capability, summary: impl Into<String>) -> Self {
        Self { target, capability, summary: summary.into(), origin: Origin::User }
    }
    pub fn agent(target: Target, capability: Capability, summary: impl Into<String>, session: &str, provider: &str) -> Self {
        Self {
            target,
            capability,
            summary: summary.into(),
            origin: Origin::Agent { session: session.into(), provider: provider.into() },
        }
    }
}

/// Proof that an operation was authorized. Not `Clone`; fields are private so it
/// can only be created here. Transport functions require one.
#[derive(Debug)]
pub struct Grant {
    capability: Capability,
    target: Target,
    summary: String,
    escalated: bool,
    agent: bool,
    _private: (),
}

impl Grant {
    pub fn capability(&self) -> Capability {
        self.capability
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn summary(&self) -> &str {
        &self.summary
    }
    pub fn is_escalated(&self) -> bool {
        self.escalated
    }
    /// True when the grant was issued to an agent rather than the user.
    pub fn is_agent(&self) -> bool {
        self.agent
    }
    /// Panics if this grant does not cover `cap` on `target`. Transports call this
    /// as a defence-in-depth check before doing I/O.
    pub fn require(&self, cap: Capability, target: &Target) -> Result<(), Denial> {
        if self.capability == cap && &self.target == target {
            Ok(())
        } else {
            Err(Denial::GrantMismatch)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    #[error("Debian is read-only: '{0}' is not permitted without explicit owner approval")]
    DebianReadOnly(&'static str),
    #[error("This host's policy does not allow you to {0}")]
    NotGranted(&'static str),
    #[error("Agents are not allowed to {0} on this target")]
    AgentNotGranted(&'static str),
    #[error("The Debian read-only policy cannot be changed from settings")]
    DebianPolicyImmutable,
    #[error("The grant does not match the operation")]
    GrantMismatch,
    #[error("Unknown target")]
    UnknownTarget,
    #[error("Escalation confirmation did not match")]
    EscalationConfirmation,
}

/// Per-target permissions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPolicy {
    /// Capabilities the user may exercise.
    pub user: BTreeSet<Capability>,
    /// Capabilities agents may exercise (always intersected with `user`).
    pub agent: BTreeSet<Capability>,
}

impl HostPolicy {
    /// Read-only default for any non-local target.
    pub fn read_only() -> Self {
        let caps: BTreeSet<_> = [Capability::Read, Capability::ListDirectory, Capability::ExecuteCatalogCommand, Capability::GitRead]
            .into_iter()
            .collect();
        Self { user: caps.clone(), agent: caps }
    }
    /// Debian: the constant read-only set.
    pub fn debian() -> Self {
        let caps: BTreeSet<_> = DEBIAN_ALLOWED.into_iter().collect();
        Self { user: caps.clone(), agent: caps }
    }
    /// Default for a newly opened local workspace: the user can edit, agents can
    /// only read and propose (proposals are shown as diffs, never written).
    pub fn local_default() -> Self {
        use Capability::*;
        Self {
            user: [Read, ListDirectory, WriteFile, DeleteFile, ExecuteArbitraryCommand, InteractiveShell, GitRead, GitWrite, DebugAttach]
                .into_iter()
                .collect(),
            agent: [Read, ListDirectory, GitRead].into_iter().collect(),
        }
    }
    fn allows(&self, cap: Capability, agent: bool) -> bool {
        self.user.contains(&cap) && (!agent || self.agent.contains(&cap))
    }
}

/// The facts used to decide whether a host is the protected Debian server.
/// Detection is deliberately over-inclusive: any one signal is enough.
#[derive(Clone, Debug, Default)]
pub struct ProtectedRegistry {
    debian_device_ids: HashSet<String>,
    debian_fingerprints: HashSet<String>,
    debian_authorities: HashSet<String>,
}

impl ProtectedRegistry {
    pub fn is_debian_device(device: &Device) -> bool {
        device.inferred_role() == HostRole::Debian
            || device.role == Some(HostRole::Debian)
            || nexus_core::site::is_debian_user(&device.username)
            || device.name.to_ascii_lowercase().contains("debian")
            || device.endpoints.iter().any(|e| {
                e.relay_target.as_deref().is_some_and(|t| {
                    t.eq_ignore_ascii_case("debian") || t.eq_ignore_ascii_case("debian-ro")
                })
                    || e.host.to_ascii_lowercase().contains("debian")
            })
    }

    /// Register a device; returns true if it is treated as Debian.
    pub fn observe_device(&mut self, device: &Device) -> bool {
        let id = device.id.to_string();
        let authorities: Vec<String> = device.endpoints.iter().map(|e| e.authority()).collect();
        let is = Self::is_debian_device(device)
            || self.debian_device_ids.contains(&id)
            || authorities.iter().any(|a| self.debian_authorities.contains(a));
        if is {
            self.debian_device_ids.insert(id);
            self.debian_authorities.extend(authorities);
        }
        is
    }

    /// A host key seen on a Debian connection marks that key as Debian forever,
    /// so the same machine reached under another device entry stays protected.
    pub fn record_debian_fingerprint(&mut self, fingerprint: &str) {
        self.debian_fingerprints.insert(fingerprint.to_string());
    }

    pub fn is_debian_fingerprint(&self, fingerprint: &str) -> bool {
        self.debian_fingerprints.contains(fingerprint)
    }

    pub fn is_debian_key(&self, key: &str) -> bool {
        self.debian_device_ids.contains(key)
    }

    pub fn fingerprints(&self) -> impl Iterator<Item = &String> {
        self.debian_fingerprints.iter()
    }
}

/// A single-use, owner-approved exception for one exact Debian operation.
/// Never usable by agents. Expires after a short window.
#[derive(Debug)]
struct Escalation {
    target: Target,
    capability: Capability,
    summary: String,
    expires: Instant,
}

/// Description of an escalation request shown to the owner before approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationRequest {
    pub target: Target,
    pub capability: Capability,
    pub summary: String,
    pub reason: String,
    pub affected: String,
    pub risks: String,
    pub rollback: String,
}

impl EscalationRequest {
    /// The exact phrase the owner must type to approve.
    pub fn confirmation_phrase(&self) -> String {
        format!("APPROVE DEBIAN WRITE: {}", self.summary)
    }
}

/// Owner-only Debian capabilities while the owner has unlocked Debian writes
/// (owner decision, 8 Nov 2026, proposal 0001 Phase 3). Agents never get them.
/// `DeleteFile` and `ServiceControl` stay single-use escalations even then.
pub const DEBIAN_UNLOCKED: [Capability; 4] = [Capability::WriteFile, Capability::ExecuteArbitraryCommand, Capability::InteractiveShell, Capability::GitWrite];
/// Phrase the owner types to unlock Debian writes.
pub const DEBIAN_UNLOCK_PHRASE: &str = "unlock debian";
/// How long an unlock lasts.
pub const DEBIAN_UNLOCK_DURATION: Duration = Duration::from_secs(30 * 60);

struct Inner {
    policies: HashMap<Target, HostPolicy>,
    registry: ProtectedRegistry,
    escalations: Vec<Escalation>,
    debian_unlocked_until: Option<Instant>,
}

/// The authorization engine. Cheap to clone (shared state).
#[derive(Clone)]
pub struct PolicyEngine {
    inner: Arc<Mutex<Inner>>,
    audit: Arc<dyn AuditSink>,
}

impl PolicyEngine {
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                policies: HashMap::new(),
                registry: ProtectedRegistry::default(),
                escalations: Vec::new(),
                debian_unlocked_until: None,
            })),
            audit,
        }
    }

    /// Register a device. Debian devices always receive the constant policy.
    pub fn register_device(&self, device: &Device) {
        let mut inner = self.inner.lock();
        let target = Target::Host { key: device.id.to_string() };
        if inner.registry.observe_device(device) {
            inner.policies.insert(target, HostPolicy::debian());
        } else {
            inner.policies.entry(target).or_insert_with(HostPolicy::read_only);
        }
    }

    pub fn record_debian_fingerprint(&self, fp: &str) {
        self.inner.lock().registry.record_debian_fingerprint(fp);
    }

    /// Whether a connection presenting `fingerprint` must be treated as Debian.
    pub fn fingerprint_is_debian(&self, fingerprint: &str) -> bool {
        self.inner.lock().registry.is_debian_fingerprint(fingerprint)
    }

    /// Mark a host as Debian after the fact (e.g. its key matched a Debian pin).
    pub fn mark_debian(&self, key: &str) {
        let mut inner = self.inner.lock();
        inner.registry.debian_device_ids.insert(key.to_string());
        inner.policies.insert(Target::Host { key: key.to_string() }, HostPolicy::debian());
    }

    pub fn is_debian(&self, target: &Target) -> bool {
        let inner = self.inner.lock();
        Self::is_debian_locked(&inner, target)
    }

    fn is_debian_locked(inner: &Inner, target: &Target) -> bool {
        match target {
            Target::Gateway => true,
            Target::Host { key } => inner.registry.is_debian_key(key),
            Target::LocalWorkspace { .. } => false,
        }
    }

    /// Change a target's policy. Refused for Debian and the gateway.
    pub fn set_policy(&self, target: Target, policy: HostPolicy) -> Result<(), Denial> {
        let mut inner = self.inner.lock();
        if Self::is_debian_locked(&inner, &target) {
            drop(inner);
            self.audit.record(AuditEvent::new(&target, None, "set policy", &Origin::User, Outcome::Denied("debian policy immutable".into())));
            return Err(Denial::DebianPolicyImmutable);
        }
        inner.policies.insert(target, policy);
        Ok(())
    }

    pub fn policy(&self, target: &Target) -> HostPolicy {
        let inner = self.inner.lock();
        Self::effective_policy(&inner, target)
    }

    fn effective_policy(inner: &Inner, target: &Target) -> HostPolicy {
        if Self::is_debian_locked(inner, target) {
            return HostPolicy::debian();
        }
        match inner.policies.get(target) {
            Some(p) => p.clone(),
            None => match target {
                Target::LocalWorkspace { .. } => HostPolicy::local_default(),
                _ => HostPolicy::read_only(),
            },
        }
    }

    /// The single authorization gate.
    pub fn authorize(&self, op: &Operation) -> Result<Grant, Denial> {
        let result = self.decide(op);
        let outcome = match &result {
            Ok(g) if g.escalated => Outcome::AllowedEscalated,
            Ok(_) => Outcome::Allowed,
            Err(d) => Outcome::Denied(d.to_string()),
        };
        self.audit.record(AuditEvent::new(&op.target, Some(op.capability), &op.summary, &op.origin, outcome));
        result
    }

    fn decide(&self, op: &Operation) -> Result<Grant, Denial> {
        let mut inner = self.inner.lock();
        let debian = Self::is_debian_locked(&inner, &op.target);
        let grant = |escalated| Grant {
            capability: op.capability,
            target: op.target.clone(),
            summary: op.summary.clone(),
            escalated,
            agent: op.origin.is_agent(),
            _private: (),
        };
        if debian {
            if DEBIAN_ALLOWED.contains(&op.capability) {
                return Ok(grant(false));
            }
            // Owner unlock: hosts only (never the gateway), never agents.
            if !op.origin.is_agent()
                && matches!(op.target, Target::Host { .. })
                && DEBIAN_UNLOCKED.contains(&op.capability)
                && inner.debian_unlocked_until.is_some_and(|t| t > Instant::now())
            {
                return Ok(grant(true));
            }
            // Only the owner, never an agent, and only via a matching single-use escalation.
            if !op.origin.is_agent() {
                let now = Instant::now();
                inner.escalations.retain(|e| e.expires > now);
                if let Some(i) = inner.escalations.iter().position(|e| {
                    e.target == op.target && e.capability == op.capability && e.summary == op.summary
                }) {
                    inner.escalations.remove(i);
                    return Ok(grant(true));
                }
            }
            return Err(Denial::DebianReadOnly(op.capability.label()));
        }
        let policy = Self::effective_policy(&inner, &op.target);
        if !policy.user.contains(&op.capability) {
            return Err(Denial::NotGranted(op.capability.label()));
        }
        if op.origin.is_agent() && !policy.allows(op.capability, true) {
            return Err(Denial::AgentNotGranted(op.capability.label()));
        }
        Ok(grant(false))
    }

    /// Owner unlock of Debian writes (`DEBIAN_UNLOCKED`) for `duration`.
    /// `typed` must equal [`DEBIAN_UNLOCK_PHRASE`]. No agent tool calls this.
    pub fn unlock_debian(&self, typed: &str, duration: Duration) -> Result<(), Denial> {
        if typed.trim() != DEBIAN_UNLOCK_PHRASE {
            return Err(Denial::EscalationConfirmation);
        }
        self.audit.record(AuditEvent::new(&Target::Gateway, None, &format!("unlock debian writes for {} min", duration.as_secs() / 60), &Origin::User, Outcome::EscalationApproved));
        self.inner.lock().debian_unlocked_until = Some(Instant::now() + duration);
        Ok(())
    }

    pub fn lock_debian(&self) {
        let was = self.inner.lock().debian_unlocked_until.take();
        if was.is_some_and(|t| t > Instant::now()) {
            self.audit.record(AuditEvent::new(&Target::Gateway, None, "lock debian writes", &Origin::User, Outcome::Allowed));
        }
    }

    /// Remaining unlock time, if Debian writes are unlocked.
    pub fn debian_unlocked_for(&self) -> Option<Duration> {
        self.inner.lock().debian_unlocked_until.and_then(|t| t.checked_duration_since(Instant::now())).filter(|d| !d.is_zero())
    }

    /// Owner approval of one exact Debian write. `typed` must equal the request's
    /// confirmation phrase. Valid once, for five minutes. Not reachable by agents:
    /// there is no agent tool that calls this.
    pub fn approve_escalation(&self, request: &EscalationRequest, typed: &str) -> Result<(), Denial> {
        if typed.trim() != request.confirmation_phrase() {
            return Err(Denial::EscalationConfirmation);
        }
        self.audit.record(AuditEvent::new(
            &request.target,
            Some(request.capability),
            &request.summary,
            &Origin::User,
            Outcome::EscalationApproved,
        ));
        self.inner.lock().escalations.push(Escalation {
            target: request.target.clone(),
            capability: request.capability,
            summary: request.summary.clone(),
            expires: Instant::now() + Duration::from_secs(300),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::MemoryAudit;

    fn engine() -> (PolicyEngine, Arc<MemoryAudit>) {
        let audit = Arc::new(MemoryAudit::default());
        (PolicyEngine::new(audit.clone()), audit)
    }

    fn debian() -> Device {
        Device::suggestions().into_iter().find(|d| d.role == Some(HostRole::Debian)).unwrap()
    }

    fn nixos() -> Device {
        Device::suggestions().into_iter().find(|d| d.role == Some(HostRole::Nixos)).unwrap()
    }

    #[test]
    fn debian_denies_every_mutating_capability_for_user_and_agent() {
        let (e, audit) = engine();
        let d = debian();
        e.register_device(&d);
        let t = Target::Host { key: d.id.to_string() };
        for cap in Capability::ALL {
            let u = e.authorize(&Operation::user(t.clone(), cap, "x"));
            let a = e.authorize(&Operation::agent(t.clone(), cap, "x", "s", "codex"));
            if DEBIAN_ALLOWED.contains(&cap) {
                assert!(u.is_ok() && a.is_ok(), "{cap:?} should be allowed");
            } else {
                assert!(matches!(u, Err(Denial::DebianReadOnly(_))), "{cap:?}");
                assert!(matches!(a, Err(Denial::DebianReadOnly(_))), "{cap:?}");
            }
        }
        assert_eq!(audit.events().len(), Capability::ALL.len() * 2);
    }

    #[test]
    fn debian_unlock_is_owner_only_timed_and_never_for_agents() {
        let (e, _) = engine();
        let d = debian();
        e.register_device(&d);
        let t = Target::Host { key: d.id.to_string() };
        let user = |c| e.authorize(&Operation::user(t.clone(), c, "x"));
        let agent = |c| e.authorize(&Operation::agent(t.clone(), c, "x", "s", "codex"));
        // Locked by default.
        assert!(user(Capability::WriteFile).is_err());
        assert!(e.debian_unlocked_for().is_none());
        assert!(e.unlock_debian("unlock", DEBIAN_UNLOCK_DURATION).is_err());
        e.unlock_debian("unlock debian", DEBIAN_UNLOCK_DURATION).unwrap();
        assert!(e.debian_unlocked_for().is_some());
        for cap in Capability::ALL {
            let expected = DEBIAN_ALLOWED.contains(&cap) || DEBIAN_UNLOCKED.contains(&cap);
            assert_eq!(user(cap).is_ok(), expected, "user {cap:?}");
            // Agents keep exactly the read-only set, unlocked or not.
            assert_eq!(agent(cap).is_ok(), DEBIAN_ALLOWED.contains(&cap), "agent {cap:?}");
        }
        assert!(user(Capability::WriteFile).unwrap().is_escalated());
        // Delete and service control still need a single-use escalation.
        assert!(user(Capability::DeleteFile).is_err());
        assert!(user(Capability::ServiceControl).is_err());
        // The gateway is not covered by the unlock.
        assert!(e.authorize(&Operation::user(Target::Gateway, Capability::GatewayMutation, "x")).is_err());
        e.lock_debian();
        assert!(user(Capability::InteractiveShell).is_err());
        // Expiry.
        e.unlock_debian("unlock debian", Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(user(Capability::WriteFile).is_err());
        assert!(e.debian_unlocked_for().is_none());
    }

    #[test]
    fn debian_policy_cannot_be_loosened() {
        let (e, _) = engine();
        let d = debian();
        e.register_device(&d);
        let t = Target::Host { key: d.id.to_string() };
        let mut all = HostPolicy::default();
        all.user = Capability::ALL.into_iter().collect();
        all.agent = all.user.clone();
        assert_eq!(e.set_policy(t.clone(), all.clone()), Err(Denial::DebianPolicyImmutable));
        assert_eq!(e.set_policy(Target::Gateway, all), Err(Denial::DebianPolicyImmutable));
        assert!(e.authorize(&Operation::user(t, Capability::WriteFile, "x")).is_err());
    }

    #[test]
    fn debian_detected_by_any_signal() {
        let mut d = nixos();
        d.name = "Old box".into();
        d.username = "admin".into();
        d.role = Some(HostRole::Other);
        d.endpoints[0].relay_target = Some("debian".into());
        assert!(ProtectedRegistry::is_debian_device(&d));
        let mut d2 = nixos();
        d2.role = Some(HostRole::Other);
        d2.username = "x".into();
        d2.endpoints[0].relay_target = None;
        d2.endpoints[0].host = "debian.lan".into();
        assert!(ProtectedRegistry::is_debian_device(&d2));
    }

    #[test]
    fn relabelled_debian_alias_with_same_authority_stays_protected() {
        let (e, _) = engine();
        let mut d = debian();
        d.endpoints[0].host = "192.168.1.20".into();
        d.endpoints[0].port = 22;
        d.endpoints[0].relay_target = None;
        e.register_device(&d);
        // A second device entry for the same address, labelled innocuously.
        let mut alias = nixos();
        alias.name = "Box".into();
        alias.username = "root".into();
        alias.role = Some(HostRole::Other);
        alias.endpoints[0].host = "192.168.1.20".into();
        alias.endpoints[0].port = 22;
        alias.endpoints[0].relay_target = None;
        e.register_device(&alias);
        let t = Target::Host { key: alias.id.to_string() };
        assert!(e.is_debian(&t));
        assert!(e.authorize(&Operation::user(t, Capability::InteractiveShell, "sh")).is_err());
    }

    #[test]
    fn gateway_is_treated_as_debian() {
        let (e, _) = engine();
        assert!(e.authorize(&Operation::user(Target::Gateway, Capability::GatewayMutation, "PUT /v1/conversations/x")).is_err());
        assert!(e.authorize(&Operation::user(Target::Gateway, Capability::GatewayRead, "GET /v1/models")).is_ok());
    }

    #[test]
    fn non_debian_hosts_default_to_read_only() {
        let (e, _) = engine();
        let n = nixos();
        e.register_device(&n);
        let t = Target::Host { key: n.id.to_string() };
        assert!(e.authorize(&Operation::user(t.clone(), Capability::Read, "x")).is_ok());
        assert!(matches!(e.authorize(&Operation::user(t.clone(), Capability::WriteFile, "x")), Err(Denial::NotGranted(_))));
        // Explicit grant works for user; agent still needs its own grant.
        let mut p = HostPolicy::read_only();
        p.user.insert(Capability::WriteFile);
        e.set_policy(t.clone(), p).unwrap();
        assert!(e.authorize(&Operation::user(t.clone(), Capability::WriteFile, "x")).is_ok());
        assert!(matches!(
            e.authorize(&Operation::agent(t, Capability::WriteFile, "x", "s", "claude")),
            Err(Denial::AgentNotGranted(_))
        ));
    }

    #[test]
    fn local_workspace_agents_start_read_only() {
        let (e, _) = engine();
        let t = Target::LocalWorkspace { root: "C:/p".into() };
        assert!(e.authorize(&Operation::user(t.clone(), Capability::WriteFile, "a.rs")).is_ok());
        assert!(e.authorize(&Operation::agent(t.clone(), Capability::WriteFile, "a.rs", "s", "codex")).is_err());
        assert!(e.authorize(&Operation::agent(t, Capability::Read, "a.rs", "s", "codex")).is_ok());
    }

    #[test]
    fn escalation_is_single_use_exact_and_user_only() {
        let (e, audit) = engine();
        let d = debian();
        e.register_device(&d);
        let t = Target::Host { key: d.id.to_string() };
        let req = EscalationRequest {
            target: t.clone(),
            capability: Capability::ServiceControl,
            summary: "systemctl --user restart nexus-gateway".into(),
            reason: "r".into(),
            affected: "a".into(),
            risks: "k".into(),
            rollback: "b".into(),
        };
        assert_eq!(e.approve_escalation(&req, "yes"), Err(Denial::EscalationConfirmation));
        e.approve_escalation(&req, &req.confirmation_phrase()).unwrap();
        // Agent cannot consume it.
        assert!(e.authorize(&Operation::agent(t.clone(), Capability::ServiceControl, &req.summary, "s", "codex")).is_err());
        // Different summary cannot consume it.
        assert!(e.authorize(&Operation::user(t.clone(), Capability::ServiceControl, "systemctl restart sshd")).is_err());
        let g = e.authorize(&Operation::user(t.clone(), Capability::ServiceControl, &req.summary)).unwrap();
        assert!(g.is_escalated());
        // Second use refused.
        assert!(e.authorize(&Operation::user(t, Capability::ServiceControl, &req.summary)).is_err());
        assert!(audit.events().iter().any(|ev| matches!(ev.outcome, Outcome::EscalationApproved)));
    }

    #[test]
    fn grant_require_checks_capability_and_target() {
        let (e, _) = engine();
        let t = Target::LocalWorkspace { root: "C:/p".into() };
        let g = e.authorize(&Operation::user(t.clone(), Capability::Read, "a")).unwrap();
        assert!(g.require(Capability::Read, &t).is_ok());
        assert_eq!(g.require(Capability::WriteFile, &t), Err(Denial::GrantMismatch));
        assert_eq!(g.require(Capability::Read, &Target::Gateway), Err(Denial::GrantMismatch));
    }

    #[test]
    fn fingerprint_marks_alias_as_debian() {
        let (e, _) = engine();
        e.record_debian_fingerprint("SHA256:abc");
        assert!(e.fingerprint_is_debian("SHA256:abc"));
        let n = nixos();
        e.register_device(&n);
        e.mark_debian(&n.id.to_string());
        assert!(e.is_debian(&Target::Host { key: n.id.to_string() }));
    }
}
