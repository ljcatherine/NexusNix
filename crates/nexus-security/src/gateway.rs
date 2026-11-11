//! Classification of Nexus gateway routes (from `gateway/main.go` @2263620).
//! The gateway, orchestrator and workspace-agent run on Debian, so any route that
//! persists state there is a Debian write and is denied by the policy engine.
//! Unknown routes are classified as mutations (deny by default).

use crate::policy::Capability;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    Read,
    Inference,
    Mutation,
    /// SSH relay to a named target; the target host's own policy then applies.
    SshRelay,
}

impl RouteClass {
    pub fn capability(self) -> Capability {
        match self {
            RouteClass::Read | RouteClass::SshRelay => Capability::GatewayRead,
            RouteClass::Inference => Capability::GatewayInference,
            RouteClass::Mutation => Capability::GatewayMutation,
        }
    }
}

fn segs(path: &str) -> Vec<&str> {
    path.split('?').next().unwrap_or("").trim_matches('/').split('/').collect()
}

pub fn classify(method: &str, path: &str) -> RouteClass {
    let m = method.to_ascii_uppercase();
    if path.contains("..") || path.contains('\\') || path.contains("//") {
        return RouteClass::Mutation;
    }
    let s = segs(path);
    let s: Vec<&str> = s.iter().copied().collect();
    match (m.as_str(), s.as_slice()) {
        ("GET", ["healthz"]) => RouteClass::Read,
        ("GET", ["v1", "models"]) => RouteClass::Read,
        ("GET", ["v1", "context"]) => RouteClass::Read,
        ("GET", ["v1", "conversations"]) => RouteClass::Read,
        ("GET", ["v1", "conversations", _]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "status"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "models"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "models", "status"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "agent-runs"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "agent-runs", "active"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "agent-runs", _]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "workspaces"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "workspaces", _]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "workspaces", _, _, "context"]) => RouteClass::Read,
        ("GET", ["v1", "nexus", "workspaces", _, _, "files"]) => RouteClass::Read,
        ("GET", ["v1", "ssh", _]) => RouteClass::SshRelay,
        // Inference: forwarded to PS5; the gateway does not persist request bodies.
        ("POST", ["v1", "chat", "completions"]) => RouteClass::Inference,
        ("POST", ["v1", "chat", "completions", "input_tokens"]) => RouteClass::Inference,
        ("POST", ["v1", "search"]) => RouteClass::Inference,
        ("POST", ["v1", "research"]) => RouteClass::Inference,
        // Everything else — conversation PUT/DELETE, agent-run creation/cancel,
        // model load/unload (writes the switch journal), workspace tasks, patch
        // and command review/execute, internal routes, Minecraft panel actions —
        // is a mutation.
        _ => RouteClass::Mutation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_routes_are_mutations() {
        for (m, p) in [
            ("PUT", "/v1/conversations/abc"),
            ("DELETE", "/v1/conversations/abc"),
            ("POST", "/v1/nexus/agent-runs"),
            ("POST", "/v1/nexus/agent-runs/r1/cancel"),
            ("POST", "/v1/nexus/agent-runs/r1/subagents/c/cancel"),
            ("POST", "/v1/nexus/models/q4/load"),
            ("POST", "/v1/nexus/models/unload"),
            ("POST", "/v1/nexus/workspaces/debian/w/tasks"),
            ("POST", "/internal/nexus/authorize-run"),
            ("POST", "/v1/nexus/workspaces/debian/w/patches/x/apply"),
            ("POST", "/v1/minecraft/panel/api/power"),
            ("GET", "/v1/minecraft/panel/"),
            ("GET", "/v1/unknown"),
            ("GET", "/v1/models/../nexus/models/x/load"),
            ("PATCH", "/v1/models"),
        ] {
            assert_eq!(classify(m, p), RouteClass::Mutation, "{m} {p}");
        }
    }

    #[test]
    fn read_and_inference_routes() {
        assert_eq!(classify("GET", "/v1/models"), RouteClass::Read);
        assert_eq!(classify("get", "/v1/nexus/models/status?x=1"), RouteClass::Read);
        assert_eq!(classify("GET", "/v1/nexus/workspaces/debian/w/files"), RouteClass::Read);
        assert_eq!(classify("POST", "/v1/chat/completions"), RouteClass::Inference);
        assert_eq!(classify("GET", "/v1/ssh/debian"), RouteClass::SshRelay);
    }
}
