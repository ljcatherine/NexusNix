//! Host telemetry: a Rust port of the iOS `HostMetricsParser` and
//! `HostNetworkRateCalculator`. The script itself is
//! `nexus_security::catalog::METRICS_SCRIPT` (read-only `/proc` reads).
//! Values are only what the host reported; nothing is synthesized.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Filesystem {
    pub total: u64,
    pub used: u64,
    pub available: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetCounters {
    pub interface: String,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Gpu {
    pub index: u32,
    pub utilization: Option<f64>,
    pub memory_total_mib: Option<u64>,
    pub memory_used_mib: Option<u64>,
    pub temperature_c: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub observed_at: SystemTime,
    pub boot_id: Option<String>,
    pub uptime_secs: Option<f64>,
    pub load: Option<LoadAverage>,
    pub cpu_count: Option<u32>,
    pub cpu_percent: Option<f64>,
    pub memory_total: Option<u64>,
    pub memory_available: Option<u64>,
    pub root_fs: Option<Filesystem>,
    pub network: Vec<NetCounters>,
    pub nvidia_available: bool,
    pub gpus: Vec<Gpu>,
}

/// Low-resource thresholds (percent). Matches the iOS app's warning levels.
pub const ALERT_PERCENT: f64 = 90.0;

impl Snapshot {
    /// Resources above [`ALERT_PERCENT`], as short labels (e.g. "CPU 95%").
    pub fn alerts(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(c) = self.cpu_percent.filter(|c| *c >= ALERT_PERCENT) {
            v.push(format!("CPU {c:.0}%"));
        }
        if let Some(m) = self.memory_used_percent().filter(|m| *m >= ALERT_PERCENT) {
            v.push(format!("memory {m:.0}%"));
        }
        if let Some(fs) = self.root_fs.as_ref().filter(|f| f.total > 0) {
            let d = fs.used as f64 * 100.0 / fs.total as f64;
            if d >= ALERT_PERCENT {
                v.push(format!("disk {d:.0}%"));
            }
        }
        v
    }

    pub fn memory_used_percent(&self) -> Option<f64> {
        match (self.memory_total, self.memory_available) {
            (Some(t), Some(a)) if t > 0 => Some((t - a) as f64 * 100.0 / t as f64),
            _ => None,
        }
    }
    pub fn disk_used_percent(&self) -> Option<f64> {
        self.root_fs.as_ref().map(|f| f.used as f64 * 100.0 / f.total as f64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("The server returned metrics in an unsupported format.")]
    Unsupported,
}

fn finite(s: &str, lo: f64, hi: f64) -> Option<f64> {
    s.parse::<f64>().ok().filter(|v| v.is_finite() && *v >= lo && *v <= hi)
}

fn valid_iface(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

fn valid_uuid(s: &str) -> bool {
    s.len() == 36 && s.chars().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

pub fn parse(output: &str, observed_at: SystemTime) -> Result<Snapshot, ParseError> {
    let mut lines = output.lines().map(|l| l.trim_end_matches('\r'));
    if lines.next() != Some("nexus_metrics\t1") {
        return Err(ParseError::Unsupported);
    }
    let mut s = Snapshot {
        observed_at,
        boot_id: None,
        uptime_secs: None,
        load: None,
        cpu_count: None,
        cpu_percent: None,
        memory_total: None,
        memory_available: None,
        root_fs: None,
        network: vec![],
        nvidia_available: false,
        gpus: vec![],
    };
    let mut ifaces: BTreeMap<String, NetCounters> = BTreeMap::new();
    let mut gpus: BTreeMap<u32, Gpu> = BTreeMap::new();
    for line in lines {
        let f: Vec<&str> = line.split('\t').collect();
        match (f[0], f.len()) {
            ("boot_id", 2) if valid_uuid(f[1]) => s.boot_id = Some(f[1].to_ascii_lowercase()),
            ("uptime", 2) => s.uptime_secs = finite(f[1], 0.0, f64::MAX),
            ("load", 4) => {
                if let (Some(a), Some(b), Some(c)) = (finite(f[1], 0.0, f64::MAX), finite(f[2], 0.0, f64::MAX), finite(f[3], 0.0, f64::MAX)) {
                    s.load = Some(LoadAverage { one: a, five: b, fifteen: c });
                }
            }
            ("cpu_count", 2) => s.cpu_count = f[1].parse().ok().filter(|v| *v > 0),
            ("cpu_utilization", 2) => s.cpu_percent = finite(f[1], 0.0, 100.0),
            ("memory", 3) => {
                if let (Ok(t), Ok(a)) = (f[1].parse::<u64>(), f[2].parse::<u64>()) {
                    if t > 0 && a <= t {
                        s.memory_total = Some(t);
                        s.memory_available = Some(a);
                    }
                }
            }
            ("filesystem", 4) => {
                if let (Ok(t), Ok(u), Ok(a)) = (f[1].parse::<u64>(), f[2].parse::<u64>(), f[3].parse::<u64>()) {
                    if t > 0 && u <= t && a <= t - u {
                        s.root_fs = Some(Filesystem { total: t, used: u, available: a });
                    }
                }
            }
            ("network", 4) if valid_iface(f[1]) => {
                if let (Ok(rx), Ok(tx)) = (f[2].parse(), f[3].parse()) {
                    ifaces.insert(f[1].into(), NetCounters { interface: f[1].into(), rx, tx });
                }
            }
            ("nvidia_tool", 2) => s.nvidia_available = f[1] == "available",
            ("nvidia", 6) => {
                let Ok(index) = f[1].parse::<u32>() else { continue };
                let util = finite(f[2], 0.0, 100.0);
                let (mt, mu) = (f[3].parse::<u64>().ok(), f[4].parse::<u64>().ok());
                let valid_mem = matches!((mt, mu), (Some(t), Some(u)) if t > 0 && u <= t);
                let temp = finite(f[5], 0.0, 200.0);
                if util.is_none() && !valid_mem && temp.is_none() {
                    continue;
                }
                gpus.insert(index, Gpu {
                    index,
                    utilization: util,
                    memory_total_mib: if valid_mem { mt } else { None },
                    memory_used_mib: if valid_mem { mu } else { None },
                    temperature_c: temp,
                });
            }
            _ => {}
        }
    }
    s.network = ifaces.into_values().collect();
    s.gpus = gpus.into_values().collect();
    Ok(s)
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetRate {
    pub interface: String,
    pub rx_per_sec: f64,
    pub tx_per_sec: f64,
    pub interval_secs: f64,
}

/// A sample tagged with the endpoint it came from.
#[derive(Clone, Debug)]
pub struct Sample {
    pub authority: String,
    pub snapshot: Snapshot,
}

/// Bounded per-host history.
#[derive(Clone, Debug, Default)]
pub struct History {
    samples: VecDeque<Sample>,
}

impl History {
    pub const CAPACITY: usize = 720;

    pub fn push(&mut self, sample: Sample) {
        self.samples.push_back(sample);
        while self.samples.len() > Self::CAPACITY {
            self.samples.pop_front();
        }
    }

    pub fn latest(&self) -> Option<&Snapshot> {
        self.samples.back().map(|s| &s.snapshot)
    }

    pub fn series(&self, f: impl Fn(&Snapshot) -> Option<f64>) -> Vec<f64> {
        self.samples.iter().filter_map(|s| f(&s.snapshot)).collect()
    }

    /// Rates only between the two latest samples from the same endpoint and boot,
    /// with monotonic counters — same rules as the iOS calculator.
    pub fn network_rates(&self) -> Vec<NetRate> {
        let n = self.samples.len();
        if n < 2 {
            return vec![];
        }
        let (prev, cur) = (&self.samples[n - 2], &self.samples[n - 1]);
        if prev.authority != cur.authority || prev.snapshot.boot_id != cur.snapshot.boot_id {
            return vec![];
        }
        if let (Some(a), Some(b)) = (prev.snapshot.uptime_secs, cur.snapshot.uptime_secs) {
            if b < a {
                return vec![];
            }
        }
        let Ok(dt) = cur.snapshot.observed_at.duration_since(prev.snapshot.observed_at) else { return vec![] };
        let dt = dt.as_secs_f64();
        if dt <= 0.0 {
            return vec![];
        }
        let before: BTreeMap<&str, &NetCounters> = prev.snapshot.network.iter().map(|c| (c.interface.as_str(), c)).collect();
        cur.snapshot
            .network
            .iter()
            .filter_map(|l| {
                let e = before.get(l.interface.as_str())?;
                if l.rx < e.rx || l.tx < e.tx {
                    return None;
                }
                Some(NetRate {
                    interface: l.interface.clone(),
                    rx_per_sec: (l.rx - e.rx) as f64 / dt,
                    tx_per_sec: (l.tx - e.tx) as f64 / dt,
                    interval_secs: dt,
                })
            })
            .collect()
    }
}

/// Human-readable byte size (binary units).
pub fn format_bytes(b: f64) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{v:.0} {}", U[i]) } else { format!("{v:.1} {}", U[i]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SAMPLE: &str = "nexus_metrics\t1\nboot_id\t0f3c6a1e-1111-2222-3333-444455556666\nuptime\t1234.5\nload\t0.5\t0.4\t0.3\ncpu_count\t8\ncpu_utilization\t24.00\nmemory\t16000000000\t6000000000\nfilesystem\t1000\t400\t500\nnetwork\teth0\t1000\t2000\nnetwork\tbad iface\t1\t1\nnvidia_tool\tunavailable\n";

    #[test]
    fn parses_ios_format() {
        let s = parse(SAMPLE, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(s.cpu_count, Some(8));
        assert_eq!(s.cpu_percent, Some(24.0));
        assert_eq!(s.network.len(), 1);
        assert!((s.memory_used_percent().unwrap() - 62.5).abs() < 1e-9);
        assert_eq!(s.disk_used_percent(), Some(40.0));
        assert!(!s.nvidia_available);
    }

    #[test]
    fn rejects_bad_header_and_bad_values() {
        assert!(parse("hello", SystemTime::UNIX_EPOCH).is_err());
        let s = parse("nexus_metrics\t1\ncpu_utilization\t150\nmemory\t10\t20\nfilesystem\t10\t8\t5\n", SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(s.cpu_percent, None);
        assert_eq!(s.memory_total, None);
        assert_eq!(s.root_fs, None);
    }

    #[test]
    fn rates_require_same_endpoint_and_boot() {
        let t0 = SystemTime::UNIX_EPOCH;
        let a = parse(SAMPLE, t0).unwrap();
        let mut b = parse(&SAMPLE.replace("eth0\t1000\t2000", "eth0\t3000\t2500"), t0 + Duration::from_secs(10)).unwrap();
        let mut h = History::default();
        h.push(Sample { authority: "x".into(), snapshot: a.clone() });
        h.push(Sample { authority: "x".into(), snapshot: b.clone() });
        let r = h.network_rates();
        assert_eq!(r.len(), 1);
        assert!((r[0].rx_per_sec - 200.0).abs() < 1e-9);
        b.boot_id = Some("other".into());
        let mut h2 = History::default();
        h2.push(Sample { authority: "x".into(), snapshot: a });
        h2.push(Sample { authority: "x".into(), snapshot: b });
        assert!(h2.network_rates().is_empty());
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(512.0), "512 B");
        assert_eq!(format_bytes(4.6 * 1024.0 * 1024.0 * 1024.0), "4.6 GB");
    }
}

#[cfg(test)]
mod alert_tests {
    use super::*;

    #[test]
    fn alerts_only_above_threshold() {
        let mut s = Snapshot { observed_at: std::time::SystemTime::now(), boot_id: None, uptime_secs: None, load: None, cpu_count: None, cpu_percent: Some(12.0), memory_total: Some(100), memory_available: Some(50), root_fs: Some(Filesystem { total: 100, used: 20, available: 80 }), network: vec![], nvidia_available: false, gpus: vec![] };
        assert!(s.alerts().is_empty());
        s.cpu_percent = Some(97.0);
        s.memory_available = Some(5);
        s.root_fs = Some(Filesystem { total: 100, used: 91, available: 9 });
        assert_eq!(s.alerts(), vec!["CPU 97%".to_string(), "memory 95%".to_string(), "disk 91%".to_string()]);
    }
}
