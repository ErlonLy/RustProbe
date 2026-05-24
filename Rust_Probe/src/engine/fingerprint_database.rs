




use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub vid: u16,
    pub pid: u16,
    pub name: String,
    pub manufacturer: String,
    pub num_interfaces: u8,
    pub num_endpoints: usize,
    pub endpoint_topology: EndpointTopology,
    pub hid_signature: Option<HIDSignature>,
    pub timing_signature: TimingSignature,
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointTopology {
    pub addresses: Vec<u8>,
    pub packet_sizes: Vec<u16>,
    pub intervals: Vec<u8>,
    pub transfer_types: Vec<String>,
    pub topology_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HIDSignature {
    pub report_descriptor_hash: String,
    pub report_descriptor_size: usize,
    pub usage_page: u16,
    pub usage: u16,
    pub polling_interval: u8,
    pub num_buttons: Option<u8>,
    pub num_axes: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSignature {
    pub enumeration_avg_us: u64,
    pub enumeration_stddev_us: u64,
    pub descriptor_read_avg_us: u64,
    pub control_response_avg_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectedFingerprint {
    vid: u16,
    pid: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    structural_hash: String,
    num_interfaces: u8,
    num_endpoints: usize,
    endpoint_addresses: Vec<u8>,
    endpoint_packet_sizes: Vec<u16>,
    endpoint_intervals: Vec<u8>,
    hid_report_descriptor_hash: Option<String>,
    hid_report_descriptor_size: Option<usize>,
    hid_usage_page: Option<u16>,
    hid_usage: Option<u16>,
    timing_mean_us: u64,
    timing_stddev_us: u64,
    device_name: String,
    is_genuine: bool,
}

pub struct FingerprintDatabase {
    fingerprints: HashMap<(u16, u16), Vec<DeviceFingerprint>>,
    nearest_cache: LruCache<String, Vec<SimilarityMatch>>,
}

impl FingerprintDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            fingerprints: HashMap::new(),
            nearest_cache: LruCache::new(NonZeroUsize::new(256).expect("non-zero")),
        };

        db.load_collected_dataset("data/collected_fingerprints.json");
        db
    }

    fn load_collected_dataset(&mut self, path: &str) {
        let p = Path::new(path);
        if !p.exists() {
            return;
        }

        let mut file = match File::open(p) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            return;
        }
        let parsed: Vec<CollectedFingerprint> = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => return,
        };

        for fp in parsed.into_iter().filter(|f| f.is_genuine) {
            let entry = DeviceFingerprint {
                vid: fp.vid,
                pid: fp.pid,
                name: fp.device_name.clone(),
                manufacturer: fp
                    .manufacturer
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                num_interfaces: fp.num_interfaces,
                num_endpoints: fp.num_endpoints,
                endpoint_topology: EndpointTopology {
                    addresses: fp.endpoint_addresses.clone(),
                    packet_sizes: fp.endpoint_packet_sizes.clone(),
                    intervals: fp.endpoint_intervals.clone(),
                    transfer_types: vec!["Unknown".to_string(); fp.num_endpoints],
                    topology_hash: fp.structural_hash.clone(),
                },
                hid_signature: fp.hid_report_descriptor_hash.as_ref().map(|h| HIDSignature {
                    report_descriptor_hash: h.clone(),
                    report_descriptor_size: fp.hid_report_descriptor_size.unwrap_or(0),
                    usage_page: fp.hid_usage_page.unwrap_or(0),
                    usage: fp.hid_usage.unwrap_or(0),
                    polling_interval: 0,
                    num_buttons: None,
                    num_axes: None,
                }),
                timing_signature: TimingSignature {
                    enumeration_avg_us: 0,
                    enumeration_stddev_us: 0,
                    descriptor_read_avg_us: fp.timing_mean_us,
                    control_response_avg_us: fp.timing_stddev_us,
                },
                variants: vec![fp.product.unwrap_or_else(|| fp.device_name.clone())],
            };

            self.add_fingerprint(entry);
        }
    }

    fn add_fingerprint(&mut self, fp: DeviceFingerprint) {
        self.fingerprints
            .entry((fp.vid, fp.pid))
            .or_default()
            .push(fp);
    }

    pub fn get_fingerprints(&self, vid: u16, pid: u16) -> Option<&[DeviceFingerprint]> {
        self.fingerprints.get(&(vid, pid)).map(Vec::as_slice)
    }

    pub fn compare_topology(
        &self,
        vid: u16,
        pid: u16,
        observed_interfaces: u8,
        observed_endpoints: usize,
    ) -> Option<TopologyMatch> {
        let candidates = self.get_fingerprints(vid, pid)?;
        let mut best: Option<TopologyMatch> = None;

        for fp in candidates {
            let interfaces_match = fp.num_interfaces == observed_interfaces;
            let endpoints_match = fp.num_endpoints == observed_endpoints;
            let confidence = if interfaces_match && endpoints_match {
                1.0
            } else if interfaces_match || endpoints_match {
                0.5
            } else {
                0.0
            };
            let current = TopologyMatch {
                matches: interfaces_match && endpoints_match,
                confidence,
                expected_interfaces: fp.num_interfaces,
                observed_interfaces,
                expected_endpoints: fp.num_endpoints,
                observed_endpoints,
            };
            if best
                .as_ref()
                .map(|b| current.confidence > b.confidence)
                .unwrap_or(true)
            {
                best = Some(current);
            }
        }
        best
    }

    pub fn compare_hid_signature(&self, vid: u16, pid: u16, observed_hash: &[u8]) -> Option<HIDMatch> {
        let candidates = self.get_fingerprints(vid, pid)?;
        let observed_full = hex_encode(observed_hash);
        let mut best: Option<HIDMatch> = None;

        for fp in candidates {
            let Some(ref hid_sig) = fp.hid_signature else {
                continue;
            };

            let matches = hid_sig.report_descriptor_hash == observed_full;
            let confidence = if matches { 1.0 } else { 0.0 };
            let current = HIDMatch {
                matches,
                confidence,
                expected_hash: hid_sig.report_descriptor_hash.clone(),
                observed_hash: observed_full.clone(),
            };
            if best
                .as_ref()
                .map(|b| current.confidence > b.confidence)
                .unwrap_or(true)
            {
                best = Some(current);
            }
        }

        best
    }

    pub fn find_nearest_matches(
        &mut self,
        observed_vid: u16,
        observed_pid: u16,
        observed_interfaces: u8,
        observed_endpoints: usize,
        observed_hid_hash: Option<&[u8]>,
        observed_stack: Option<&str>,
        observed_timing_avg: u64,
    ) -> Vec<SimilarityMatch> {
        let cache_key = format!(
            "{:04X}:{:04X}:{}:{}:{}:{}:{}",
            observed_vid,
            observed_pid,
            observed_interfaces,
            observed_endpoints,
            observed_stack.unwrap_or("none"),
            observed_timing_avg,
            observed_hid_hash.map(hex_encode).unwrap_or_else(|| "none".to_string())
        );
        if let Some(cached) = self.nearest_cache.get(&cache_key) {
            return cached.clone();
        }

        let mut matches = Vec::new();

        for candidates in self.fingerprints.values() {
            for fp in candidates {
                let mut similarity_score = 0.0;
                let mut evidence = Vec::new();

                if fp.vid == observed_vid && fp.pid == observed_pid {
                    similarity_score += 0.30;
                    evidence.push("VID:PID exact match".to_string());
                }

                let interface_diff = (fp.num_interfaces as i32 - observed_interfaces as i32).abs();
                let endpoint_diff = (fp.num_endpoints as i32 - observed_endpoints as i32).abs();
                let topology_similarity = if interface_diff == 0 && endpoint_diff == 0 {
                    1.0
                } else if interface_diff <= 1 && endpoint_diff <= 2 {
                    0.7
                } else if interface_diff <= 2 && endpoint_diff <= 4 {
                    0.4
                } else {
                    0.0
                };
                similarity_score += topology_similarity * 0.25;
                if topology_similarity > 0.0 {
                    evidence.push(format!("Topology similarity: {:.0}%", topology_similarity * 100.0));
                }

                if let (Some(observed_hash), Some(ref hid_sig)) = (observed_hid_hash, &fp.hid_signature) {
                    let hid_similarity = if hid_sig.report_descriptor_hash == hex_encode(observed_hash) {
                        1.0
                    } else {
                        0.0
                    };
                    similarity_score += hid_similarity * 0.20;
                    if hid_similarity > 0.0 {
                        evidence.push("HID hash match".to_string());
                    }
                }

                if let Some(stack) = observed_stack {
                    let suspicious_stacks = ["TinyUSB", "LUFA", "ESP-IDF", "Arduino AVR"];
                    let is_suspicious_stack = suspicious_stacks.iter().any(|s| stack.contains(s));
                    let is_peripheral = !is_likely_dev_board_vid(fp.vid);

                    if is_peripheral && is_suspicious_stack {
                        similarity_score -= 0.15;
                        evidence.push(format!("MISMATCH: {} device with {} stack", fp.manufacturer, stack));
                    } else if !is_suspicious_stack {
                        similarity_score += 0.15;
                        evidence.push("Stack compatible".to_string());
                    }
                }

                let timing_diff =
                    (fp.timing_signature.descriptor_read_avg_us as i64 - observed_timing_avg as i64).abs();
                let timing_similarity = if timing_diff < 50 {
                    1.0
                } else if timing_diff < 200 {
                    0.6
                } else if timing_diff < 500 {
                    0.3
                } else {
                    0.0
                };
                similarity_score += timing_similarity * 0.10;
                if timing_similarity > 0.0 {
                    evidence.push(format!("Timing similarity: {:.0}%", timing_similarity * 100.0));
                }

                if similarity_score > 0.20 {
                    matches.push(SimilarityMatch {
                        vid: fp.vid,
                        pid: fp.pid,
                        name: fp.name.clone(),
                        manufacturer: fp.manufacturer.clone(),
                        similarity: similarity_score,
                        evidence,
                    });
                }
            }
        }

        matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());
        matches.truncate(5);
        self.nearest_cache.put(cache_key, matches.clone());
        matches
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn is_likely_dev_board_vid(vid: u16) -> bool {
    matches!(
        vid,
        0x2341 | 0x2A03 | 0x1B4F | 0x303A | 0x16C0 | 0x10C4 | 0x1A86 | 0x0403 | 0x067B | 0x0483
    )
}

#[derive(Debug, Clone)]
pub struct TopologyMatch {
    pub matches: bool,
    pub confidence: f32,
    pub expected_interfaces: u8,
    pub observed_interfaces: u8,
    pub expected_endpoints: usize,
    pub observed_endpoints: usize,
}

#[derive(Debug, Clone)]
pub struct HIDMatch {
    pub matches: bool,
    pub confidence: f32,
    pub expected_hash: String,
    pub observed_hash: String,
}

#[derive(Debug, Clone)]
pub struct SimilarityMatch {
    pub vid: u16,
    pub pid: u16,
    pub name: String,
    pub manufacturer: String,
    pub similarity: f32,
    pub evidence: Vec<String>,
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}
