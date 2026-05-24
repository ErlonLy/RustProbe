use crate::core::{ClaimedIdentity, IdentityMismatch, MismatchDetail, MismatchSeverity, ObservedBehavior};
use crate::engine::{FingerprintDatabase, OriginInferenceEngine};

pub struct MismatchEngine {
    fingerprint_db: FingerprintDatabase,
    origin_inference: OriginInferenceEngine,
}

impl MismatchEngine {
    pub fn new() -> Self {
        Self {
            fingerprint_db: FingerprintDatabase::new(),
            origin_inference: OriginInferenceEngine::new(),
        }
    }

    pub fn detect_mismatches(&self, claimed: &ClaimedIdentity, observed: &ObservedBehavior) -> IdentityMismatch {
        let mut mismatches = Vec::new();
        let mut severity = MismatchSeverity::None;

        if let Some(topo_match) = self.fingerprint_db.compare_topology(
            claimed.vid,
            claimed.pid,
            observed.num_interfaces,
            observed.num_endpoints,
        ) {
            if !topo_match.matches {
                mismatches.push(MismatchDetail {
                    category: "Topology".to_string(),
                    claimed: format!("{} interfaces, {} endpoints", topo_match.expected_interfaces, topo_match.expected_endpoints),
                    observed: format!("{} interfaces, {} endpoints", topo_match.observed_interfaces, topo_match.observed_endpoints),
                    impact: 0.3,
                });
                severity = MismatchSeverity::Major;
            }
        }

        let impossible = self.origin_inference.detect_impossible_combinations(claimed, observed);
        for imp in impossible {
            mismatches.push(MismatchDetail {
                category: "Impossible Combination".to_string(),
                claimed: format!("VID:0x{:04X} PID:0x{:04X}", claimed.vid, claimed.pid),
                observed: imp,
                impact: 0.5,
            });
            severity = MismatchSeverity::Critical;
        }

        if let Some(ref hid_hash) = observed.hid_report_descriptor_hash {
            if let Some(hid_match) = self
                .fingerprint_db
                .compare_hid_signature(claimed.vid, claimed.pid, hid_hash)
            {
                if !hid_match.matches {
                    mismatches.push(MismatchDetail {
                        category: "HID Signature".to_string(),
                        claimed: format!("Expected: {}", hid_match.expected_hash),
                        observed: format!("Observed: {}", hid_match.observed_hash),
                        impact: 0.4,
                    });
                    if severity_rank(severity) < severity_rank(MismatchSeverity::Major) {
                        severity = MismatchSeverity::Major;
                    }
                }
            }
        }

        if is_likely_peripheral(claimed.vid) {
            if claimed.manufacturer.is_none() {
                mismatches.push(MismatchDetail {
                    category: "Missing Manufacturer".to_string(),
                    claimed: "Known peripheral should have manufacturer string".to_string(),
                    observed: "No manufacturer string".to_string(),
                    impact: 0.25,
                });
                if severity_rank(severity) < severity_rank(MismatchSeverity::Moderate) {
                    severity = MismatchSeverity::Moderate;
                }
            }
            if claimed.product.is_none() {
                mismatches.push(MismatchDetail {
                    category: "Missing Product".to_string(),
                    claimed: "Known peripheral should have product string".to_string(),
                    observed: "No product string".to_string(),
                    impact: 0.25,
                });
                if severity_rank(severity) < severity_rank(MismatchSeverity::Moderate) {
                    severity = MismatchSeverity::Moderate;
                }
            }
        }

        IdentityMismatch {
            has_mismatch: !mismatches.is_empty(),
            severity,
            mismatches,
        }
    }

    pub fn calculate_identity_score(&self, mismatch: &IdentityMismatch) -> f32 {
        if mismatch.mismatches.is_empty() {
            return 1.0;
        }
        let total_impact: f32 = mismatch.mismatches.iter().map(|m| m.impact).sum();
        (1.0 - total_impact).max(0.0)
    }
}

fn severity_rank(severity: MismatchSeverity) -> u8 {
    match severity {
        MismatchSeverity::None => 0,
        MismatchSeverity::Minor => 1,
        MismatchSeverity::Moderate => 2,
        MismatchSeverity::Major => 3,
        MismatchSeverity::Critical => 4,
    }
}

fn is_likely_peripheral(vid: u16) -> bool {
    !is_likely_dev_board(vid)
}

fn is_likely_dev_board(vid: u16) -> bool {
    matches!(
        vid,
        0x2341 | 0x2A03 | 0x1B4F | 0x303A | 0x16C0 | 0x10C4 | 0x1A86 | 0x0403 | 0x067B | 0x0483
    )
}

impl Default for MismatchEngine {
    fn default() -> Self {
        Self::new()
    }
}
