use crate::core::{Anomaly, AnomalySeverity, AnomalyType};
use crate::layers::{
    DescriptorOrderingResult, HIDResult, PassiveResult, StructuralResult, TimingResult,
};

pub struct ForensicEngine;

impl ForensicEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        passive: &PassiveResult,
        structural: &StructuralResult,
        hid: Option<&HIDResult>,
        timing: &TimingResult,
        descriptor_ordering: Option<&DescriptorOrderingResult>,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        self.analyze_strings(passive, &mut anomalies);
        self.analyze_descriptor_entropy(hid, descriptor_ordering, &mut anomalies);
        self.analyze_timing_coherence(structural, hid, timing, &mut anomalies);
        self.analyze_descriptor_ordering_consistency(descriptor_ordering, &mut anomalies);
        anomalies
    }

    pub fn penalty(&self, anomalies: &[Anomaly]) -> f32 {
        anomalies.iter().fold(0.0, |acc, anomaly| {
            acc + match anomaly.severity {
                AnomalySeverity::Info => 0.0,
                AnomalySeverity::Low => 0.015,
                AnomalySeverity::Medium => 0.035,
                AnomalySeverity::High => 0.065,
                AnomalySeverity::Critical => 0.10,
            }
        })
    }

    fn analyze_strings(&self, passive: &PassiveResult, anomalies: &mut Vec<Anomaly>) {
        let mut suspicious = Vec::new();
        for (field, value) in [
            ("manufacturer", passive.manufacturer.as_deref()),
            ("product", passive.product.as_deref()),
            ("serial", passive.serial.as_deref()),
        ] {
            if let Some(s) = value {
                let lower = s.trim().to_lowercase();
                if lower.is_empty() {
                    suspicious.push(format!("{field}: vazio"));
                    continue;
                }

                let placeholders = [
                    "unknown",
                    "default",
                    "example",
                    "test",
                    "sample",
                    "none",
                    "null",
                    "n/a",
                    "manufacturer",
                    "product",
                    "serial",
                ];
                if placeholders.iter().any(|p| lower == *p || lower.contains(&format!("{p} "))) {
                    suspicious.push(format!("{field}: placeholder"));
                }

                if self.has_excessive_repetition(&lower) {
                    suspicious.push(format!("{field}: repeticao excessiva"));
                }
            }
        }

        if !suspicious.is_empty() {
            anomalies.push(
                Anomaly::new(AnomalyType::SuspiciousIdentityString, "Forensic")
                    .with_details(suspicious.join(", ")),
            );
        }
    }

    fn analyze_descriptor_entropy(
        &self,
        hid: Option<&HIDResult>,
        descriptor_ordering: Option<&DescriptorOrderingResult>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        if let Some(hid_data) = hid {
            let entropy = self.shannon_entropy(&hid_data.report_descriptor);
            if hid_data.report_descriptor.len() >= 16 && entropy < 2.2 {
                anomalies.push(
                    Anomaly::new(AnomalyType::DescriptorEntropyAnomaly, "Forensic").with_details(
                        format!(
                            "Entropia HID baixa: {:.2} bits/byte em {} bytes",
                            entropy,
                            hid_data.report_descriptor.len()
                        ),
                    ),
                );
            }
        }

        if let Some(ordering) = descriptor_ordering {
            let bytes = ordering.raw_bytes_hash.as_slice();
            let leading_zeros = bytes.iter().take_while(|b| **b == 0).count();
            if leading_zeros >= 3 {
                anomalies.push(
                    Anomaly::new(AnomalyType::DescriptorEntropyAnomaly, "Forensic")
                        .with_severity(AnomalySeverity::Low)
                        .with_details("Raw descriptor hash com prefixo atipico".to_string()),
                );
            }
        }
    }

    fn analyze_timing_coherence(
        &self,
        structural: &StructuralResult,
        hid: Option<&HIDResult>,
        timing: &TimingResult,
        anomalies: &mut Vec<Anomaly>,
    ) {
        let mean = timing.repeated_read_stats.mean_us;
        let jitter = timing.repeated_read_stats.jitter_us;
        let std_dev = timing.repeated_read_stats.std_dev_us;
        let simple_topology =
            structural.topology.num_interfaces <= 1 && structural.topology.endpoint_addresses.len() <= 1;
        let hid_small = hid
            .map(|h| h.report_descriptor.len() <= 32)
            .unwrap_or(false);

        if simple_topology && hid_small && mean > 0 && mean < 180 && (jitter > 1000 || std_dev > 550) {
            anomalies.push(
                Anomaly::new(AnomalyType::SuspiciousTimingCoherence, "Forensic").with_details(
                    format!(
                        "Timing incoerente para topologia simples: mean={}us jitter={}us stddev={}us",
                        mean, jitter, std_dev
                    ),
                ),
            );
        }
    }

    fn analyze_descriptor_ordering_consistency(
        &self,
        descriptor_ordering: Option<&DescriptorOrderingResult>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        let Some(ordering) = descriptor_ordering else {
            return;
        };

        let endpoint_count = ordering.endpoint_attributes.len();
        if endpoint_count >= 2 {
            let all_same_interval = ordering
                .endpoint_attributes
                .windows(2)
                .all(|w| w[0].2 == w[1].2);
            let unique_types = ordering
                .bm_attributes_ordering
                .iter()
                .skip(1)
                .copied()
                .collect::<std::collections::HashSet<u8>>()
                .len();

            if all_same_interval && unique_types <= 1 {
                anomalies.push(
                    Anomaly::new(AnomalyType::SuspiciousDescriptorOrdering, "Forensic").with_details(
                        "Ordenacao com intervalos e tipos uniformes em todos endpoints".to_string(),
                    ),
                );
            }
        }
    }

    fn has_excessive_repetition(&self, value: &str) -> bool {
        let chars: Vec<char> = value.chars().filter(|c| !c.is_whitespace()).collect();
        if chars.len() < 6 {
            return false;
        }
        let mut counts = std::collections::HashMap::<char, usize>::new();
        for c in chars.iter().copied() {
            *counts.entry(c).or_insert(0) += 1;
        }
        let max_count = counts.values().copied().max().unwrap_or(0);
        (max_count as f32 / chars.len() as f32) > 0.65
    }

    fn shannon_entropy(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0usize; 256];
        for byte in data {
            freq[*byte as usize] += 1;
        }
        let len = data.len() as f32;
        let mut entropy = 0.0f32;
        for count in freq {
            if count == 0 {
                continue;
            }
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
        entropy
    }
}

impl Default for ForensicEngine {
    fn default() -> Self {
        Self::new()
    }
}
