




use crate::core::{Anomaly, AnomalySeverity};
use crate::layers::*;

#[derive(Debug, Clone, Default)]
pub struct EvidenceVector {
    pub legitimacy: f32,
    pub spoof: f32,
    pub uncertainty: f32,
}

impl EvidenceVector {
    pub fn accumulate_legitimacy(&mut self, value: f32) {
        self.legitimacy += value;
    }

    pub fn accumulate_spoof(&mut self, value: f32) {
        self.spoof += value;
    }

    pub fn accumulate_uncertainty(&mut self, value: f32) {
        self.uncertainty += value;
    }
}

pub struct ScoringEngine {
    base_score: i32,
}

impl ScoringEngine {
    pub fn new() -> Self {
        Self {
            base_score: 50, 
        }
    }
    
    
    pub fn calculate_score(
        &self,
        passive: &PassiveResult,
        structural: &StructuralResult,
        hid: &Option<HIDResult>,
        cdc: &Option<CDCResult>,
        timing: &TimingResult,
        stack: &StackResult,
        protocol: &ProtocolResult,
        anomalies: &[Anomaly],
        has_known_profile: bool,
    ) -> f32 {
        let evidence = self.collect_evidence(
            passive,
            structural,
            hid,
            cdc,
            timing,
            stack,
            protocol,
            anomalies,
            has_known_profile,
        );
        self.evidence_to_score(&evidence)
    }

    pub fn collect_evidence(
        &self,
        passive: &PassiveResult,
        structural: &StructuralResult,
        hid: &Option<HIDResult>,
        cdc: &Option<CDCResult>,
        timing: &TimingResult,
        stack: &StackResult,
        protocol: &ProtocolResult,
        anomalies: &[Anomaly],
        has_known_profile: bool,
    ) -> EvidenceVector {
        let mut e = EvidenceVector::default();

        if structural.score >= 0.9 {
            e.accumulate_legitimacy(0.15);
        } else {
            e.accumulate_uncertainty(0.10);
        }

        if let Some(h) = hid {
            if h.score >= 0.9 {
                e.accumulate_legitimacy(0.20);
            } else {
                e.accumulate_spoof(0.15);
            }
        } else {
            e.accumulate_uncertainty(0.08);
        }

        if passive.manufacturer.is_some() {
            e.accumulate_legitimacy(0.08);
        } else {
            e.accumulate_spoof(0.08);
        }
        if passive.product.is_some() {
            e.accumulate_legitimacy(0.08);
        } else {
            e.accumulate_spoof(0.08);
        }
        if passive.serial.is_none() {
            e.accumulate_uncertainty(0.05);
        }

        if stack.detected_stack.is_some() && stack.confidence >= 0.7 {
            e.accumulate_legitimacy(0.10);
        } else {
            e.accumulate_uncertainty(0.08);
        }

        if let Some(c) = cdc {
            if c.set_line_coding_success && c.get_line_coding_success && c.line_coding_roundtrip_valid {
                e.accumulate_legitimacy(0.08);
            } else {
                e.accumulate_spoof(0.12);
            }
        }

        if timing.repeated_read_stats.std_dev_us < 100 {
            e.accumulate_legitimacy(0.10);
        } else if timing.repeated_read_stats.jitter_us > 1000 {
            e.accumulate_spoof(0.12);
        } else {
            e.accumulate_uncertainty(0.05);
        }

        if protocol.score >= 0.9 {
            e.accumulate_legitimacy(0.08);
        } else {
            e.accumulate_uncertainty(0.06);
        }

        if has_known_profile {
            e.accumulate_legitimacy(0.10);
        } else {
            e.accumulate_uncertainty(0.06);
        }

        for anomaly in anomalies {
            match anomaly.severity {
                AnomalySeverity::Info => e.accumulate_uncertainty(0.01),
                AnomalySeverity::Low => e.accumulate_uncertainty(0.03),
                AnomalySeverity::Medium => e.accumulate_spoof(0.08),
                AnomalySeverity::High => e.accumulate_spoof(0.16),
                AnomalySeverity::Critical => e.accumulate_spoof(0.30),
            }
        }

        e
    }

    fn evidence_to_score(&self, evidence: &EvidenceVector) -> f32 {
        let base = self.base_score as f32 / 100.0;
        let score = base + evidence.legitimacy - evidence.spoof - evidence.uncertainty * 0.4;
        score.clamp(0.0, 1.0)
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_perfect_device() {
        let _engine = ScoringEngine::new();
        
        
        
        
        
    }
    
    #[test]
    fn test_spoofed_device() {
        let _engine = ScoringEngine::new();
        
        
        
        
    }
}
