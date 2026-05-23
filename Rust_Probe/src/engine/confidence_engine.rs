use crate::core::{ConfidenceScore, TrustLevel};
use crate::layers::*;

pub struct LayerResults {
    pub passive: PassiveResult,
    pub structural: StructuralResult,
    pub hid: Option<HIDResult>,
    pub cdc: Option<CDCResult>,
    pub invalid_request: InvalidRequestResult,
    pub timing: TimingResult,
    pub consistency: ConsistencyResult,
    pub bootloader: Option<BootloaderResult>,
    pub stack: StackResult,
    pub protocol: ProtocolResult,
}

pub struct ConfidenceEngine;

impl ConfidenceEngine {
    pub fn new() -> Self {
        Self
    }
    
    pub fn calculate_confidence(&self, results: &LayerResults, whitelist_match: bool) -> ConfidenceScore {
        const PASSIVE_WEIGHT: f32 = 0.15;
        const STRUCTURAL_WEIGHT: f32 = 0.25;
        const HID_WEIGHT: f32 = 0.30;
        const ACTIVE_WEIGHT: f32 = 0.15;
        const STACK_WEIGHT: f32 = 0.10;
        const PROTOCOL_WEIGHT: f32 = 0.05;
        
        let passive_score = results.passive.score;
        let structural_score = results.structural.score;
        let hid_score = results.hid.as_ref().map(|h| h.score).unwrap_or(0.0);
        let active_score = self.calculate_active_score(results);
        let stack_score = results.stack.score;
        let protocol_score = results.protocol.score;
        
        let mut overall = 0.0;
        let mut total_weight = 0.0;
        
        overall += passive_score * PASSIVE_WEIGHT;
        total_weight += PASSIVE_WEIGHT;
        
        overall += structural_score * STRUCTURAL_WEIGHT;
        total_weight += STRUCTURAL_WEIGHT;
        
        if results.hid.is_some() {
            overall += hid_score * HID_WEIGHT;
            total_weight += HID_WEIGHT;
        }
        
        overall += active_score * ACTIVE_WEIGHT;
        total_weight += ACTIVE_WEIGHT;
        
        overall += stack_score * STACK_WEIGHT;
        total_weight += STACK_WEIGHT;
        
        overall += protocol_score * PROTOCOL_WEIGHT;
        total_weight += PROTOCOL_WEIGHT;
        
        overall /= total_weight;
        
        let anomaly_count = self.count_anomalies(results);
        let trust_level = self.classify_trust_level(overall, anomaly_count, whitelist_match);
        let matched_profile = results.structural.matched_profile.clone();
        
        ConfidenceScore {
            overall,
            passive_score,
            structural_score,
            hid_score,
            active_score,
            stack_score,
            protocol_score,
            trust_level,
            anomaly_count,
            whitelist_match,
            matched_profile,
        }
    }
    
    fn calculate_active_score(&self, results: &LayerResults) -> f32 {
        let mut score = 0.0;
        let mut count = 0.0;
        
        if let Some(ref cdc) = results.cdc {
            score += cdc.score;
            count += 1.0;
        }
        
        score += results.invalid_request.score;
        count += 1.0;
        
        score += results.timing.score;
        count += 1.0;
        
        score += results.consistency.score;
        count += 1.0;
        
        if let Some(ref bootloader) = results.bootloader {
            score += bootloader.score;
            count += 1.0;
        }
        
        if count > 0.0 {
            score / count
        } else {
            0.0
        }
    }
    
    fn count_anomalies(&self, results: &LayerResults) -> usize {
        let mut count = 0;
        count += results.passive.anomalies.len();
        count += results.timing.anomalies.len();
        count += results.consistency.anomalies.len();
        count += results.invalid_request.anomalies.len();
        
        if let Some(ref hid) = results.hid {
            count += hid.anomalies.len();
        }
        if let Some(ref cdc) = results.cdc {
            count += cdc.anomalies.len();
        }
        if let Some(ref bootloader) = results.bootloader {
            count += bootloader.anomalies.len();
        }
        
        count
    }
    
    fn classify_trust_level(&self, confidence: f32, anomaly_count: usize, whitelist_match: bool) -> TrustLevel {
        if whitelist_match {
            return TrustLevel::Genuine;
        }
        
        if confidence >= 0.85 {
            TrustLevel::Genuine
        } else if confidence >= 0.60 {
            TrustLevel::BoardModified
        } else if confidence >= 0.30 && anomaly_count >= 3 {
            TrustLevel::VidPidSpoofed
        } else if confidence >= 0.10 {
            TrustLevel::DeepModification
        } else {
            TrustLevel::Unknown
        }
    }
}

impl Default for ConfidenceEngine {
    fn default() -> Self {
        Self::new()
    }
}
