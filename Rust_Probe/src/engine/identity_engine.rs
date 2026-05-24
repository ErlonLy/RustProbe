




use crate::core::{ClaimedIdentity, ObservedBehavior, IdentityAnalysis, MismatchSeverity};
use crate::layers::{PassiveResult, StructuralResult, HIDResult, CDCResult, StackResult, TimingResult, DescriptorOrderingResult, StackPattern};
use crate::engine::{MismatchEngine, OriginInferenceEngine};

pub struct IdentityEngine {
    origin_inference: OriginInferenceEngine,
    mismatch_engine: MismatchEngine,
}

impl IdentityEngine {
    pub fn new() -> Self {
        Self {
            origin_inference: OriginInferenceEngine::new(),
            mismatch_engine: MismatchEngine::new(),
        }
    }
    
    
    pub fn analyze_identity(
        &self,
        passive: &PassiveResult,
        structural: &StructuralResult,
        hid: &Option<HIDResult>,
        cdc: &Option<CDCResult>,
        stack: &StackResult,
        timing: &TimingResult,
        descriptor_ordering: Option<&DescriptorOrderingResult>,
    ) -> IdentityAnalysis {
        
        let claimed = self.build_claimed_identity(passive);
        
        
        let observed = self.build_observed_behavior(structural, hid, cdc, stack, timing, descriptor_ordering);
        
        
        let inferred = self.origin_inference.infer_origin(&observed);
        
        
        let mismatch = self.mismatch_engine.detect_mismatches(&claimed, &observed);
        
        
        let identity_score = self.mismatch_engine.calculate_identity_score(&mismatch);
        
        
        let is_spoofed = mismatch.severity == MismatchSeverity::Major || 
                        mismatch.severity == MismatchSeverity::Critical;
        
        IdentityAnalysis {
            claimed,
            observed,
            inferred,
            mismatch,
            identity_score,
            is_spoofed,
        }
    }
    
    
    fn build_claimed_identity(&self, passive: &PassiveResult) -> ClaimedIdentity {
        ClaimedIdentity {
            vid: passive.vid,
            pid: passive.pid,
            manufacturer: passive.manufacturer.clone(),
            product: passive.product.clone(),
            serial: passive.serial.clone(),
            device_class: passive.device_class,
            device_subclass: passive.device_subclass,
            device_protocol: passive.device_protocol,
        }
    }
    
    
    fn build_observed_behavior(
        &self,
        structural: &StructuralResult,
        hid: &Option<HIDResult>,
        cdc: &Option<CDCResult>,
        stack: &StackResult,
        timing: &TimingResult,
        descriptor_ordering: Option<&DescriptorOrderingResult>,
    ) -> ObservedBehavior {
        let descriptor_ordering_anomaly = self.detect_ordering_anomaly(stack, descriptor_ordering);

        ObservedBehavior {
            num_interfaces: structural.topology.num_interfaces,
            num_endpoints: structural.topology.endpoint_addresses.len(),
            endpoint_addresses: structural.topology.endpoint_addresses.clone(),
            endpoint_packet_sizes: structural.topology.endpoint_max_packet_sizes.clone(),
            endpoint_intervals: structural.topology.endpoint_intervals.clone(),
            hid_report_descriptor_hash: hid.as_ref().map(|h| {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&h.report_descriptor);
                hasher.finalize().to_vec()
            }),
            hid_report_descriptor_size: hid.as_ref().map(|h| h.report_descriptor.len()),
            hid_usage_page: hid.as_ref().and_then(|h| h.usage_page),
            hid_usage: hid.as_ref().and_then(|h| h.usage),
            hid_polling_interval: None,
            detected_stack: stack.detected_stack.as_ref().map(|s| s.as_str().to_string()),
            stack_confidence: stack.confidence,
            enumeration_timing_us: 0,
            descriptor_read_jitter_us: timing.repeated_read_stats.jitter_us,
            control_response_avg_us: timing.repeated_read_stats.mean_us,
            has_cdc_remnants: cdc.is_some(),
            has_interface_gaps: structural.topology.num_interfaces > 1 && 
                               structural.topology.endpoint_addresses.len() < structural.topology.num_interfaces as usize * 2,
            has_endpoint_gaps: self.detect_endpoint_gaps(&structural.topology.endpoint_addresses),
            descriptor_ordering_anomaly,
        }
    }

    fn detect_ordering_anomaly(
        &self,
        stack: &StackResult,
        descriptor_ordering: Option<&DescriptorOrderingResult>,
    ) -> bool {
        let Some(ordering) = descriptor_ordering else {
            return false;
        };

        let Some(ref detected_stack) = stack.detected_stack else {
            return false;
        };

        let Some(ref pattern) = ordering.detected_pattern else {
            return false;
        };

        match (detected_stack.as_str(), pattern) {
            ("TinyUSB", StackPattern::TinyUSB) => false,
            ("LUFA", StackPattern::LUFA) => false,
            ("ESP-IDF", StackPattern::ESPIDF) => false,
            ("STM32Cube", StackPattern::STM32Cube) => false,
            _ => true,
        }
    }
    
    
    fn detect_endpoint_gaps(&self, endpoint_addresses: &[u8]) -> bool {
        if endpoint_addresses.len() < 2 {
            return false;
        }
        
        let mut sorted = endpoint_addresses.to_vec();
        sorted.sort_unstable();
        
        for i in 1..sorted.len() {
            let gap = sorted[i].saturating_sub(sorted[i - 1]);
            if gap > 1 {
                return true;
            }
        }
        
        false
    }
    
    
}

impl Default for IdentityEngine {
    fn default() -> Self {
        Self::new()
    }
}
