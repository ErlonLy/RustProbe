




use crate::core::device_identity::*;

pub struct OriginInferenceEngine {
    
}

impl OriginInferenceEngine {
    pub fn new() -> Self {
        Self {}
    }
    
    
    pub fn infer_origin(&self, observed: &ObservedBehavior) -> InferredOrigin {
        let mut candidates = Vec::new();
        let mut reasoning = Vec::new();
        
        
        let mut stack_scores: std::collections::HashMap<String, f32> = std::collections::HashMap::new();
        
        
        if let Some(ref stack) = observed.detected_stack {
            let base_score = 0.5; 
            
            
            if stack.contains("TinyUSB") {
                let mut score = base_score;
                
                if observed.has_interface_gaps {
                    score += 0.2; 
                    reasoning.push("Interface gaps (typical of TinyUSB composite)".to_string());
                }
                
                if observed.has_cdc_remnants {
                    score += 0.3; 
                    reasoning.push("CDC remnants despite HID-only claim".to_string());
                }
                
                if observed.descriptor_ordering_anomaly {
                    score += 0.1; 
                    reasoning.push("TinyUSB descriptor ordering pattern".to_string());
                }
                
                if observed.num_interfaces >= 2 && observed.num_endpoints <= 3 {
                    score += 0.15; 
                    reasoning.push("Typical TinyUSB composite layout".to_string());
                }
                
                stack_scores.insert("TinyUSB (ESP32-S3/RP2040)".to_string(), score);
            }
            
            
            if stack.contains("LUFA") {
                let mut score = base_score;
                
                
                if observed.has_endpoint_gaps {
                    score += 0.2;
                    reasoning.push("LUFA endpoint numbering pattern".to_string());
                }
                
                
                if observed.control_response_avg_us < 100 {
                    score += 0.25;
                    reasoning.push("Fast control responses (ATmega timing)".to_string());
                }
                
                stack_scores.insert("LUFA (ATmega32U4)".to_string(), score);
            }
            
            
            if stack.contains("ESP") {
                let mut score = base_score;
                
                if observed.descriptor_read_jitter_us > 500 {
                    score += 0.3; 
                    reasoning.push("High jitter typical of ESP32".to_string());
                }
                
                if observed.has_cdc_remnants {
                    score += 0.2;
                    reasoning.push("CDC/ACM pattern common in ESP-IDF".to_string());
                }
                
                stack_scores.insert("ESP-IDF (ESP32)".to_string(), score);
            }
        }
        
        
        if observed.num_interfaces == 1 && observed.num_endpoints == 1 {
            let score = 0.75;
            stack_scores.insert("Arduino/ESP32 Simple HID Clone".to_string(), score);
            reasoning.push("Simplified topology (1 interface, 1 endpoint)".to_string());
        }
        
        
        if observed.num_interfaces > 1 && (observed.has_interface_gaps || observed.has_endpoint_gaps) {
            let score = 0.8;
            stack_scores.insert("TinyUSB Composite with Disabled CDC".to_string(), score);
            reasoning.push("Multiple interfaces with gaps suggest CDC_DISABLED".to_string());
        }
        
        
        for (name, score) in stack_scores {
            let mut evidence = Vec::new();
            evidence.push(format!("Accumulated confidence: {:.1}%", score * 100.0));
            
            candidates.push(OriginCandidate {
                name,
                probability: score,
                evidence,
            });
        }
        
        
        if let Some(ref hid_hash) = observed.hid_report_descriptor_hash {
            let hid_candidates = self.analyze_hid_signature(hid_hash, observed);
            candidates.extend(hid_candidates);
        }
        
        
        let total: f32 = candidates.iter().map(|c| c.probability).sum();
        if total > 0.0 {
            for candidate in &mut candidates {
                candidate.probability /= total;
            }
        }
        
        
        candidates.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
        
        
        candidates.truncate(3);
        
        let confidence = candidates.first().map(|c| c.probability).unwrap_or(0.0);
        
        InferredOrigin {
            candidates,
            confidence,
            reasoning,
        }
    }
    
    fn analyze_hid_signature(&self, _hid_hash: &[u8], observed: &ObservedBehavior) -> Vec<OriginCandidate> {
        let mut candidates = Vec::new();
        
        
        if let Some(size) = observed.hid_report_descriptor_size {
            if size < 100 {
                candidates.push(OriginCandidate {
                    name: "Generic HID Implementation".to_string(),
                    probability: 0.6,
                    evidence: vec![
                        format!("Small HID descriptor ({} bytes)", size),
                        "Typical of simplified clone implementations".to_string(),
                    ],
                });
            }
        }
        
        candidates
    }
    
    
    pub fn detect_impossible_combinations(&self, claimed: &ClaimedIdentity, observed: &ObservedBehavior) -> Vec<String> {
        let mut impossible = Vec::new();
        
        if self.is_likely_peripheral_vid(claimed.vid) {
            if let Some(stack) = observed.detected_stack.as_deref() {
                if self.is_dev_board_stack(stack) {
                    impossible.push(format!(
                        "Peripheral VID with development-board stack detected: {}",
                        stack
                    ));
                }
            }

            if observed.num_interfaces == 1 && observed.num_endpoints == 1 && !self.is_receiver_like(claimed) {
                impossible.push("Claimed peripheral has oversimplified HID topology (1 interface, 1 endpoint)".to_string());
            }
        }
        
        if observed.has_cdc_remnants && claimed.device_class == 0x03 {
            impossible.push("HID-only device shouldn't have CDC remnants".to_string());
        }
        
        impossible
    }

    fn is_dev_board_stack(&self, stack: &str) -> bool {
        ["TinyUSB", "LUFA", "ESP-IDF", "Arduino AVR", "PJRC/Teensy"]
            .iter()
            .any(|s| stack.contains(s))
    }

    fn is_likely_peripheral_vid(&self, vid: u16) -> bool {
        !self.is_likely_dev_board_vid(vid)
    }

    fn is_likely_dev_board_vid(&self, vid: u16) -> bool {
        matches!(
            vid,
            0x2341 | 0x2A03 | 0x1B4F | 0x303A | 0x16C0 | 0x10C4 | 0x1A86 | 0x0403 | 0x067B | 0x0483
        )
    }

    fn is_receiver_like(&self, claimed: &ClaimedIdentity) -> bool {
        let mut haystack = String::new();
        if let Some(ref p) = claimed.product {
            haystack.push_str(&p.to_lowercase());
            haystack.push(' ');
        }
        if let Some(ref m) = claimed.manufacturer {
            haystack.push_str(&m.to_lowercase());
        }
        haystack.contains("receiver")
            || haystack.contains("dongle")
            || haystack.contains("wireless")
            || haystack.contains("2.4g")
    }
}

impl Default for OriginInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}
