/// Origin Inference Engine - Reverse Fingerprinting
/// 
/// Infers the TRUE origin of a device based on behavioral signatures,
/// even when compile-time flags are used to spoof identity.

use crate::core::device_identity::*;

pub struct OriginInferenceEngine {
    stack_signatures: Vec<StackSignature>,
}

#[derive(Debug, Clone)]
struct StackSignature {
    name: String,
    indicators: Vec<StackIndicator>,
    confidence_threshold: f32,
}

#[derive(Debug, Clone)]
struct StackIndicator {
    feature: String,
    weight: f32,
}

impl OriginInferenceEngine {
    pub fn new() -> Self {
        Self {
            stack_signatures: Self::build_stack_signatures(),
        }
    }
    
    fn build_stack_signatures() -> Vec<StackSignature> {
        vec![
            // TinyUSB signature
            StackSignature {
                name: "TinyUSB (ESP32-S3/RP2040)".to_string(),
                indicators: vec![
                    StackIndicator { feature: "composite_layout".to_string(), weight: 0.3 },
                    StackIndicator { feature: "endpoint_numbering_sequential".to_string(), weight: 0.2 },
                    StackIndicator { feature: "descriptor_order_tinyusb".to_string(), weight: 0.25 },
                    StackIndicator { feature: "cdc_remnants".to_string(), weight: 0.15 },
                    StackIndicator { feature: "interface_gaps".to_string(), weight: 0.1 },
                ],
                confidence_threshold: 0.6,
            },
            
            // LUFA signature
            StackSignature {
                name: "LUFA (ATmega32U4)".to_string(),
                indicators: vec![
                    StackIndicator { feature: "lufa_descriptor_order".to_string(), weight: 0.35 },
                    StackIndicator { feature: "atmega_timing_pattern".to_string(), weight: 0.25 },
                    StackIndicator { feature: "endpoint_addresses_lufa".to_string(), weight: 0.2 },
                    StackIndicator { feature: "hid_report_lufa_style".to_string(), weight: 0.2 },
                ],
                confidence_threshold: 0.65,
            },
            
            // ESP-IDF signature
            StackSignature {
                name: "ESP-IDF (ESP32)".to_string(),
                indicators: vec![
                    StackIndicator { feature: "esp_idf_timing".to_string(), weight: 0.3 },
                    StackIndicator { feature: "esp_descriptor_layout".to_string(), weight: 0.25 },
                    StackIndicator { feature: "high_jitter".to_string(), weight: 0.2 },
                    StackIndicator { feature: "cdc_acm_pattern".to_string(), weight: 0.15 },
                    StackIndicator { feature: "interface_association".to_string(), weight: 0.1 },
                ],
                confidence_threshold: 0.6,
            },
            
            // Arduino AVR Core
            StackSignature {
                name: "Arduino AVR Core (Leonardo/Micro)".to_string(),
                indicators: vec![
                    StackIndicator { feature: "caterina_bootloader".to_string(), weight: 0.4 },
                    StackIndicator { feature: "arduino_cdc_layout".to_string(), weight: 0.3 },
                    StackIndicator { feature: "atmega_timing".to_string(), weight: 0.2 },
                    StackIndicator { feature: "arduino_vid_pid_pattern".to_string(), weight: 0.1 },
                ],
                confidence_threshold: 0.7,
            },
            
            // STM32 HAL/Cube
            StackSignature {
                name: "STM32 HAL/CubeMX".to_string(),
                indicators: vec![
                    StackIndicator { feature: "stm32_descriptor_order".to_string(), weight: 0.35 },
                    StackIndicator { feature: "stm32_timing_signature".to_string(), weight: 0.25 },
                    StackIndicator { feature: "stm32_endpoint_pattern".to_string(), weight: 0.2 },
                    StackIndicator { feature: "hal_cdc_structure".to_string(), weight: 0.2 },
                ],
                confidence_threshold: 0.65,
            },
            
            // PJRC (Teensy)
            StackSignature {
                name: "PJRC Teensy".to_string(),
                indicators: vec![
                    StackIndicator { feature: "teensy_descriptor_style".to_string(), weight: 0.4 },
                    StackIndicator { feature: "pjrc_vid".to_string(), weight: 0.3 },
                    StackIndicator { feature: "teensy_timing".to_string(), weight: 0.2 },
                    StackIndicator { feature: "teensy_hid_layout".to_string(), weight: 0.1 },
                ],
                confidence_threshold: 0.7,
            },
        ]
    }
    
    /// Infer the true origin of a device based on observed behavior
    pub fn infer_origin(&self, observed: &ObservedBehavior) -> InferredOrigin {
        let mut candidates = Vec::new();
        let mut reasoning = Vec::new();
        
        // Analyze stack signature
        if let Some(ref stack) = observed.detected_stack {
            let stack_candidate = self.analyze_stack_signature(stack, observed);
            if stack_candidate.probability > 0.5 {
                candidates.push(stack_candidate);
            }
        }
        
        // Analyze topology signature
        let topology_candidates = self.analyze_topology_signature(observed);
        candidates.extend(topology_candidates);
        
        // Analyze HID signature
        if let Some(ref hid_hash) = observed.hid_report_descriptor_hash {
            let hid_candidates = self.analyze_hid_signature(hid_hash, observed);
            candidates.extend(hid_candidates);
        }
        
        // Analyze CDC remnants
        if observed.has_cdc_remnants {
            reasoning.push("CDC remnants detected despite claimed HID-only device".to_string());
            
            // Boost TinyUSB/ESP-IDF probability
            for candidate in &mut candidates {
                if candidate.name.contains("TinyUSB") || candidate.name.contains("ESP") {
                    candidate.probability *= 1.3;
                }
            }
        }
        
        // Analyze structural anomalies
        if observed.has_interface_gaps || observed.has_endpoint_gaps {
            reasoning.push("Interface/endpoint gaps suggest composite device with disabled components".to_string());
        }
        
        if observed.descriptor_ordering_anomaly {
            reasoning.push("Descriptor ordering doesn't match claimed manufacturer".to_string());
        }
        
        // Normalize probabilities
        let total: f32 = candidates.iter().map(|c| c.probability).sum();
        if total > 0.0 {
            for candidate in &mut candidates {
                candidate.probability /= total;
            }
        }
        
        // Sort by probability
        candidates.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
        
        // Take top 3
        candidates.truncate(3);
        
        let confidence = candidates.first().map(|c| c.probability).unwrap_or(0.0);
        
        InferredOrigin {
            candidates,
            confidence,
            reasoning,
        }
    }
    
    fn analyze_stack_signature(&self, stack: &str, observed: &ObservedBehavior) -> OriginCandidate {
        let mut evidence = Vec::new();
        let mut probability: f32 = 0.7; // Base probability from stack detection
        
        // Match against known signatures
        for sig in &self.stack_signatures {
            if sig.name.contains(stack) {
                evidence.push(format!("Stack detected: {}", stack));
                
                // Check indicators
                if observed.has_cdc_remnants {
                    evidence.push("CDC remnants present".to_string());
                    probability += 0.1;
                }
                
                if observed.has_interface_gaps {
                    evidence.push("Interface gaps detected".to_string());
                    probability += 0.05;
                }
                
                return OriginCandidate {
                    name: sig.name.clone(),
                    probability: probability.min(0.95_f32),
                    evidence,
                };
            }
        }
        
        // Generic stack match
        OriginCandidate {
            name: format!("{} (generic)", stack),
            probability: 0.5,
            evidence: vec![format!("Stack signature: {}", stack)],
        }
    }
    
    fn analyze_topology_signature(&self, observed: &ObservedBehavior) -> Vec<OriginCandidate> {
        let mut candidates = Vec::new();
        
        // Simplified topology (1 interface, 1 endpoint) = likely Arduino/ESP clone
        if observed.num_interfaces == 1 && observed.num_endpoints == 1 {
            candidates.push(OriginCandidate {
                name: "Arduino/ESP32 Simple HID Clone".to_string(),
                probability: 0.75,
                evidence: vec![
                    "Simplified topology (1 interface, 1 endpoint)".to_string(),
                    "Typical of basic Arduino HID implementations".to_string(),
                ],
            });
        }
        
        // Composite with gaps = TinyUSB with CDC_DISABLED
        if observed.num_interfaces > 1 && (observed.has_interface_gaps || observed.has_endpoint_gaps) {
            candidates.push(OriginCandidate {
                name: "TinyUSB Composite with Disabled CDC".to_string(),
                probability: 0.8,
                evidence: vec![
                    "Multiple interfaces with gaps".to_string(),
                    "Suggests CDC_DISABLED flag usage".to_string(),
                ],
            });
        }
        
        candidates
    }
    
    fn analyze_hid_signature(&self, _hid_hash: &[u8], observed: &ObservedBehavior) -> Vec<OriginCandidate> {
        let mut candidates = Vec::new();
        
        // Generic HID descriptor = likely clone
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
    
    /// Detect impossible combinations (claimed vs observed)
    pub fn detect_impossible_combinations(&self, claimed: &ClaimedIdentity, observed: &ObservedBehavior) -> Vec<String> {
        let mut impossible = Vec::new();
        
        // Logitech device with TinyUSB stack
        if claimed.vid == 0x046D && observed.detected_stack.as_deref() == Some("TinyUSB") {
            impossible.push("Logitech devices don't use TinyUSB stack".to_string());
        }
        
        // Logitech device with ESP-IDF
        if claimed.vid == 0x046D && observed.detected_stack.as_deref() == Some("ESP-IDF") {
            impossible.push("Logitech devices don't use ESP-IDF".to_string());
        }
        
        // Logitech device with LUFA
        if claimed.vid == 0x046D && observed.detected_stack.as_deref() == Some("LUFA") {
            impossible.push("Logitech devices don't use LUFA (ATmega)".to_string());
        }
        
        // Known device with simplified topology
        if claimed.vid == 0x046D && observed.num_interfaces == 1 && observed.num_endpoints == 1 {
            impossible.push("Logitech gaming mice have complex topology (2+ interfaces)".to_string());
        }
        
        // CDC remnants in claimed HID-only device
        if observed.has_cdc_remnants && claimed.device_class == 0x03 {
            impossible.push("HID-only device shouldn't have CDC remnants".to_string());
        }
        
        impossible
    }
}

impl Default for OriginInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}
