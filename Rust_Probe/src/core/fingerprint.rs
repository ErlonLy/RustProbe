use serde::{Deserialize, Serialize};
use crate::core::{TimingProfile, USBStack, BootloaderType, ProbeResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbFingerprint {
    pub structural_hash: [u8; 32],
    pub hid_hash: Option<[u8; 32]>,
    pub timing_profile: TimingProfile,
    pub detected_stack: Option<USBStack>,
}

impl UsbFingerprint {
    pub fn new(structural_hash: [u8; 32]) -> Self {
        Self {
            structural_hash,
            hid_hash: None,
            timing_profile: TimingProfile::new(),
            detected_stack: None,
        }
    }
    
    pub fn similarity(&self, other: &UsbFingerprint) -> f32 {
        let mut score = 0.0;
        let mut weight_sum = 0.0;
        
        if self.structural_hash == other.structural_hash {
            score += 0.4;
        }
        weight_sum += 0.4;
        
        if let (Some(h1), Some(h2)) = (&self.hid_hash, &other.hid_hash) {
            if h1 == h2 {
                score += 0.3;
            }
            weight_sum += 0.3;
        }
        
        score += self.timing_profile.similarity(&other.timing_profile) as f64 * 0.2;
        weight_sum += 0.2;
        
        if self.detected_stack == other.detected_stack {
            score += 0.1;
        }
        weight_sum += 0.1;
        
        (score / weight_sum) as f32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootloaderSignature {
    pub bootloader_type: BootloaderType,
    pub validation_passed: bool,
    pub timing_ms: u64,
}

impl BootloaderSignature {
    pub fn new(bootloader_type: BootloaderType) -> Self {
        Self {
            bootloader_type,
            validation_passed: false,
            timing_ms: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolResponses {
    pub arduino_response: ProbeResponse,
    pub esp_response: ProbeResponse,
    pub teensy_response: ProbeResponse,
}

impl ProtocolResponses {
    pub fn new() -> Self {
        Self {
            arduino_response: ProbeResponse::NoResponse,
            esp_response: ProbeResponse::NoResponse,
            teensy_response: ProbeResponse::NoResponse,
        }
    }
}

impl Default for ProtocolResponses {
    fn default() -> Self {
        Self::new()
    }
}
