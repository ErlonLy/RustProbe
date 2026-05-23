use rusb::{Device, Context};
use crate::core::{LayerResult, LayerError, USBStack, TopologyData};

#[derive(Debug, Clone)]
pub struct StackResult {
    pub detected_stack: Option<USBStack>,
    pub confidence: f32,
    pub score: f32,
    pub signatures: Vec<String>,
}

impl StackResult {
    pub fn new() -> Self {
        Self {
            detected_stack: None,
            confidence: 0.0,
            score: 0.0,
            signatures: Vec::new(),
        }
    }
}

impl Default for StackResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for StackResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &[]
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        if let Some(ref stack) = self.detected_stack {
            evidence.push(format!("Stack USB detectada: {}", stack.as_str()));
            evidence.push(format!("Confianca: {:.1}%", self.confidence * 100.0));
        }
        evidence
    }
}

pub struct StackFingerprintAnalyzer;

impl StackFingerprintAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, _device: &Device<Context>, topology: &TopologyData) -> Result<StackResult, LayerError> {
        let mut result = StackResult::new();
        
        let lufa_score = self.detect_lufa_signatures(topology);
        let tinyusb_score = self.detect_tinyusb_signatures(topology);
        let espidf_score = self.detect_esp_idf_signatures(topology);
        
        let max_score = lufa_score.max(tinyusb_score).max(espidf_score);
        
        if max_score > 0.5 {
            if max_score == lufa_score {
                result.detected_stack = Some(USBStack::LUFA);
                result.signatures.push("Padrao de endpoints LUFA detectado".to_string());
            } else if max_score == tinyusb_score {
                result.detected_stack = Some(USBStack::TinyUSB);
                result.signatures.push("Padrao IAD TinyUSB detectado".to_string());
            } else {
                result.detected_stack = Some(USBStack::ESPIDF);
                result.signatures.push("Padrao ESP-IDF detectado".to_string());
            }
            result.confidence = max_score;
            result.score = max_score;
        }
        
        Ok(result)
    }
    
    fn detect_lufa_signatures(&self, topology: &TopologyData) -> f32 {
        let mut score = 0.0;
        
        if topology.endpoint_addresses.len() >= 2 {
            if topology.endpoint_addresses[0] == 0x81 && topology.endpoint_addresses.get(1) == Some(&0x82) {
                score += 0.5;
            }
        }
        
        if topology.interface_classes.contains(&0x02) {
            score += 0.3;
        }
        
        score
    }
    
    fn detect_tinyusb_signatures(&self, topology: &TopologyData) -> f32 {
        let mut score = 0.0;
        
        if topology.has_iad {
            score += 0.6;
        }
        
        if topology.interface_classes.len() > 1 {
            score += 0.2;
        }
        
        score
    }
    
    fn detect_esp_idf_signatures(&self, topology: &TopologyData) -> f32 {
        let mut score = 0.0;
        
        if topology.endpoint_addresses.contains(&0x81) && topology.endpoint_addresses.contains(&0x02) {
            score += 0.4;
        }
        
        if topology.num_interfaces >= 2 {
            score += 0.3;
        }
        
        score
    }
}

impl Default for StackFingerprintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
