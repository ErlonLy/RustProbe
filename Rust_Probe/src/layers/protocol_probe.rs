use rusb::{Device, Context};
use crate::core::{LayerResult, LayerError, ProbeResponse};

#[derive(Debug, Clone)]
pub struct ProtocolResult {
    pub arduino_probe: ProbeResponse,
    pub esp_probe: ProbeResponse,
    pub teensy_probe: ProbeResponse,
    pub score: f32,
    pub detected_protocol: Option<String>,
}

impl ProtocolResult {
    pub fn new() -> Self {
        Self {
            arduino_probe: ProbeResponse::NoResponse,
            esp_probe: ProbeResponse::NoResponse,
            teensy_probe: ProbeResponse::NoResponse,
            score: 1.0,
            detected_protocol: None,
        }
    }
}

impl Default for ProtocolResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for ProtocolResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &[]
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        if let Some(ref protocol) = self.detected_protocol {
            evidence.push(format!("Protocolo detectado: {}", protocol));
        }
        evidence
    }
}

pub struct ProtocolProber;

impl ProtocolProber {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, _device: &Device<Context>) -> Result<ProtocolResult, LayerError> {
        Ok(ProtocolResult::new())
    }
}

impl Default for ProtocolProber {
    fn default() -> Self {
        Self::new()
    }
}
