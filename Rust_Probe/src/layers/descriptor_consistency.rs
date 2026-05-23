use rusb::{Device, Context};
use std::time::Duration;
use crate::core::{LayerResult, LayerError};

#[derive(Debug, Clone)]
pub struct ConsistencyResult {
    pub iterations: usize,
    pub size_consistent: bool,
    pub content_consistent: bool,
    pub checksums: Vec<u32>,
    pub score: f32,
    pub anomalies: Vec<String>,
}

impl ConsistencyResult {
    pub fn new() -> Self {
        Self {
            iterations: 0,
            size_consistent: true,
            content_consistent: true,
            checksums: Vec::new(),
            score: 1.0,
            anomalies: Vec::new(),
        }
    }
}

impl Default for ConsistencyResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for ConsistencyResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &self.anomalies
    }
    
    fn evidence(&self) -> Vec<String> {
        vec![
            format!("Iteracoes: {}", self.iterations),
            format!("Consistente: {}", if self.content_consistent { "Sim" } else { "Nao" }),
        ]
    }
}

pub struct DescriptorConsistencyAnalyzer;

impl DescriptorConsistencyAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<ConsistencyResult, LayerError> {
        let handle = device.open()
            .map_err(|e| LayerError::NonCritical(format!("Falha ao abrir dispositivo: {}", e)))?;
        
        let descriptors = self.read_descriptor_repeatedly(&handle, 100);
        
        let mut result = ConsistencyResult::new();
        result.iterations = descriptors.len();
        
        if descriptors.is_empty() {
            return Err(LayerError::NonCritical("Nenhum descritor lido".to_string()));
        }
        
        result.content_consistent = self.verify_consistency(&descriptors);
        result.size_consistent = descriptors.iter().all(|d| d.len() == descriptors[0].len());
        
        if !result.content_consistent {
            result.anomalies.push("Descritores inconsistentes detectados".to_string());
            result.score = 0.0;
        }
        
        if !result.size_consistent {
            result.anomalies.push("Tamanhos de descritores inconsistentes".to_string());
            result.score *= 0.5;
        }
        
        Ok(result)
    }
    
    fn read_descriptor_repeatedly(&self, handle: &rusb::DeviceHandle<Context>, iterations: usize) -> Vec<Vec<u8>> {
        let mut descriptors = Vec::new();
        let timeout = Duration::from_millis(100);
        
        for _ in 0..iterations {
            let mut buffer = [0u8; 18];
            if let Ok(n) = handle.read_control(0x80, 0x06, 0x0100, 0, &mut buffer, timeout) {
                descriptors.push(buffer[..n].to_vec());
            }
        }
        
        descriptors
    }
    
    fn verify_consistency(&self, descriptors: &[Vec<u8>]) -> bool {
        if descriptors.is_empty() {
            return true;
        }
        
        let first = &descriptors[0];
        descriptors.iter().all(|d| d == first)
    }
}

impl Default for DescriptorConsistencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
