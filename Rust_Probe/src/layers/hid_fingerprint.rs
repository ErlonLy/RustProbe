use rusb::{Device, Context};
use sha2::{Sha256, Digest};
use std::time::Duration;
use crate::core::{LayerResult, LayerError};

#[derive(Debug, Clone)]
pub struct HIDResult {
    pub interface_number: u8,
    pub report_descriptor: Vec<u8>,
    pub fingerprint_hash: [u8; 32],
    pub matched_profile: Option<String>,
    pub similarity: f32,
    pub score: f32,
    pub usage_page: Option<u16>,
    pub usage: Option<u16>,
    pub anomalies: Vec<String>,
}

impl HIDResult {
    pub fn new() -> Self {
        Self {
            interface_number: 0,
            report_descriptor: Vec::new(),
            fingerprint_hash: [0u8; 32],
            matched_profile: None,
            similarity: 0.0,
            score: 0.0,
            usage_page: None,
            usage: None,
            anomalies: Vec::new(),
        }
    }
}

impl Default for HIDResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for HIDResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &self.anomalies
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        let hash_str = self.fingerprint_hash.iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        evidence.push(format!("HID Fingerprint: {}...", hash_str));
        if let Some(page) = self.usage_page {
            evidence.push(format!("Usage Page: 0x{:04X}", page));
        }
        if let Some(usage) = self.usage {
            evidence.push(format!("Usage: 0x{:04X}", usage));
        }
        evidence
    }
}

pub struct HIDFingerprintAnalyzer;

impl HIDFingerprintAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<Option<HIDResult>, LayerError> {
        let hid_interface = self.find_hid_interface(device);
        
        if hid_interface.is_none() {
            return Ok(None);
        }
        
        let interface_num = hid_interface.unwrap();
        
        let handle = device.open()
            .map_err(|e| LayerError::NonCritical(format!("Falha ao abrir dispositivo: {}", e)))?;
        
        match self.read_hid_report_descriptor(&handle, interface_num) {
            Ok(descriptor) => {
                let mut hasher = Sha256::new();
                hasher.update(&descriptor);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                
                let usage_page = self.extract_usage_page(&descriptor);
                let usage = self.extract_usage(&descriptor);
                
                Ok(Some(HIDResult {
                    interface_number: interface_num,
                    report_descriptor: descriptor,
                    fingerprint_hash: hash,
                    matched_profile: None,
                    similarity: 0.0,
                    score: 1.0,
                    usage_page,
                    usage,
                    anomalies: Vec::new(),
                }))
            }
            Err(e) => {
                Err(LayerError::NonCritical(format!("Falha ao ler descritor HID: {}", e)))
            }
        }
    }
    
    fn find_hid_interface(&self, device: &Device<Context>) -> Option<u8> {
        if let Ok(config_desc) = device.active_config_descriptor() {
            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    if interface_desc.class_code() == 0x03 {
                        return Some(interface_desc.interface_number());
                    }
                }
            }
        }
        None
    }
    
    fn read_hid_report_descriptor(&self, handle: &rusb::DeviceHandle<Context>, interface_num: u8) 
        -> Result<Vec<u8>, rusb::Error> {
        let request_type = 0x81;
        let request = 0x06;
        let value = 0x2200;
        let timeout = Duration::from_millis(1000);
        
        let mut buffer = vec![0u8; 4096];
        let bytes_read = handle.read_control(
            request_type,
            request,
            value,
            interface_num as u16,
            &mut buffer,
            timeout
        )?;
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    
    fn extract_usage_page(&self, descriptor: &[u8]) -> Option<u16> {
        for i in 0..descriptor.len().saturating_sub(1) {
            if descriptor[i] == 0x05 {
                return Some(descriptor[i + 1] as u16);
            }
        }
        None
    }
    
    fn extract_usage(&self, descriptor: &[u8]) -> Option<u16> {
        for i in 0..descriptor.len().saturating_sub(1) {
            if descriptor[i] == 0x09 {
                return Some(descriptor[i + 1] as u16);
            }
        }
        None
    }
}

impl Default for HIDFingerprintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
