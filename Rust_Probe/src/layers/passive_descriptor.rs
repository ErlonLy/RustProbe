use rusb::{Device, Context};
use std::time::Duration;
use crate::core::{LayerResult, LayerError};

#[derive(Debug, Clone)]
pub struct PassiveResult {
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub usb_version: (u8, u8),
    pub device_version: (u8, u8),
    pub num_configurations: u8,
    pub max_packet_size: u8,
    pub score: f32,
    pub anomalies: Vec<String>,
}

impl PassiveResult {
    pub fn new() -> Self {
        Self {
            vid: 0,
            pid: 0,
            manufacturer: None,
            product: None,
            serial: None,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            usb_version: (0, 0),
            device_version: (0, 0),
            num_configurations: 0,
            max_packet_size: 0,
            score: 0.0,
            anomalies: Vec::new(),
        }
    }
}

impl Default for PassiveResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for PassiveResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &self.anomalies
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        evidence.push(format!("VID: 0x{:04X}, PID: 0x{:04X}", self.vid, self.pid));
        if let Some(ref mfr) = self.manufacturer {
            evidence.push(format!("Fabricante: {}", mfr));
        }
        if let Some(ref prod) = self.product {
            evidence.push(format!("Produto: {}", prod));
        }
        evidence.push(format!("Classe: 0x{:02X}", self.device_class));
        evidence
    }
}

pub struct PassiveDescriptorAnalyzer;

impl PassiveDescriptorAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<PassiveResult, LayerError> {
        let mut result = PassiveResult::new();
        result.score = 1.0;
        
        let desc = device.device_descriptor()
            .map_err(|e| LayerError::Critical(format!("Falha ao ler descritor do dispositivo: {}", e)))?;
        
        result.vid = desc.vendor_id();
        result.pid = desc.product_id();
        result.device_class = desc.class_code();
        result.device_subclass = desc.sub_class_code();
        result.device_protocol = desc.protocol_code();
        result.num_configurations = desc.num_configurations();
        result.max_packet_size = desc.max_packet_size();
        
        let usb_ver = desc.usb_version();
        result.usb_version = (usb_ver.major(), usb_ver.minor());
        
        let dev_ver = desc.device_version();
        result.device_version = (dev_ver.major(), dev_ver.minor());
        
        if let Ok(handle) = device.open() {
            if let Ok(langs) = handle.read_languages(Duration::from_secs(1)) {
                if let Some(&lang) = langs.first() {
                    result.manufacturer = handle.read_manufacturer_string(lang, &desc, Duration::from_secs(1)).ok();
                    result.product = handle.read_product_string(lang, &desc, Duration::from_secs(1)).ok();
                    result.serial = handle.read_serial_number_string(lang, &desc, Duration::from_secs(1)).ok();
                }
            }
        }
        
        if result.manufacturer.is_none() {
            result.anomalies.push("String de fabricante ausente".to_string());
            result.score *= 0.95;
        }
        
        if result.product.is_none() {
            result.anomalies.push("String de produto ausente".to_string());
            result.score *= 0.95;
        }
        
        if result.serial.is_none() {
            result.anomalies.push("Numero de serie ausente".to_string());
            result.score *= 0.98;
        }
        
        if result.device_class == 0xFF {
            result.anomalies.push("Classe vendor-specific detectada".to_string());
            result.score *= 0.9;
        }
        
        Ok(result)
    }
}

impl Default for PassiveDescriptorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
