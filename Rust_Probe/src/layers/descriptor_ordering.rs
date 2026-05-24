









use rusb::{Device, Context};
use sha2::{Sha256, Digest};
use crate::core::{LayerResult, LayerError};

#[derive(Debug, Clone)]
pub struct DescriptorOrderingResult {
    pub ordering_hash: [u8; 32],
    pub raw_bytes_hash: [u8; 32],
    pub descriptor_sequence: Vec<DescriptorType>,
    pub total_length: usize,
    pub string_index_topology: Vec<u8>,
    pub descriptor_lengths: Vec<u8>,
    pub endpoint_attributes: Vec<(u8, u16, u8)>,
    pub bm_attributes_ordering: Vec<u8>,
    pub detected_pattern: Option<StackPattern>,
    pub score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    Device = 0x01,
    Configuration = 0x02,
    String = 0x03,
    Interface = 0x04,
    Endpoint = 0x05,
    InterfaceAssociation = 0x0B,
    HID = 0x21,
    HIDReport = 0x22,
    CDCHeader = 0x24,
    CDCCallManagement = 0x25,
    CDCACM = 0x26,
    CDCUnion = 0x27,
    Unknown = 0xFF,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackPattern {
    TinyUSB,
    LUFA,
    STM32Cube,
    ESPIDF,
    ArduinoAVR,
    PJRC,
    Zephyr,
    Unknown,
}

impl StackPattern {
    pub fn as_str(&self) -> &str {
        match self {
            StackPattern::TinyUSB => "TinyUSB",
            StackPattern::LUFA => "LUFA",
            StackPattern::STM32Cube => "STM32Cube",
            StackPattern::ESPIDF => "ESP-IDF",
            StackPattern::ArduinoAVR => "Arduino AVR",
            StackPattern::PJRC => "PJRC/Teensy",
            StackPattern::Zephyr => "Zephyr",
            StackPattern::Unknown => "Unknown",
        }
    }
}

impl DescriptorOrderingResult {
    pub fn new() -> Self {
        Self {
            ordering_hash: [0u8; 32],
            raw_bytes_hash: [0u8; 32],
            descriptor_sequence: Vec::new(),
            total_length: 0,
            string_index_topology: Vec::new(),
            descriptor_lengths: Vec::new(),
            endpoint_attributes: Vec::new(),
            bm_attributes_ordering: Vec::new(),
            detected_pattern: None,
            score: 0.0,
        }
    }
}

impl Default for DescriptorOrderingResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for DescriptorOrderingResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &[]
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        
        let hash_str = self.ordering_hash.iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        evidence.push(format!("Descriptor ordering hash: {}...", hash_str));
        
        evidence.push(format!("Descriptor sequence length: {}", self.descriptor_sequence.len()));
        evidence.push(format!("Total descriptor length: {} bytes", self.total_length));
        
        if let Some(ref pattern) = self.detected_pattern {
            evidence.push(format!("Detected pattern: {}", pattern.as_str()));
        }
        
        evidence
    }
}

pub struct DescriptorOrderingAnalyzer;

impl DescriptorOrderingAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<DescriptorOrderingResult, LayerError> {
        let config_desc = device.active_config_descriptor()
            .map_err(|e| LayerError::Critical(format!("Failed to read config descriptor: {}", e)))?;
        
        let mut result = DescriptorOrderingResult::new();
        
        
        result.descriptor_sequence = self.extract_descriptor_sequence(&config_desc);
        result.total_length = config_desc.total_length() as usize;
        
        
        result.string_index_topology = self.extract_string_indices(&config_desc);
        
        
        result.descriptor_lengths = self.extract_descriptor_lengths(&config_desc);
        result.bm_attributes_ordering = self.extract_bmattributes_ordering(&config_desc);
        result.endpoint_attributes = self.extract_endpoint_attribute_ordering(&config_desc);
        
        
        result.ordering_hash = self.generate_deep_ordering_hash(
            &result,
            &result.descriptor_lengths,
            &result.bm_attributes_ordering,
            &result.endpoint_attributes,
        );
        result.raw_bytes_hash = self.generate_raw_bytes_hash(&config_desc);
        
        
        result.detected_pattern = self.detect_stack_pattern(&result.descriptor_sequence);
        
        result.score = if result.detected_pattern.is_some() { 1.0 } else { 0.6 };
        
        Ok(result)
    }
    
    fn extract_descriptor_sequence(&self, config_desc: &rusb::ConfigDescriptor) -> Vec<DescriptorType> {
        let mut sequence = Vec::new();
        
        
        sequence.push(DescriptorType::Configuration);
        
        
        let has_cdc = config_desc.interfaces().any(|iface| {
            iface.descriptors().any(|d| d.class_code() == 0x02)
        });
        if has_cdc && config_desc.num_interfaces() > 1 {
            sequence.push(DescriptorType::InterfaceAssociation);
        }
        
        
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                sequence.push(DescriptorType::Interface);
                
                
                if interface_desc.class_code() == 0x03 {
                    sequence.push(DescriptorType::HID);
                }
                
                
                if interface_desc.class_code() == 0x02 {
                    sequence.push(DescriptorType::CDCHeader);
                }
                
                
                for _ in interface_desc.endpoint_descriptors() {
                    sequence.push(DescriptorType::Endpoint);
                }
            }
        }
        
        sequence
    }
    
    
    fn extract_descriptor_lengths(&self, config_desc: &rusb::ConfigDescriptor) -> Vec<u8> {
        let mut lengths = Vec::new();
        
        
        lengths.push(9); 
        
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                
                lengths.push(9); 
                
                
                for endpoint_desc in interface_desc.endpoint_descriptors() {
                    lengths.push(7); 
                    
                    
                    if endpoint_desc.max_packet_size() > 64 {
                        lengths.push(4); 
                    }
                }
            }
        }
        
        lengths
    }
    
    
    fn extract_bmattributes_ordering(&self, config_desc: &rusb::ConfigDescriptor) -> Vec<u8> {
        let mut attributes = Vec::new();
        
        
        attributes.push(config_desc.self_powered() as u8);
        
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                
                for endpoint_desc in interface_desc.endpoint_descriptors() {
                    let transfer_type = endpoint_desc.transfer_type() as u8;
                    attributes.push(transfer_type);
                }
            }
        }
        
        attributes
    }
    
    
    fn extract_endpoint_attribute_ordering(&self, config_desc: &rusb::ConfigDescriptor) -> Vec<(u8, u16, u8)> {
        let mut endpoint_attrs = Vec::new();
        
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                for endpoint_desc in interface_desc.endpoint_descriptors() {
                    endpoint_attrs.push((
                        endpoint_desc.address(),
                        endpoint_desc.max_packet_size(),
                        endpoint_desc.interval(),
                    ));
                }
            }
        }
        
        endpoint_attrs
    }
    
    
    fn generate_deep_ordering_hash(&self, result: &DescriptorOrderingResult, 
                                   lengths: &[u8], 
                                   bmattrs: &[u8],
                                   endpoint_attrs: &[(u8, u16, u8)]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        
        for desc_type in &result.descriptor_sequence {
            hasher.update(&[*desc_type as u8]);
        }
        
        
        for &length in lengths {
            hasher.update(&[length]);
        }
        
        
        for &attr in bmattrs {
            hasher.update(&[attr]);
        }
        
        
        for &(addr, packet_size, interval) in endpoint_attrs {
            hasher.update(&[addr]);
            hasher.update(&packet_size.to_le_bytes());
            hasher.update(&[interval]);
        }
        
        
        hasher.update(&(result.total_length as u32).to_le_bytes());
        
        
        for &index in &result.string_index_topology {
            hasher.update(&[index]);
        }
        
        let result_hash = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result_hash);
        hash
    }

    fn generate_raw_bytes_hash(&self, config_desc: &rusb::ConfigDescriptor) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&config_desc.extra());
        hasher.update(&(config_desc.total_length() as u32).to_le_bytes());
        hasher.update(&[config_desc.num_interfaces()]);
        let result_hash = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result_hash);
        hash
    }
    
    fn extract_string_indices(&self, config_desc: &rusb::ConfigDescriptor) -> Vec<u8> {
        let mut indices = Vec::new();
        
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                let string_index = interface_desc.description_string_index().unwrap_or(0);
                if string_index > 0 {
                    indices.push(string_index);
                }
            }
        }
        
        indices
    }
    
    fn detect_stack_pattern(&self, sequence: &[DescriptorType]) -> Option<StackPattern> {
        
        if self.matches_tinyusb_pattern(sequence) {
            return Some(StackPattern::TinyUSB);
        }
        
        
        if self.matches_lufa_pattern(sequence) {
            return Some(StackPattern::LUFA);
        }
        
        
        if self.matches_stm32_pattern(sequence) {
            return Some(StackPattern::STM32Cube);
        }
        
        
        if self.matches_espidf_pattern(sequence) {
            return Some(StackPattern::ESPIDF);
        }
        
        None
    }
    
    fn matches_tinyusb_pattern(&self, sequence: &[DescriptorType]) -> bool {
        
        if sequence.len() < 3 {
            return false;
        }
        
        
        for i in 0..sequence.len() - 1 {
            if sequence[i] == DescriptorType::InterfaceAssociation 
                && sequence[i + 1] == DescriptorType::Interface {
                return true;
            }
        }
        
        false
    }
    
    fn matches_lufa_pattern(&self, sequence: &[DescriptorType]) -> bool {
        
        for i in 0..sequence.len().saturating_sub(2) {
            if sequence[i] == DescriptorType::Interface
                && sequence[i + 1] == DescriptorType::Endpoint
                && sequence.get(i + 2) == Some(&DescriptorType::HID) {
                return true;
            }
        }
        
        false
    }
    
    fn matches_stm32_pattern(&self, sequence: &[DescriptorType]) -> bool {
        
        for i in 0..sequence.len().saturating_sub(2) {
            if sequence[i] == DescriptorType::Interface
                && sequence[i + 1] == DescriptorType::CDCHeader
                && sequence[i + 2] == DescriptorType::Endpoint {
                return true;
            }
        }
        
        false
    }
    
    fn matches_espidf_pattern(&self, sequence: &[DescriptorType]) -> bool {
        
        let has_cdc = sequence.iter().any(|d| *d == DescriptorType::CDCHeader);
        let has_iad = sequence.iter().any(|d| *d == DescriptorType::InterfaceAssociation);
        
        has_cdc && has_iad
    }
}

impl Default for DescriptorOrderingAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
