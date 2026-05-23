use rusb::{Device, Context};
use std::time::{Duration, Instant};
use crate::core::{LayerResult, LayerError, LineCoding, TimingStats};

#[derive(Debug, Clone)]
pub struct CDCResult {
    pub interface_number: u8,
    pub set_line_coding_success: bool,
    pub get_line_coding_success: bool,
    pub set_control_line_state_success: bool,
    pub line_coding_roundtrip_valid: bool,
    pub timing_stats: TimingStats,
    pub score: f32,
    pub anomalies: Vec<String>,
}

impl CDCResult {
    pub fn new() -> Self {
        Self {
            interface_number: 0,
            set_line_coding_success: false,
            get_line_coding_success: false,
            set_control_line_state_success: false,
            line_coding_roundtrip_valid: false,
            timing_stats: TimingStats::new(),
            score: 0.0,
            anomalies: Vec::new(),
        }
    }
}

impl Default for CDCResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for CDCResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &self.anomalies
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        evidence.push(format!("SET_LINE_CODING: {}", if self.set_line_coding_success { "OK" } else { "FALHOU" }));
        evidence.push(format!("GET_LINE_CODING: {}", if self.get_line_coding_success { "OK" } else { "FALHOU" }));
        evidence.push(format!("Roundtrip valido: {}", if self.line_coding_roundtrip_valid { "Sim" } else { "Nao" }));
        evidence
    }
}

pub struct CDCChallengeAnalyzer;

impl CDCChallengeAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<Option<CDCResult>, LayerError> {
        let cdc_interface = self.find_cdc_interface(device);
        
        if cdc_interface.is_none() {
            return Ok(None);
        }
        
        let interface_num = cdc_interface.unwrap();
        
        let handle = device.open()
            .map_err(|e| LayerError::NonCritical(format!("Falha ao abrir dispositivo: {}", e)))?;
        
        let mut result = CDCResult::new();
        result.interface_number = interface_num;
        result.score = 1.0;
        
        let line_coding = LineCoding::default_115200();
        
        let start = Instant::now();
        match self.set_line_coding(&handle, interface_num, &line_coding) {
            Ok(_) => {
                result.set_line_coding_success = true;
                result.timing_stats.mean_us = start.elapsed().as_micros() as u64;
            }
            Err(e) => {
                result.set_line_coding_success = false;
                result.anomalies.push(format!("SET_LINE_CODING falhou: {}", e));
                result.score *= 0.5;
            }
        }
        
        let start = Instant::now();
        match self.get_line_coding(&handle, interface_num) {
            Ok(retrieved) => {
                result.get_line_coding_success = true;
                let elapsed = start.elapsed().as_micros() as u64;
                
                if retrieved == line_coding {
                    result.line_coding_roundtrip_valid = true;
                } else {
                    result.line_coding_roundtrip_valid = false;
                    result.anomalies.push("Roundtrip de line coding invalido".to_string());
                    result.score *= 0.7;
                }
                
                if elapsed > 100_000 {
                    result.anomalies.push("Tempo de resposta CDC lento".to_string());
                    result.score *= 0.9;
                }
            }
            Err(e) => {
                result.get_line_coding_success = false;
                result.anomalies.push(format!("GET_LINE_CODING falhou: {}", e));
                result.score *= 0.5;
            }
        }
        
        Ok(Some(result))
    }
    
    fn find_cdc_interface(&self, device: &Device<Context>) -> Option<u8> {
        if let Ok(config_desc) = device.active_config_descriptor() {
            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    if interface_desc.class_code() == 0x02 && interface_desc.sub_class_code() == 0x02 {
                        return Some(interface_desc.interface_number());
                    }
                }
            }
        }
        None
    }
    
    fn set_line_coding(&self, handle: &rusb::DeviceHandle<Context>, interface_num: u8, 
                       line_coding: &LineCoding) -> Result<(), rusb::Error> {
        let request_type = 0x21;
        let request = 0x20;
        let value = 0;
        let timeout = Duration::from_millis(1000);
        
        let mut buffer = [0u8; 7];
        buffer[0..4].copy_from_slice(&line_coding.dte_rate.to_le_bytes());
        buffer[4] = line_coding.char_format;
        buffer[5] = line_coding.parity_type;
        buffer[6] = line_coding.data_bits;
        
        handle.write_control(
            request_type,
            request,
            value,
            interface_num as u16,
            &buffer,
            timeout
        )?;
        
        Ok(())
    }
    
    fn get_line_coding(&self, handle: &rusb::DeviceHandle<Context>, interface_num: u8) 
        -> Result<LineCoding, rusb::Error> {
        let request_type = 0xA1;
        let request = 0x21;
        let value = 0;
        let timeout = Duration::from_millis(1000);
        
        let mut buffer = [0u8; 7];
        let bytes_read = handle.read_control(
            request_type,
            request,
            value,
            interface_num as u16,
            &mut buffer,
            timeout
        )?;
        
        if bytes_read != 7 {
            return Err(rusb::Error::Other);
        }
        
        let dte_rate = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        
        Ok(LineCoding {
            dte_rate,
            char_format: buffer[4],
            parity_type: buffer[5],
            data_bits: buffer[6],
        })
    }
}

impl Default for CDCChallengeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
