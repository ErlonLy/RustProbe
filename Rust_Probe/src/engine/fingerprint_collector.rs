




use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use log::{info, warn};

use crate::engine::DeviceAnalysis;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedFingerprint {
    pub timestamp: String,
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    
    
    pub structural_hash: String,
    pub num_interfaces: u8,
    pub num_endpoints: usize,
    pub endpoint_addresses: Vec<u8>,
    pub endpoint_packet_sizes: Vec<u16>,
    pub endpoint_intervals: Vec<u8>,
    pub interface_classes: Vec<u8>,
    
    
    pub hid_report_descriptor_hash: Option<String>,
    pub hid_report_descriptor_size: Option<usize>,
    pub hid_usage_page: Option<u16>,
    pub hid_usage: Option<u16>,
    
    
    pub detected_stack: Option<String>,
    pub stack_confidence: f32,
    
    
    pub timing_mean_us: u64,
    pub timing_stddev_us: u64,
    pub timing_jitter_us: u64,
    
    
    pub device_name: String,
    pub is_genuine: bool,
    pub notes: String,
}

pub struct FingerprintCollector {
    database_path: String,
    fingerprints: Vec<CollectedFingerprint>,
}

impl FingerprintCollector {
    pub fn new(database_path: &str) -> Self {
        let mut collector = Self {
            database_path: database_path.to_string(),
            fingerprints: Vec::new(),
        };
        
        
        if let Err(e) = collector.load() {
            warn!("Não foi possível carregar banco de fingerprints: {}", e);
        }
        
        collector
    }
    
    
    pub fn collect_from_analysis(
        &mut self,
        analysis: &DeviceAnalysis,
        device_name: &str,
        is_genuine: bool,
        notes: &str,
    ) {
        let structural_hash = analysis.structural.fingerprint_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        
        let hid_report_hash = analysis.hid.as_ref().map(|h| {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&h.report_descriptor);
            hasher.finalize()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        });
        
        let fingerprint = CollectedFingerprint {
            timestamp: chrono::Utc::now().to_rfc3339(),
            vid: analysis.passive.vid,
            pid: analysis.passive.pid,
            manufacturer: analysis.passive.manufacturer.clone(),
            product: analysis.passive.product.clone(),
            serial: analysis.passive.serial.clone(),
            structural_hash,
            num_interfaces: analysis.structural.topology.num_interfaces,
            num_endpoints: analysis.structural.topology.endpoint_addresses.len(),
            endpoint_addresses: analysis.structural.topology.endpoint_addresses.clone(),
            endpoint_packet_sizes: analysis.structural.topology.endpoint_max_packet_sizes.clone(),
            endpoint_intervals: analysis.structural.topology.endpoint_intervals.clone(),
            interface_classes: analysis.structural.topology.interface_classes.clone(),
            hid_report_descriptor_hash: hid_report_hash,
            hid_report_descriptor_size: analysis.hid.as_ref().map(|h| h.report_descriptor.len()),
            hid_usage_page: analysis.hid.as_ref().and_then(|h| h.usage_page),
            hid_usage: analysis.hid.as_ref().and_then(|h| h.usage),
            detected_stack: analysis.stack.detected_stack.as_ref().map(|s| s.as_str().to_string()),
            stack_confidence: analysis.stack.confidence,
            timing_mean_us: analysis.timing.repeated_read_stats.mean_us,
            timing_stddev_us: analysis.timing.repeated_read_stats.std_dev_us,
            timing_jitter_us: analysis.timing.repeated_read_stats.jitter_us,
            device_name: device_name.to_string(),
            is_genuine,
            notes: notes.to_string(),
        };
        
        self.fingerprints.push(fingerprint);
        info!("Fingerprint coletado: {} (VID:0x{:04X} PID:0x{:04X})", device_name, analysis.passive.vid, analysis.passive.pid);
    }
    
    
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(&self.fingerprints)?;
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.database_path)?;
        
        file.write_all(json.as_bytes())?;
        
        info!("Salvos {} fingerprints em {}", self.fingerprints.len(), self.database_path);
        Ok(())
    }
    
    
    pub fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new(&self.database_path);
        
        if !path.exists() {
            return Ok(());
        }
        
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        self.fingerprints = serde_json::from_str(&contents)?;
        
        info!("Carregados {} fingerprints de {}", self.fingerprints.len(), self.database_path);
        Ok(())
    }
    
    
    pub fn get_genuine_fingerprints(&self) -> Vec<&CollectedFingerprint> {
        self.fingerprints.iter().filter(|f| f.is_genuine).collect()
    }
    
    
    pub fn get_spoofed_fingerprints(&self) -> Vec<&CollectedFingerprint> {
        self.fingerprints.iter().filter(|f| !f.is_genuine).collect()
    }
    
    
    pub fn find_by_vidpid(&self, vid: u16, pid: u16) -> Vec<&CollectedFingerprint> {
        self.fingerprints.iter()
            .filter(|f| f.vid == vid && f.pid == pid)
            .collect()
    }
    
    
    pub fn compare_against_database(&self, analysis: &DeviceAnalysis) -> FingerprintMatch {
        let genuine_matches = self.find_by_vidpid(analysis.passive.vid, analysis.passive.pid);
        
        if genuine_matches.is_empty() {
            return FingerprintMatch {
                has_match: false,
                confidence: 0.0,
                matched_device: None,
                differences: vec!["No fingerprints found for this VID:PID".to_string()],
            };
        }
        
        
        let analysis_hash = analysis.structural.fingerprint_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        
        for genuine in genuine_matches {
            let mut differences = Vec::new();
            let mut match_score = 100.0;
            
            
            if genuine.structural_hash != analysis_hash {
                differences.push("Structural hash mismatch".to_string());
                match_score -= 30.0;
            }
            
            
            if genuine.num_interfaces != analysis.structural.topology.num_interfaces {
                differences.push(format!(
                    "Interface count mismatch: expected {}, got {}",
                    genuine.num_interfaces,
                    analysis.structural.topology.num_interfaces
                ));
                match_score -= 20.0;
            }
            
            if genuine.num_endpoints != analysis.structural.topology.endpoint_addresses.len() {
                differences.push(format!(
                    "Endpoint count mismatch: expected {}, got {}",
                    genuine.num_endpoints,
                    analysis.structural.topology.endpoint_addresses.len()
                ));
                match_score -= 20.0;
            }
            
            
            if let (Some(ref genuine_hid), Some(ref analysis_hid)) = (&genuine.hid_report_descriptor_hash, &analysis.hid) {
                let analysis_hid_hash = {
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(&analysis_hid.report_descriptor);
                    hasher.finalize()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>()
                };
                
                if genuine_hid != &analysis_hid_hash {
                    differences.push("HID report descriptor mismatch".to_string());
                    match_score -= 25.0;
                }
            }
            
            
            if let (Some(ref genuine_stack), Some(ref analysis_stack)) = (&genuine.detected_stack, &analysis.stack.detected_stack) {
                if genuine_stack != analysis_stack.as_str() {
                    differences.push(format!(
                        "Stack mismatch: expected {}, got {}",
                        genuine_stack,
                        analysis_stack.as_str()
                    ));
                    match_score -= 15.0;
                }
            }
            
            let confidence = (match_score / 100.0_f32).max(0.0);
            
            if confidence > 0.7 {
                return FingerprintMatch {
                    has_match: true,
                    confidence,
                    matched_device: Some(genuine.device_name.clone()),
                    differences,
                };
            }
        }
        
        FingerprintMatch {
            has_match: false,
            confidence: 0.0,
            matched_device: None,
            differences: vec!["Device does not match any genuine fingerprints".to_string()],
        }
    }
    
    
    pub fn export_to_code(&self) -> String {
        let mut code = String::new();
        
        code.push_str("// Auto-generated fingerprints from collected data\n\n");
        
        for fp in self.get_genuine_fingerprints() {
            code.push_str(&format!(
                "// {} (VID:0x{:04X} PID:0x{:04X})\n",
                fp.device_name, fp.vid, fp.pid
            ));
            code.push_str(&format!("// Collected: {}\n", fp.timestamp));
            code.push_str(&format!("// Interfaces: {}, Endpoints: {}\n",
                fp.num_interfaces, fp.num_endpoints));
            if let Some(ref stack) = fp.detected_stack {
                code.push_str(&format!("// Stack: {}\n", stack));
            }
            code.push_str("\n");
        }
        
        code
    }
}

#[derive(Debug, Clone)]
pub struct FingerprintMatch {
    pub has_match: bool,
    pub confidence: f32,
    pub matched_device: Option<String>,
    pub differences: Vec<String>,
}

impl Default for FingerprintCollector {
    fn default() -> Self {
        Self::new("data/collected_fingerprints.json")
    }
}
