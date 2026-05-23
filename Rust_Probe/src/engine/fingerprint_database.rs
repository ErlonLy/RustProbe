/// Fingerprint Database - Real Device Signatures
/// 
/// This module stores and compares fingerprints of genuine devices
/// to detect spoofing attempts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub vid: u16,
    pub pid: u16,
    pub name: String,
    pub manufacturer: String,
    
    // Topology signature
    pub num_interfaces: u8,
    pub num_endpoints: usize,
    pub endpoint_topology: EndpointTopology,
    
    // HID signature (if applicable)
    pub hid_signature: Option<HIDSignature>,
    
    // Timing signature
    pub timing_signature: TimingSignature,
    
    // Known variations
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointTopology {
    pub addresses: Vec<u8>,
    pub packet_sizes: Vec<u16>,
    pub intervals: Vec<u8>,
    pub transfer_types: Vec<String>,
    pub topology_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HIDSignature {
    pub report_descriptor_hash: String,
    pub report_descriptor_size: usize,
    pub usage_page: u16,
    pub usage: u16,
    pub polling_interval: u8,
    pub num_buttons: Option<u8>,
    pub num_axes: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSignature {
    pub enumeration_avg_us: u64,
    pub enumeration_stddev_us: u64,
    pub descriptor_read_avg_us: u64,
    pub control_response_avg_us: u64,
}

pub struct FingerprintDatabase {
    fingerprints: HashMap<(u16, u16), DeviceFingerprint>,
}

impl FingerprintDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            fingerprints: HashMap::new(),
        };
        
        // Load known genuine devices
        db.load_genuine_devices();
        
        db
    }
    
    fn load_genuine_devices(&mut self) {
        // Logitech G502 HERO
        self.add_fingerprint(DeviceFingerprint {
            vid: 0x046D,
            pid: 0xC08B,
            name: "Logitech G502 HERO Gaming Mouse".to_string(),
            manufacturer: "Logitech".to_string(),
            num_interfaces: 2,
            num_endpoints: 2,
            endpoint_topology: EndpointTopology {
                addresses: vec![0x81, 0x82],
                packet_sizes: vec![8, 20],
                intervals: vec![1, 1],
                transfer_types: vec!["Interrupt".to_string(), "Interrupt".to_string()],
                topology_hash: "g502_hero_topo_v1".to_string(),
            },
            hid_signature: Some(HIDSignature {
                report_descriptor_hash: "g502_hero_hid_v1".to_string(),
                report_descriptor_size: 213,
                usage_page: 0x0001,
                usage: 0x0002,
                polling_interval: 1,
                num_buttons: Some(11),
                num_axes: Some(3),
            }),
            timing_signature: TimingSignature {
                enumeration_avg_us: 150,
                enumeration_stddev_us: 20,
                descriptor_read_avg_us: 50,
                control_response_avg_us: 30,
            },
            variants: vec!["G502 HERO".to_string(), "G502 HERO SE".to_string()],
        });
        
        // Logitech G305
        self.add_fingerprint(DeviceFingerprint {
            vid: 0x046D,
            pid: 0xC539,
            name: "Logitech G305 LIGHTSPEED".to_string(),
            manufacturer: "Logitech".to_string(),
            num_interfaces: 3,
            num_endpoints: 3,
            endpoint_topology: EndpointTopology {
                addresses: vec![0x81, 0x82, 0x83],
                packet_sizes: vec![8, 20, 20],
                intervals: vec![8, 2, 2],
                transfer_types: vec!["Interrupt".to_string(), "Interrupt".to_string(), "Interrupt".to_string()],
                topology_hash: "g305_topo_v1".to_string(),
            },
            hid_signature: Some(HIDSignature {
                report_descriptor_hash: "g305_hid_v1".to_string(),
                report_descriptor_size: 185,
                usage_page: 0x0001,
                usage: 0x0002,
                polling_interval: 8,
                num_buttons: Some(6),
                num_axes: Some(3),
            }),
            timing_signature: TimingSignature {
                enumeration_avg_us: 200,
                enumeration_stddev_us: 30,
                descriptor_read_avg_us: 60,
                control_response_avg_us: 40,
            },
            variants: vec!["G305".to_string()],
        });
        
        // Add more genuine devices here...
    }
    
    fn add_fingerprint(&mut self, fp: DeviceFingerprint) {
        self.fingerprints.insert((fp.vid, fp.pid), fp);
    }
    
    pub fn get_fingerprint(&self, vid: u16, pid: u16) -> Option<&DeviceFingerprint> {
        self.fingerprints.get(&(vid, pid))
    }
    
    pub fn compare_topology(&self, vid: u16, pid: u16, observed_interfaces: u8, observed_endpoints: usize) -> Option<TopologyMatch> {
        if let Some(fp) = self.get_fingerprint(vid, pid) {
            let interfaces_match = fp.num_interfaces == observed_interfaces;
            let endpoints_match = fp.num_endpoints == observed_endpoints;
            
            let confidence = if interfaces_match && endpoints_match {
                1.0
            } else if interfaces_match || endpoints_match {
                0.5
            } else {
                0.0
            };
            
            Some(TopologyMatch {
                matches: interfaces_match && endpoints_match,
                confidence,
                expected_interfaces: fp.num_interfaces,
                observed_interfaces,
                expected_endpoints: fp.num_endpoints,
                observed_endpoints,
            })
        } else {
            None
        }
    }
    
    pub fn compare_hid_signature(&self, vid: u16, pid: u16, observed_hash: &[u8]) -> Option<HIDMatch> {
        if let Some(fp) = self.get_fingerprint(vid, pid) {
            if let Some(ref hid_sig) = fp.hid_signature {
                // Compare hash (simplified - in real implementation, use proper hash comparison)
                let hash_str = observed_hash.iter()
                    .take(16)
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                
                let matches = hid_sig.report_descriptor_hash.contains(&hash_str);
                
                Some(HIDMatch {
                    matches,
                    confidence: if matches { 1.0 } else { 0.0 },
                    expected_hash: hid_sig.report_descriptor_hash.clone(),
                    observed_hash: hash_str,
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopologyMatch {
    pub matches: bool,
    pub confidence: f32,
    pub expected_interfaces: u8,
    pub observed_interfaces: u8,
    pub expected_endpoints: usize,
    pub observed_endpoints: usize,
}

#[derive(Debug, Clone)]
pub struct HIDMatch {
    pub matches: bool,
    pub confidence: f32,
    pub expected_hash: String,
    pub observed_hash: String,
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}
