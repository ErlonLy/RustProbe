use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs::File;
use crate::core::{DeviceCategory, USBStack, TimingProfile, UsbFingerprint};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub category: DeviceCategory,
    pub structural_fingerprint: String,
    pub hid_fingerprint: Option<String>,
    pub expected_stack: Option<USBStack>,
    pub timing_profile: Option<TimingProfile>,
    pub vid_pid_combinations: Vec<(u16, u16)>,
    pub metadata: ProfileMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub created_at: String,
    pub updated_at: String,
    pub version: String,
    pub confidence_threshold: f32,
}

impl DeviceProfile {
    pub fn load_database(path: &Path) -> Result<Vec<DeviceProfile>, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let profiles: Vec<DeviceProfile> = serde_json::from_reader(file)?;
        Ok(profiles)
    }
    
    pub fn matches(&self, fingerprint: &UsbFingerprint) -> ProfileMatch {
        let mut similarity = 0.0;
        let mut weight_sum = 0.0;
        
        let structural_hash_str = hex::encode(fingerprint.structural_hash);
        if self.structural_fingerprint == structural_hash_str {
            similarity += 0.5;
        }
        weight_sum += 0.5;
        
        if let (Some(ref profile_hid), Some(device_hid)) = 
            (&self.hid_fingerprint, &fingerprint.hid_hash) {
            let device_hid_str = hex::encode(device_hid);
            if profile_hid == &device_hid_str {
                similarity += 0.3;
            }
            weight_sum += 0.3;
        }
        
        if self.expected_stack == fingerprint.detected_stack {
            similarity += 0.1;
        }
        weight_sum += 0.1;
        
        if let Some(ref profile_timing) = self.timing_profile {
            similarity += profile_timing.similarity(&fingerprint.timing_profile) as f64 * 0.1;
            weight_sum += 0.1;
        }
        
        let final_similarity = (similarity / weight_sum) as f32;
        
        ProfileMatch {
            profile_name: self.name.clone(),
            profile_id: self.id.clone(),
            similarity: final_similarity,
            matched: final_similarity >= self.metadata.confidence_threshold,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfileMatch {
    pub profile_name: String,
    pub profile_id: String,
    pub similarity: f32,
    pub matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistProfile {
    pub name: String,
    pub vendor: String,
    pub structural_fingerprint: Option<String>,
    pub hid_fingerprint: Option<String>,
    pub vid_range: Option<(u16, u16)>,
    pub allowed_anomalies: Vec<String>,
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
