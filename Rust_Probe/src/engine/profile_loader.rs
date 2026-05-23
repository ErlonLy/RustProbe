use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use log::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfileEntry {
    pub name: String,
    pub vid: String,
    pub pid: String,
    pub vendor: String,
    pub product: Option<String>,
    pub description: Option<String>,
    pub manufacturer: Option<String>,
    pub usb_product: Option<String>,
    pub usb_manufacturer: Option<String>,
}

impl DeviceProfileEntry {
    pub fn vid_u16(&self) -> Option<u16> {
        u16::from_str_radix(self.vid.trim_start_matches("0x"), 16).ok()
    }
    
    pub fn pid_u16(&self) -> Option<u16> {
        u16::from_str_radix(self.pid.trim_start_matches("0x"), 16).ok()
    }
    
    pub fn matches(&self, vid: u16, pid: u16) -> bool {
        if let (Some(profile_vid), Some(profile_pid)) = (self.vid_u16(), self.pid_u16()) {
            profile_vid == vid && profile_pid == pid
        } else {
            false
        }
    }
}

pub struct ProfileLoader {
    profiles: HashMap<String, HashMap<String, DeviceProfileEntry>>,
}

impl Clone for ProfileLoader {
    fn clone(&self) -> Self {
        Self {
            profiles: self.profiles.clone(),
        }
    }
}

impl ProfileLoader {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }
    
    pub fn load_from_file(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let file_path = Path::new(path);
        
        if !file_path.exists() {
            warn!("Arquivo de perfis não encontrado: {}", path);
            return Ok(());
        }
        
        let mut file = File::open(file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        let profiles: HashMap<String, HashMap<String, DeviceProfileEntry>> = 
            serde_json::from_str(&contents)?;
        
        let mut total_profiles = 0;
        for (brand, devices) in &profiles {
            total_profiles += devices.len();
            self.profiles.insert(brand.clone(), devices.clone());
        }
        
        info!("Carregados {} perfis de {} marcas", total_profiles, self.profiles.len());
        Ok(())
    }
    
    pub fn find_profile(&self, vid: u16, pid: u16) -> Option<(&str, &DeviceProfileEntry)> {
        for (brand, devices) in &self.profiles {
            for (_model, profile) in devices {
                if profile.matches(vid, pid) {
                    return Some((brand, profile));
                }
            }
        }
        None
    }
    
    pub fn find_by_vid(&self, vid: u16) -> Vec<(&str, &str, &DeviceProfileEntry)> {
        let mut results = Vec::new();
        
        for (brand, devices) in &self.profiles {
            for (model, profile) in devices {
                if let Some(profile_vid) = profile.vid_u16() {
                    if profile_vid == vid {
                        results.push((brand.as_str(), model.as_str(), profile));
                    }
                }
            }
        }
        
        results
    }
    
    pub fn get_all_brands(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }
    
    pub fn get_brand_devices(&self, brand: &str) -> Option<&HashMap<String, DeviceProfileEntry>> {
        self.profiles.get(brand)
    }
    
    pub fn count_profiles(&self) -> usize {
        self.profiles.values().map(|devices| devices.len()).sum()
    }
}

impl Default for ProfileLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_profile_entry_parsing() {
        let entry = DeviceProfileEntry {
            name: "Test Device".to_string(),
            vid: "0x046D".to_string(),
            pid: "0xC08B".to_string(),
            vendor: "Logitech".to_string(),
            product: Some("G502".to_string()),
            description: None,
            manufacturer: None,
            usb_product: None,
            usb_manufacturer: None,
        };
        
        assert_eq!(entry.vid_u16(), Some(0x046D));
        assert_eq!(entry.pid_u16(), Some(0xC08B));
        assert!(entry.matches(0x046D, 0xC08B));
        assert!(!entry.matches(0x046D, 0xC08C));
    }
}
