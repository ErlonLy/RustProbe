use crate::core::WhitelistProfile;
use crate::engine::LayerResults;

pub struct Whitelist {
    profiles: Vec<WhitelistProfile>,
}

impl Whitelist {
    pub fn new(profiles: Vec<WhitelistProfile>) -> Self {
        Self { profiles }
    }
    
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }
    
    pub fn is_whitelisted(&self, results: &LayerResults) -> bool {
        for profile in &self.profiles {
            if self.match_profile(results, profile) {
                return true;
            }
        }
        false
    }
    
    fn match_profile(&self, results: &LayerResults, profile: &WhitelistProfile) -> bool {
        if let Some((min_vid, max_vid)) = profile.vid_range {
            if results.passive.vid < min_vid || results.passive.vid > max_vid {
                return false;
            }
        }
        
        if let Some(ref structural_fp) = profile.structural_fingerprint {
            let device_fp = results.structural.fingerprint_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            if structural_fp != &device_fp {
                return false;
            }
        }
        
        true
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self::empty()
    }
}
