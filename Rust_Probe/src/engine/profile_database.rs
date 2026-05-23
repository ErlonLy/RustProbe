use std::sync::{Arc, Mutex};
use lru::LruCache;
use crate::core::{DeviceProfile, ProfileMatch};

pub struct ProfileDatabase {
    profiles: Vec<DeviceProfile>,
    cache: Arc<Mutex<LruCache<String, ProfileMatch>>>,
}

impl ProfileDatabase {
    pub fn new(profiles: Vec<DeviceProfile>) -> Self {
        Self {
            profiles,
            cache: Arc::new(Mutex::new(LruCache::new(std::num::NonZeroUsize::new(100).unwrap()))),
        }
    }
    
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }
    
    pub fn match_structural(&self, hash: &[u8; 32]) -> Option<ProfileMatch> {
        let hash_str = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&hash_str) {
                return Some(cached.clone());
            }
        }
        
        let mut best_match: Option<ProfileMatch> = None;
        let mut best_similarity = 0.0f32;
        
        for profile in &self.profiles {
            if profile.structural_fingerprint == hash_str {
                let profile_match = ProfileMatch {
                    profile_name: profile.name.clone(),
                    profile_id: profile.id.clone(),
                    similarity: 1.0,
                    matched: true,
                };
                
                if let Ok(mut cache) = self.cache.lock() {
                    cache.put(hash_str.clone(), profile_match.clone());
                }
                
                return Some(profile_match);
            }
            
            let similarity = self.calculate_partial_similarity(&hash_str, &profile.structural_fingerprint);
            if similarity > best_similarity && similarity > 0.7 {
                best_similarity = similarity;
                best_match = Some(ProfileMatch {
                    profile_name: profile.name.clone(),
                    profile_id: profile.id.clone(),
                    similarity,
                    matched: similarity >= profile.metadata.confidence_threshold,
                });
            }
        }
        
        if let Some(ref m) = best_match {
            if let Ok(mut cache) = self.cache.lock() {
                cache.put(hash_str, m.clone());
            }
        }
        
        best_match
    }
    
    fn calculate_partial_similarity(&self, hash1: &str, hash2: &str) -> f32 {
        if hash1.len() != hash2.len() {
            return 0.0;
        }
        
        let matching_chars = hash1.chars()
            .zip(hash2.chars())
            .filter(|(a, b)| a == b)
            .count();
        
        matching_chars as f32 / hash1.len() as f32
    }
}

impl Default for ProfileDatabase {
    fn default() -> Self {
        Self::empty()
    }
}
