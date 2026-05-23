use serde::{Deserialize, Serialize};
use crate::core::TimingClassification;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingStats {
    pub mean_us: u64,
    pub std_dev_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub jitter_us: u64,
    pub variance: f64,
}

impl TimingStats {
    pub fn new() -> Self {
        Self {
            mean_us: 0,
            std_dev_us: 0,
            min_us: 0,
            max_us: 0,
            jitter_us: 0,
            variance: 0.0,
        }
    }
    
    pub fn from_measurements(timings: &[u64]) -> Self {
        if timings.is_empty() {
            return Self::new();
        }
        
        let mean = timings.iter().sum::<u64>() / timings.len() as u64;
        let min = *timings.iter().min().unwrap_or(&0);
        let max = *timings.iter().max().unwrap_or(&0);
        let jitter = max - min;
        
        let variance: f64 = timings.iter()
            .map(|&t| {
                let diff = t as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>() / timings.len() as f64;
        
        let std_dev = variance.sqrt() as u64;
        
        Self {
            mean_us: mean,
            std_dev_us: std_dev,
            min_us: min,
            max_us: max,
            jitter_us: jitter,
            variance,
        }
    }
}

impl Default for TimingStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingProfile {
    pub mean_us: u64,
    pub std_dev_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub jitter_us: u64,
    pub variance: f64,
    pub enumeration_latency_us: u64,
}

impl TimingProfile {
    pub fn new() -> Self {
        Self {
            mean_us: 0,
            std_dev_us: 0,
            min_us: 0,
            max_us: 0,
            jitter_us: 0,
            variance: 0.0,
            enumeration_latency_us: 0,
        }
    }
    
    pub fn similarity(&self, other: &TimingProfile) -> f32 {
        let std_dev_diff = (self.std_dev_us as f64 - other.std_dev_us as f64).abs();
        let std_dev_max = self.std_dev_us.max(other.std_dev_us) as f64;
        let std_dev_similarity = if std_dev_max > 0.0 {
            1.0 - (std_dev_diff / std_dev_max).min(1.0)
        } else {
            1.0
        };
        
        let jitter_diff = (self.jitter_us as f64 - other.jitter_us as f64).abs();
        let jitter_max = self.jitter_us.max(other.jitter_us) as f64;
        let jitter_similarity = if jitter_max > 0.0 {
            1.0 - (jitter_diff / jitter_max).min(1.0)
        } else {
            1.0
        };
        
        ((std_dev_similarity + jitter_similarity) / 2.0) as f32
    }
    
    pub fn classify(&self) -> TimingClassification {
        if self.std_dev_us < 5000 {
            TimingClassification::RealHardware
        } else if self.std_dev_us > 20000 {
            TimingClassification::Emulated
        } else if self.jitter_us > 50000 {
            TimingClassification::Proxied
        } else {
            TimingClassification::Unknown
        }
    }
}

impl Default for TimingProfile {
    fn default() -> Self {
        Self::new()
    }
}
