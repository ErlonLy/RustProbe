use rusb::{Device, Context};
use std::time::{Duration, Instant};
use crate::core::{LayerResult, LayerError, TimingStats};

#[derive(Debug, Clone)]
pub struct TimingResult {
    pub enumeration_latency_us: u64,
    pub descriptor_read_stats: TimingStats,
    pub control_transfer_stats: TimingStats,
    pub repeated_read_stats: TimingStats,
    pub score: f32,
    pub is_consistent: bool,
    pub anomalies: Vec<String>,
}

impl TimingResult {
    pub fn new() -> Self {
        Self {
            enumeration_latency_us: 0,
            descriptor_read_stats: TimingStats::new(),
            control_transfer_stats: TimingStats::new(),
            repeated_read_stats: TimingStats::new(),
            score: 1.0,
            is_consistent: true,
            anomalies: Vec::new(),
        }
    }
}

impl Default for TimingResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for TimingResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &self.anomalies
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        evidence.push(format!("Media: {} us", self.repeated_read_stats.mean_us));
        evidence.push(format!("Desvio padrao: {} us", self.repeated_read_stats.std_dev_us));
        evidence.push(format!("Jitter: {} us", self.repeated_read_stats.jitter_us));
        evidence
    }
}

pub struct TimingAnalyzer;

impl TimingAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<TimingResult, LayerError> {
        let handle = device.open()
            .map_err(|e| LayerError::NonCritical(format!("Falha ao abrir dispositivo: {}", e)))?;
        
        let timings = self.measure_repeated_reads(&handle, 100);
        
        if timings.len() < 50 {
            return Err(LayerError::NonCritical("Amostras de timing insuficientes".to_string()));
        }
        
        let stats = TimingStats::from_measurements(&timings);
        
        let mut result = TimingResult::new();
        result.repeated_read_stats = stats.clone();
        result.descriptor_read_stats = stats;
        
        if result.repeated_read_stats.std_dev_us > 20000 {
            result.anomalies.push("Alta variancia de timing detectada".to_string());
            result.is_consistent = false;
            result.score *= 0.7;
        }
        
        if result.repeated_read_stats.jitter_us > 50000 {
            result.anomalies.push("Jitter excessivo detectado".to_string());
            result.score *= 0.8;
        }
        
        Ok(result)
    }
    
    fn measure_repeated_reads(&self, handle: &rusb::DeviceHandle<Context>, iterations: usize) -> Vec<u64> {
        let mut timings = Vec::new();
        let timeout = Duration::from_millis(100);
        
        for _ in 0..iterations {
            let start = Instant::now();
            if handle.read_languages(timeout).is_ok() {
                timings.push(start.elapsed().as_micros() as u64);
            }
        }
        
        timings
    }
}

impl Default for TimingAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
