use crate::core::{ConfidenceScore, TrustLevel, Anomaly, AnomalySeverity};
use crate::layers::*;
use crate::engine::ProfileLoader;

pub struct LayerResults {
    pub passive: PassiveResult,
    pub structural: StructuralResult,
    pub hid: Option<HIDResult>,
    pub cdc: Option<CDCResult>,
    pub invalid_request: InvalidRequestResult,
    pub timing: TimingResult,
    pub consistency: ConsistencyResult,
    pub bootloader: Option<BootloaderResult>,
    pub stack: StackResult,
    pub protocol: ProtocolResult,
}

pub struct ConfidenceEngine {
    usb_hub_vids: Vec<u16>,
    profile_loader: Option<ProfileLoader>,
}

impl ConfidenceEngine {
    pub fn new() -> Self {
        Self {
            usb_hub_vids: vec![
                0x1D6B, 
                0x8087, 
                0x0BDA, 
            ],
            profile_loader: None,
        }
    }
    
    pub fn with_profile_loader(mut self, loader: ProfileLoader) -> Self {
        self.profile_loader = Some(loader);
        self
    }
    
    pub fn calculate_confidence(&self, results: &LayerResults, whitelist_match: bool) -> (ConfidenceScore, Vec<Anomaly>) {
        
        let is_usb_hub = self.is_usb_hub(results.passive.vid, results.passive.device_class);
        
        if is_usb_hub {
            return self.handle_usb_hub(results);
        }
        
        
        let anomalies = self.collect_anomalies(results);
        
        
        let overall = self.calculate_weighted_score(results, &anomalies);
        
        
        let trust_level = self.classify_trust_level(overall, &anomalies, whitelist_match);
        
        let confidence = ConfidenceScore {
            overall,
            passive_score: results.passive.score,
            structural_score: results.structural.score,
            hid_score: results.hid.as_ref().map(|h| h.score).unwrap_or(0.0),
            active_score: self.calculate_active_score(results),
            stack_score: results.stack.score,
            protocol_score: results.protocol.score,
            trust_level,
            anomaly_count: anomalies.len(),
            whitelist_match,
            matched_profile: results.structural.matched_profile.clone(),
        };
        
        (confidence, anomalies)
    }
    
    fn is_usb_hub(&self, vid: u16, device_class: u8) -> bool {
        
        self.usb_hub_vids.contains(&vid) || device_class == 0x09
    }
    
    fn handle_usb_hub(&self, results: &LayerResults) -> (ConfidenceScore, Vec<Anomaly>) {
        use crate::core::{Anomaly, AnomalyType};
        
        let anomaly = Anomaly::new(AnomalyType::UsbHubDevice, "Passive")
            .with_details(format!("VID: 0x{:04X}, Classe: 0x{:02X}", 
                                 results.passive.vid, 
                                 results.passive.device_class));
        
        let confidence = ConfidenceScore {
            overall: 1.0,
            passive_score: 1.0,
            structural_score: 1.0,
            hid_score: 0.0,
            active_score: 1.0,
            stack_score: 0.0,
            protocol_score: 1.0,
            trust_level: TrustLevel::Genuine,
            anomaly_count: 0,
            whitelist_match: true,
            matched_profile: Some("USB Hub".to_string()),
        };
        
        (confidence, vec![anomaly])
    }
    
    fn collect_anomalies(&self, results: &LayerResults) -> Vec<Anomaly> {
        use crate::core::{Anomaly, AnomalyType};
        
        let mut anomalies = Vec::new();
        
        
        let has_known_profile = if let Some(ref loader) = self.profile_loader {
            loader.find_profile(results.passive.vid, results.passive.pid).is_some()
        } else {
            false
        };
        
        
        if has_known_profile {
            if results.passive.manufacturer.is_none() {
                anomalies.push(
                    Anomaly::new(AnomalyType::MissingManufacturer, "Passive")
                        .with_severity(AnomalySeverity::High)
                        .with_details("Dispositivo conhecido deveria ter string de fabricante".to_string())
                );
            }
            if results.passive.product.is_none() {
                anomalies.push(
                    Anomaly::new(AnomalyType::MissingProduct, "Passive")
                        .with_severity(AnomalySeverity::High)
                        .with_details("Dispositivo conhecido deveria ter string de produto".to_string())
                );
            }
            
            
            let num_interfaces = results.structural.topology.num_interfaces;
            let num_endpoints = results.structural.topology.endpoint_addresses.len();
            let is_receiver_like = self.is_receiver_like(&results.passive);
            
            
            
            if !is_receiver_like && num_interfaces == 1 && num_endpoints == 1 {
                anomalies.push(
                    Anomaly::new(AnomalyType::SimplifiedStructure, "Structural")
                        .with_severity(AnomalySeverity::High)
                        .with_details(format!(
                            "Estrutura USB simplificada suspeita: {} interface, {} endpoint (dispositivos reais geralmente têm mais)",
                            num_interfaces, num_endpoints
                        ))
                );
            }
        } else {
            
            if results.passive.manufacturer.is_none() {
                anomalies.push(Anomaly::new(AnomalyType::MissingManufacturer, "Passive"));
            }
            if results.passive.product.is_none() {
                anomalies.push(Anomaly::new(AnomalyType::MissingProduct, "Passive"));
            }
        }
        
        
        if results.passive.serial.is_none() {
            anomalies.push(Anomaly::new(AnomalyType::MissingSerial, "Passive"));
        }
        
        if results.passive.device_class == 0xFF {
            anomalies.push(Anomaly::new(AnomalyType::VendorSpecificClass, "Passive"));
        }
        
        
        if let Some(ref hid) = results.hid {
            for anomaly_str in &hid.anomalies {
                if anomaly_str.contains("polling") || anomaly_str.contains("interval") {
                    anomalies.push(Anomaly::new(AnomalyType::SuspiciousPollingRate, "HID")
                        .with_details(anomaly_str.clone()));
                } else if anomaly_str.contains("usage") {
                    anomalies.push(Anomaly::new(AnomalyType::InvalidUsagePage, "HID")
                        .with_details(anomaly_str.clone()));
                }
            }
        }
        
        
        if let Some(ref cdc) = results.cdc {
            if !cdc.set_line_coding_success || !cdc.get_line_coding_success {
                anomalies.push(Anomaly::new(AnomalyType::LineCodingFailed, "CDC"));
            }
            if !cdc.line_coding_roundtrip_valid {
                anomalies.push(Anomaly::new(AnomalyType::RoundtripMismatch, "CDC"));
            }
        }
        
        
        if results.timing.repeated_read_stats.jitter_us > 1000 {
            anomalies.push(Anomaly::new(AnomalyType::HighJitter, "Timing")
                .with_details(format!("Jitter: {} us", results.timing.repeated_read_stats.jitter_us)));
        }
        if results.timing.repeated_read_stats.std_dev_us > 500 {
            anomalies.push(Anomaly::new(AnomalyType::InconsistentTiming, "Timing")
                .with_details(format!("Desvio: {} us", results.timing.repeated_read_stats.std_dev_us)));
        }
        
        
        if results.stack.detected_stack.is_none() {
            anomalies.push(Anomaly::new(AnomalyType::UnknownStack, "Stack"));
        }
        
        
        if let Some(ref bootloader) = results.bootloader {
            for anomaly_str in &bootloader.anomalies {
                if anomaly_str.contains("desenvolvimento") || anomaly_str.contains("Caterina") {
                    anomalies.push(Anomaly::new(AnomalyType::DevelopmentBootloader, "Bootloader")
                        .with_details(anomaly_str.clone()));
                }
            }
        }
        
        anomalies
    }
    
    fn calculate_weighted_score(&self, results: &LayerResults, anomalies: &[Anomaly]) -> f32 {
        
        let mut score = 1.0;
        
        
        for anomaly in anomalies {
            score -= anomaly.severity.score_impact();
        }
        
        if results.stack.detected_stack.is_some() {
            score = (score + 0.05).min(1.0);
        }
        
        
        score.max(0.0).min(1.0)
    }
    
    fn calculate_active_score(&self, results: &LayerResults) -> f32 {
        let mut score = 0.0;
        let mut count = 0.0;
        
        if let Some(ref cdc) = results.cdc {
            score += cdc.score;
            count += 1.0;
        }
        
        score += results.invalid_request.score;
        count += 1.0;
        
        score += results.timing.score;
        count += 1.0;
        
        score += results.consistency.score;
        count += 1.0;
        
        if let Some(ref bootloader) = results.bootloader {
            score += bootloader.score;
            count += 1.0;
        }
        
        if count > 0.0 {
            score / count
        } else {
            0.0
        }
    }
    
    fn classify_trust_level(&self, confidence: f32, anomalies: &[Anomaly], whitelist_match: bool) -> TrustLevel {
        if whitelist_match {
            return TrustLevel::Genuine;
        }
        
        
        let critical_count = anomalies.iter().filter(|a| a.severity == AnomalySeverity::Critical).count();
        let high_count = anomalies.iter().filter(|a| a.severity == AnomalySeverity::High).count();
        
        
        if critical_count > 0 {
            return TrustLevel::DeepModification;
        }
        
        
        if high_count >= 2 {
            return TrustLevel::VidPidSpoofed;
        }
        
        
        if confidence >= 0.90 {
            TrustLevel::Genuine
        } else if confidence >= 0.75 {
            TrustLevel::BoardModified
        } else if confidence >= 0.50 {
            TrustLevel::BoardModified
        } else if confidence >= 0.30 {
            TrustLevel::VidPidSpoofed
        } else {
            TrustLevel::DeepModification
        }
    }

    fn is_receiver_like(&self, passive: &PassiveResult) -> bool {
        let mut haystack = String::new();
        if let Some(ref p) = passive.product {
            haystack.push_str(&p.to_lowercase());
            haystack.push(' ');
        }
        if let Some(ref m) = passive.manufacturer {
            haystack.push_str(&m.to_lowercase());
        }

        haystack.contains("receiver")
            || haystack.contains("dongle")
            || haystack.contains("wireless")
            || haystack.contains("2.4g")
    }
}

impl Default for ConfidenceEngine {
    fn default() -> Self {
        Self::new()
    }
}
