use log::{debug, error, info};
use rusb::{Context, Device};

use crate::core::{
    AnalysisError, Anomaly, AnomalySeverity, AnomalyType, ConfidenceScore, IdentityAnalysis,
    MismatchSeverity, TrustLevel,
};
use crate::engine::{
    AnalysisCache, ConfidenceEngine, FingerprintDatabase, ForensicEngine, IdentityEngine, LayerResults,
    ProfileLoader, SignatureDatabase,
};
use crate::layers::*;

#[derive(Debug, Clone)]
pub struct DeviceAnalysis {
    pub bus: u8,
    pub address: u8,
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
    pub descriptor_ordering: Option<DescriptorOrderingResult>,
    pub confidence: ConfidenceScore,
    pub anomalies: Vec<Anomaly>,
    pub signature_name: String,
    pub is_known_device: bool,
    pub seen_count: u32,
    pub matched_profile_brand: Option<String>,
    pub matched_profile_name: Option<String>,
    pub identity_analysis: Option<IdentityAnalysis>,
    pub nearest_matches: Vec<crate::engine::fingerprint_database::SimilarityMatch>,
}

pub struct DeviceAnalyzer {
    confidence_engine: ConfidenceEngine,
    signature_db: SignatureDatabase,
    profile_loader: ProfileLoader,
    fingerprint_db: FingerprintDatabase,
    identity_engine: IdentityEngine,
    forensic_engine: ForensicEngine,
    analysis_cache: AnalysisCache<DeviceAnalysis>,
    descriptor_cache: AnalysisCache<Option<DescriptorOrderingResult>>,
    hid_hash_cache: AnalysisCache<Option<Vec<u8>>>,
    identity_cache: AnalysisCache<IdentityAnalysis>,
}

impl DeviceAnalyzer {
    pub fn new() -> Self {
        let mut profile_loader = ProfileLoader::new();
        if let Err(e) = profile_loader.load_from_file("profiles/profiles.json") {
            error!("Falha ao carregar profiles.json: {}", e);
        }

        let confidence_engine = ConfidenceEngine::new().with_profile_loader(profile_loader.clone());

        Self {
            confidence_engine,
            signature_db: SignatureDatabase::new("data/device_signatures.json"),
            profile_loader,
            fingerprint_db: FingerprintDatabase::new(),
            identity_engine: IdentityEngine::new(),
            forensic_engine: ForensicEngine::new(),
            analysis_cache: AnalysisCache::new(128),
            descriptor_cache: AnalysisCache::new(256),
            hid_hash_cache: AnalysisCache::new(256),
            identity_cache: AnalysisCache::new(256),
        }
    }

    pub fn get_signature_count(&self) -> usize {
        self.signature_db.count()
    }

    pub fn get_profile_count(&self) -> usize {
        self.profile_loader.count_profiles()
    }

    pub fn analyze(&mut self, device: &Device<Context>) -> Result<DeviceAnalysis, AnalysisError> {
        let bus = device.bus_number();
        let address = device.address();
        info!("Iniciando analise do dispositivo {}:{}", bus, address);

        let passive = PassiveDescriptorAnalyzer::new()
            .analyze(device)
            .map_err(|e| AnalysisError::LayerFailed(crate::core::LayerType::PassiveDescriptor, e))?;

        let cache_key = format!("{}:{}:{:04X}:{:04X}", bus, address, passive.vid, passive.pid);
        if let Some(cached) = self.analysis_cache.get(&cache_key) {
            debug!("Cache HIT para dispositivo {}:{}", bus, address);
            return Ok(cached);
        }

        let structural = StructuralFingerprintAnalyzer::new()
            .analyze(device)
            .map_err(|e| AnalysisError::LayerFailed(crate::core::LayerType::StructuralFingerprint, e))?;

        let hid = HIDFingerprintAnalyzer::new().analyze(device).unwrap_or(None);
        let cdc = CDCChallengeAnalyzer::new().analyze(device).unwrap_or(None);
        let invalid_request = InvalidRequestAnalyzer::new()
            .analyze(device)
            .unwrap_or_else(|_| InvalidRequestResult::new());
        let timing = TimingAnalyzer::new()
            .analyze(device)
            .unwrap_or_else(|_| TimingResult::new());
        let consistency = DescriptorConsistencyAnalyzer::new()
            .analyze(device)
            .unwrap_or_else(|_| ConsistencyResult::new());
        let bootloader = BootloaderVerifier::new().analyze(device).unwrap_or(None);
        let stack = StackFingerprintAnalyzer::new()
            .analyze(device, &structural.topology)
            .unwrap_or_else(|_| StackResult::new());
        let protocol = ProtocolProber::new()
            .analyze(device)
            .unwrap_or_else(|_| ProtocolResult::new());
        let descriptor_ordering = if let Some(cached) = self.descriptor_cache.get(&cache_key) {
            cached
        } else {
            let computed = DescriptorOrderingAnalyzer::new().analyze(device).ok();
            self.descriptor_cache.put(cache_key.clone(), computed.clone());
            computed
        };

        let layer_results = LayerResults {
            passive: passive.clone(),
            structural: structural.clone(),
            hid: hid.clone(),
            cdc: cdc.clone(),
            invalid_request: invalid_request.clone(),
            timing: timing.clone(),
            consistency: consistency.clone(),
            bootloader: bootloader.clone(),
            stack: stack.clone(),
            protocol: protocol.clone(),
        };

        let (matched_profile_brand, matched_profile_name) = self
            .profile_loader
            .find_profile(passive.vid, passive.pid)
            .map(|(brand, profile)| (Some(brand.to_string()), Some(profile.name.clone())))
            .unwrap_or((None, None));

        let (mut confidence, mut anomalies) =
            self.confidence_engine.calculate_confidence(&layer_results, false);
        let forensic_anomalies = self.forensic_engine.analyze(
            &passive,
            &structural,
            hid.as_ref(),
            &timing,
            descriptor_ordering.as_ref(),
        );
        if !forensic_anomalies.is_empty() {
            let forensic_penalty = self.forensic_engine.penalty(&forensic_anomalies);
            anomalies.extend(forensic_anomalies);
            confidence.overall = (confidence.overall - forensic_penalty).max(0.0);
            if confidence.overall < 0.75 && matches!(confidence.trust_level, TrustLevel::Genuine) {
                confidence.trust_level = TrustLevel::BoardModified;
            }
        }

        let identity_key = format!(
            "{}:{}:{:04X}:{:04X}:{:02X}:{}",
            bus,
            address,
            passive.vid,
            passive.pid,
            structural.topology.num_interfaces,
            structural.topology.endpoint_addresses.len()
        );
        let identity_analysis = if let Some(cached) = self.identity_cache.get(&identity_key) {
            cached
        } else {
            let computed = self.identity_engine.analyze_identity(
                &passive,
                &structural,
                &hid,
                &cdc,
                &stack,
                &timing,
                descriptor_ordering.as_ref(),
            );
            self.identity_cache.put(identity_key, computed.clone());
            computed
        };
        self.apply_identity_verdict(&mut confidence, &mut anomalies, &identity_analysis);

        let hid_hash = if let Some(cached) = self.hid_hash_cache.get(&cache_key) {
            cached
        } else {
            let computed = hid.as_ref().map(|h| {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&h.report_descriptor);
                hasher.finalize().to_vec()
            });
            self.hid_hash_cache.put(cache_key.clone(), computed.clone());
            computed
        };

        let signature_name = self.signature_db.find_or_create(
            passive.vid,
            passive.pid,
            &structural.fingerprint_hash,
            hid_hash.as_deref(),
            passive.serial.clone(),
            passive.manufacturer.clone(),
            passive.product.clone(),
            stack.detected_stack.as_ref().map(|s| s.as_str().to_string()),
            confidence.overall,
        );
        let (is_known_device, seen_count) = self.signature_db.get_signature_info(
            passive.vid,
            passive.pid,
            &structural.fingerprint_hash,
            hid_hash.as_deref(),
            passive.serial.as_deref(),
        );

        let nearest_matches = self.fingerprint_db.find_nearest_matches(
            passive.vid,
            passive.pid,
            structural.topology.num_interfaces,
            structural.topology.endpoint_addresses.len(),
            hid_hash.as_deref(),
            stack.detected_stack.as_ref().map(|s| s.as_str()),
            timing.repeated_read_stats.mean_us,
        );

        let analysis = DeviceAnalysis {
            bus,
            address,
            passive,
            structural,
            hid,
            cdc,
            invalid_request,
            timing,
            consistency,
            bootloader,
            stack,
            protocol,
            descriptor_ordering,
            confidence,
            anomalies,
            signature_name,
            is_known_device,
            seen_count,
            matched_profile_brand,
            matched_profile_name,
            identity_analysis: Some(identity_analysis),
            nearest_matches,
        };

        self.analysis_cache.put(cache_key, analysis.clone());
        Ok(analysis)
    }

    fn apply_identity_verdict(
        &self,
        confidence: &mut ConfidenceScore,
        anomalies: &mut Vec<Anomaly>,
        identity: &IdentityAnalysis,
    ) {
        if identity.is_spoofed {
            anomalies.push(
                Anomaly::new(AnomalyType::SuspiciousVidPid, "Identity")
                    .with_severity(AnomalySeverity::Critical)
                    .with_details(format!(
                        "Claim/Reality mismatch severo: {:?}, identity score {:.1}%",
                        identity.mismatch.severity,
                        identity.identity_score * 100.0
                    )),
            );
            confidence.overall = confidence.overall.min(identity.identity_score).min(0.35);
            confidence.trust_level = match identity.mismatch.severity {
                MismatchSeverity::Critical => TrustLevel::DeepModification,
                MismatchSeverity::Major => TrustLevel::VidPidSpoofed,
                _ => TrustLevel::VidPidSpoofed,
            };
        } else if identity.mismatch.has_mismatch {
            let penalty = (1.0 - identity.identity_score) * 0.5;
            confidence.overall = (confidence.overall - penalty).max(0.0);
            if matches!(confidence.trust_level, TrustLevel::Genuine) {
                confidence.trust_level = TrustLevel::BoardModified;
            }
        }
        confidence.anomaly_count = anomalies.len();
    }
}

impl Default for DeviceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
