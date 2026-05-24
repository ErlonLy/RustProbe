use rusb::{Device, Context};
use log::{info, debug, error};
use crate::core::{ConfidenceScore, AnalysisError, Anomaly, IdentityAnalysis};
use crate::layers::*;
use crate::engine::{ConfidenceEngine, LayerResults, SignatureDatabase, ProfileLoader, FingerprintDatabase, OriginInferenceEngine};

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
    pub confidence: ConfidenceScore,
    pub anomalies: Vec<Anomaly>,
    pub signature_name: String,
    pub is_known_device: bool,
    pub seen_count: u32,
    pub matched_profile_brand: Option<String>,
    pub matched_profile_name: Option<String>,
    pub identity_analysis: Option<IdentityAnalysis>,
}

pub struct DeviceAnalyzer {
    confidence_engine: ConfidenceEngine,
    signature_db: SignatureDatabase,
    profile_loader: ProfileLoader,
    fingerprint_db: FingerprintDatabase,
    origin_inference: OriginInferenceEngine,
}

impl DeviceAnalyzer {
    pub fn new() -> Self {
        let mut profile_loader = ProfileLoader::new();
        
        // Tentar carregar profiles.json
        if let Err(e) = profile_loader.load_from_file("profiles/profiles.json") {
            error!("Falha ao carregar profiles.json: {}", e);
        }
        
        // Create confidence engine with profile loader for rigorous validation
        let confidence_engine = ConfidenceEngine::new().with_profile_loader(profile_loader.clone());
        
        Self {
            confidence_engine,
            signature_db: SignatureDatabase::new("data/device_signatures.json"),
            profile_loader,
            fingerprint_db: FingerprintDatabase::new(),
            origin_inference: OriginInferenceEngine::new(),
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
        
        debug!("Camada 1: Validacao de Descritores Passivos");
        let passive = PassiveDescriptorAnalyzer::new().analyze(device)
            .map_err(|e| AnalysisError::LayerFailed(crate::core::LayerType::PassiveDescriptor, e))?;
        
        info!("Camada 1 concluida - Score: {:.2}", passive.score);
        
        debug!("Camada 2: Fingerprint Estrutural");
        let structural = StructuralFingerprintAnalyzer::new().analyze(device)
            .map_err(|e| AnalysisError::LayerFailed(crate::core::LayerType::StructuralFingerprint, e))?;
        
        info!("Camada 2 concluida - Score: {:.2}", structural.score);
        
        debug!("Camada 3: Fingerprint HID");
        let hid = match HIDFingerprintAnalyzer::new().analyze(device) {
            Ok(result) => {
                if let Some(ref r) = result {
                    info!("Camada 3 concluida - Score: {:.2}", r.score);
                } else {
                    info!("Camada 3: Interface HID nao encontrada");
                }
                result
            }
            Err(e) => {
                // Check if it's a Windows access error (expected for HID devices in use)
                let error_msg = e.to_string();
                if error_msg.contains("Operation not supported") || error_msg.contains("Input/Output") || error_msg.contains("Access") {
                    debug!("Camada 3: Dispositivo HID em uso pelo sistema (esperado no Windows)");
                } else {
                    error!("Camada 3 falhou: {}", e);
                }
                None
            }
        };
        
        debug!("Camada 4: Desafio CDC");
        let cdc = match CDCChallengeAnalyzer::new().analyze(device) {
            Ok(result) => {
                if let Some(ref r) = result {
                    info!("Camada 4 concluida - Score: {:.2}", r.score);
                } else {
                    info!("Camada 4: Interface CDC nao encontrada");
                }
                result
            }
            Err(e) => {
                // Check if it's a Windows access error (expected for devices in use)
                let error_msg = e.to_string();
                if error_msg.contains("Operation not supported") || error_msg.contains("Access") {
                    debug!("Camada 4: Dispositivo em uso pelo sistema (esperado no Windows)");
                } else {
                    error!("Camada 4 falhou: {}", e);
                }
                None
            }
        };
        
        debug!("Camada 5: Requisicoes Invalidas");
        let invalid_request = InvalidRequestAnalyzer::new().analyze(device)
            .unwrap_or_else(|_| InvalidRequestResult::new());
        
        debug!("Camada 6: Analise de Timing");
        let timing = TimingAnalyzer::new().analyze(device)
            .unwrap_or_else(|_| TimingResult::new());
        
        debug!("Camada 7: Consistencia de Descritores");
        let consistency = DescriptorConsistencyAnalyzer::new().analyze(device)
            .unwrap_or_else(|_| ConsistencyResult::new());
        
        debug!("Camada 8: Verificacao de Bootloader");
        let bootloader = BootloaderVerifier::new().analyze(device)
            .unwrap_or(None);
        
        debug!("Camada 9: Fingerprint de Stack");
        let stack = StackFingerprintAnalyzer::new().analyze(device, &structural.topology)
            .unwrap_or_else(|_| StackResult::new());
        
        debug!("Camada 10: Sondagem de Protocolo");
        let protocol = ProtocolProber::new().analyze(device)
            .unwrap_or_else(|_| ProtocolResult::new());
        
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
        
        // Verificar se há perfil conhecido
        let (matched_profile_brand, matched_profile_name) = self.profile_loader
            .find_profile(passive.vid, passive.pid)
            .map(|(brand, profile)| {
                info!("Perfil encontrado: {} - {}", brand, profile.name);
                (Some(brand.to_string()), Some(profile.name.clone()))
            })
            .unwrap_or((None, None));
        
        let (confidence, anomalies) = self.confidence_engine.calculate_confidence(&layer_results, false);
        
        // Obter HID hash se disponível
        let hid_hash = hid.as_ref().map(|h| {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&h.report_descriptor);
            hasher.finalize().to_vec()
        });
        
        // Registrar ou atualizar assinatura do dispositivo
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
        
        // Obter informações da assinatura para logging
        let (is_known_device, seen_count) = self.signature_db.get_signature_info(
            passive.vid,
            passive.pid,
            &structural.fingerprint_hash,
            hid_hash.as_deref(),
            passive.serial.as_deref(),
        );
        
        // CLAIM vs REALITY Analysis
        let identity_analysis = self.perform_identity_analysis(
            &passive,
            &structural,
            &hid,
            &cdc,
            &stack,
            &timing,
        );
        
        info!("Analise concluida - Confianca: {:.2}, Nivel: {:?}, Anomalias: {}, Visto: {}x", 
              confidence.overall, confidence.trust_level, anomalies.len(), seen_count);
        
        Ok(DeviceAnalysis {
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
            confidence,
            anomalies,
            signature_name,
            is_known_device,
            seen_count,
            matched_profile_brand,
            matched_profile_name,
            identity_analysis: Some(identity_analysis),
        })
    }
    
    fn perform_identity_analysis(
        &self,
        passive: &PassiveResult,
        structural: &StructuralResult,
        hid: &Option<HIDResult>,
        cdc: &Option<CDCResult>,
        stack: &StackResult,
        timing: &TimingResult,
    ) -> IdentityAnalysis {
        use crate::core::{ClaimedIdentity, ObservedBehavior, IdentityAnalysis, MismatchSeverity, IdentityMismatch, MismatchDetail};
        
        // Build claimed identity
        let claimed = ClaimedIdentity {
            vid: passive.vid,
            pid: passive.pid,
            manufacturer: passive.manufacturer.clone(),
            product: passive.product.clone(),
            serial: passive.serial.clone(),
            device_class: passive.device_class,
            device_subclass: passive.device_subclass,
            device_protocol: passive.device_protocol,
        };
        
        // Build observed behavior
        let observed = ObservedBehavior {
            num_interfaces: structural.topology.num_interfaces,
            num_endpoints: structural.topology.endpoint_addresses.len(),
            endpoint_addresses: structural.topology.endpoint_addresses.clone(),
            endpoint_packet_sizes: structural.topology.endpoint_max_packet_sizes.clone(),
            endpoint_intervals: structural.topology.endpoint_intervals.clone(),
            hid_report_descriptor_hash: hid.as_ref().map(|h| {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&h.report_descriptor);
                hasher.finalize().to_vec()
            }),
            hid_report_descriptor_size: hid.as_ref().map(|h| h.report_descriptor.len()),
            hid_usage_page: hid.as_ref().and_then(|h| h.usage_page),
            hid_usage: hid.as_ref().and_then(|h| h.usage),
            hid_polling_interval: None, // TODO: extract from endpoint descriptor
            detected_stack: stack.detected_stack.as_ref().map(|s| s.as_str().to_string()),
            stack_confidence: stack.confidence,
            enumeration_timing_us: 0, // TODO: measure
            descriptor_read_jitter_us: timing.repeated_read_stats.jitter_us,
            control_response_avg_us: timing.repeated_read_stats.mean_us,
            has_cdc_remnants: cdc.is_some(),
            has_interface_gaps: structural.topology.num_interfaces > 1 && structural.topology.endpoint_addresses.len() < structural.topology.num_interfaces as usize * 2,
            has_endpoint_gaps: false, // TODO: detect gaps in endpoint numbering
            descriptor_ordering_anomaly: false, // TODO: analyze descriptor order
        };
        
        // Infer origin
        let inferred = self.origin_inference.infer_origin(&observed);
        
        // Detect mismatches
        let mut mismatches = Vec::new();
        let mut mismatch_severity = MismatchSeverity::None;
        
        // Check topology mismatch
        if let Some(topo_match) = self.fingerprint_db.compare_topology(
            passive.vid,
            passive.pid,
            structural.topology.num_interfaces,
            structural.topology.endpoint_addresses.len(),
        ) {
            if !topo_match.matches {
                mismatches.push(MismatchDetail {
                    category: "Topology".to_string(),
                    claimed: format!("{} interfaces, {} endpoints", topo_match.expected_interfaces, topo_match.expected_endpoints),
                    observed: format!("{} interfaces, {} endpoints", topo_match.observed_interfaces, topo_match.observed_endpoints),
                    impact: 0.3,
                });
                mismatch_severity = MismatchSeverity::Major;
            }
        }
        
        // Check impossible combinations
        let impossible = self.origin_inference.detect_impossible_combinations(&claimed, &observed);
        if !impossible.is_empty() {
            for imp in impossible {
                mismatches.push(MismatchDetail {
                    category: "Impossible Combination".to_string(),
                    claimed: format!("VID:0x{:04X} PID:0x{:04X}", passive.vid, passive.pid),
                    observed: imp.clone(),
                    impact: 0.5,
                });
            }
            mismatch_severity = MismatchSeverity::Critical;
        }
        
        // Calculate identity score
        let identity_score = if mismatches.is_empty() {
            1.0
        } else {
            let total_impact: f32 = mismatches.iter().map(|m| m.impact).sum();
            (1.0 - total_impact).max(0.0)
        };
        
        let is_spoofed = mismatch_severity == MismatchSeverity::Major || mismatch_severity == MismatchSeverity::Critical;
        
        IdentityAnalysis {
            claimed,
            observed,
            inferred,
            mismatch: IdentityMismatch {
                has_mismatch: !mismatches.is_empty(),
                severity: mismatch_severity,
                mismatches,
            },
            identity_score,
            is_spoofed,
        }
    }
}

impl Default for DeviceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
