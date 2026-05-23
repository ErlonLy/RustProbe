use rusb::{Device, Context};
use log::{info, debug, error};
use crate::core::{ConfidenceScore, AnalysisError, Anomaly};
use crate::layers::*;
use crate::engine::{ConfidenceEngine, LayerResults, SignatureDatabase, ProfileLoader};

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
}

pub struct DeviceAnalyzer {
    confidence_engine: ConfidenceEngine,
    signature_db: SignatureDatabase,
    profile_loader: ProfileLoader,
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
                error!("Camada 3 falhou: {}", e);
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
                error!("Camada 4 falhou: {}", e);
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
        let matched_profile_brand = self.profile_loader
            .find_profile(passive.vid, passive.pid)
            .map(|(brand, profile)| {
                info!("Perfil encontrado: {} - {}", brand, profile.name);
                brand.to_string()
            });
        
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
        })
    }
}

impl Default for DeviceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
