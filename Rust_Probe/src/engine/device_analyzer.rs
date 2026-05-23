use rusb::{Device, Context};
use log::{info, debug, error};
use crate::core::{ConfidenceScore, AnalysisError};
use crate::layers::*;
use crate::engine::{ConfidenceEngine, LayerResults};

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
}

pub struct DeviceAnalyzer {
    confidence_engine: ConfidenceEngine,
}

impl DeviceAnalyzer {
    pub fn new() -> Self {
        Self {
            confidence_engine: ConfidenceEngine::new(),
        }
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<DeviceAnalysis, AnalysisError> {
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
        
        let confidence = self.confidence_engine.calculate_confidence(&layer_results, false);
        
        info!("Analise concluida - Confianca: {:.2}, Nivel: {:?}", 
              confidence.overall, confidence.trust_level);
        
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
        })
    }
}

impl Default for DeviceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
