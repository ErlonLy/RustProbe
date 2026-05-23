use std::collections::HashMap;

pub trait LayerResult {
    fn score(&self) -> f32;
    fn anomalies(&self) -> &[String];
    fn evidence(&self) -> Vec<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayerType {
    PassiveDescriptor,
    StructuralFingerprint,
    HIDFingerprint,
    CDCChallenge,
    InvalidRequest,
    TimingAnalysis,
    DescriptorConsistency,
    BootloaderVerification,
    StackFingerprinting,
    ProtocolProbe,
}

impl LayerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LayerType::PassiveDescriptor => "Descritor Passivo",
            LayerType::StructuralFingerprint => "Impressao Digital Estrutural",
            LayerType::HIDFingerprint => "Impressao Digital HID",
            LayerType::CDCChallenge => "Desafio CDC",
            LayerType::InvalidRequest => "Requisicao Invalida",
            LayerType::TimingAnalysis => "Analise de Tempo",
            LayerType::DescriptorConsistency => "Consistencia de Descritor",
            LayerType::BootloaderVerification => "Verificacao de Bootloader",
            LayerType::StackFingerprinting => "Impressao Digital de Stack",
            LayerType::ProtocolProbe => "Sondagem de Protocolo",
        }
    }
}

pub struct AggregatedLayerResults {
    pub layer_scores: HashMap<LayerType, f32>,
    pub layer_anomalies: HashMap<LayerType, Vec<String>>,
    pub layer_evidence: HashMap<LayerType, Vec<String>>,
}

impl AggregatedLayerResults {
    pub fn new() -> Self {
        Self {
            layer_scores: HashMap::new(),
            layer_anomalies: HashMap::new(),
            layer_evidence: HashMap::new(),
        }
    }

    pub fn add_layer<T: LayerResult>(&mut self, layer_type: LayerType, result: &T) {
        self.layer_scores.insert(layer_type, result.score());
        self.layer_anomalies.insert(layer_type, result.anomalies().to_vec());
        self.layer_evidence.insert(layer_type, result.evidence());
    }

    pub fn total_anomaly_count(&self) -> usize {
        self.layer_anomalies.values().map(|v| v.len()).sum()
    }

    pub fn get_score(&self, layer_type: LayerType) -> Option<f32> {
        self.layer_scores.get(&layer_type).copied()
    }

    pub fn get_anomalies(&self, layer_type: LayerType) -> Option<&Vec<String>> {
        self.layer_anomalies.get(&layer_type)
    }

    pub fn get_evidence(&self, layer_type: LayerType) -> Option<&Vec<String>> {
        self.layer_evidence.get(&layer_type)
    }
}

impl Default for AggregatedLayerResults {
    fn default() -> Self {
        Self::new()
    }
}
