use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    
    MissingManufacturer,
    MissingProduct,
    MissingSerial,
    VendorSpecificClass,
    SuspiciousVidPid,
    DuplicateVidPid,
    
    
    UnusualInterfaceCount,
    SuspiciousInterfaceCombination,
    AnomalousEndpointConfig,
    SimplifiedStructure,
    
    
    InvalidUsagePage,
    SuspiciousPollingRate,
    UnexpectedReportDescriptor,
    
    
    LineCodingFailed,
    RoundtripMismatch,
    UnexpectedResponse,
    
    
    HighJitter,
    InconsistentTiming,
    EmulationPattern,
    SuspiciousTimingCoherence,
    
    
    UnknownStack,
    StackMismatch,
    SuspiciousDescriptorOrdering,
    
    
    DevelopmentBootloader,
    ModifiedBootloader,
    SuspiciousIdentityString,
    DescriptorEntropyAnomaly,
    
    
    UsbHubDevice,
}

impl AnomalyType {
    pub fn as_str(&self) -> &str {
        match self {
            AnomalyType::MissingManufacturer => "String de fabricante ausente",
            AnomalyType::MissingProduct => "String de produto ausente",
            AnomalyType::MissingSerial => "Numero de serie ausente",
            AnomalyType::VendorSpecificClass => "Classe vendor-specific detectada",
            AnomalyType::SuspiciousVidPid => "VID/PID suspeito",
            AnomalyType::DuplicateVidPid => "Multiplos dispositivos com mesmo VID/PID",
            AnomalyType::UnusualInterfaceCount => "Numero incomum de interfaces",
            AnomalyType::SuspiciousInterfaceCombination => "Combinacao suspeita de interfaces (HID+CDC)",
            AnomalyType::AnomalousEndpointConfig => "Configuracao anomala de endpoints",
            AnomalyType::SimplifiedStructure => "Estrutura USB simplificada (possivel clone)",
            AnomalyType::InvalidUsagePage => "Usage Page HID invalido",
            AnomalyType::SuspiciousPollingRate => "Polling rate suspeito",
            AnomalyType::UnexpectedReportDescriptor => "Report descriptor inesperado",
            AnomalyType::LineCodingFailed => "Falha em SET/GET_LINE_CODING",
            AnomalyType::RoundtripMismatch => "Roundtrip CDC invalido",
            AnomalyType::UnexpectedResponse => "Resposta inesperada do dispositivo",
            AnomalyType::HighJitter => "Jitter de timing elevado",
            AnomalyType::InconsistentTiming => "Timing inconsistente",
            AnomalyType::EmulationPattern => "Padrao de emulacao detectado",
            AnomalyType::SuspiciousTimingCoherence => "Coerencia temporal suspeita",
            AnomalyType::UnknownStack => "Stack USB desconhecida",
            AnomalyType::StackMismatch => "Stack nao corresponde ao esperado",
            AnomalyType::SuspiciousDescriptorOrdering => "Ordenacao de descritores suspeita",
            AnomalyType::DevelopmentBootloader => "Bootloader de desenvolvimento detectado",
            AnomalyType::ModifiedBootloader => "Bootloader modificado",
            AnomalyType::SuspiciousIdentityString => "Strings de identidade suspeitas",
            AnomalyType::DescriptorEntropyAnomaly => "Entropia de descritor anomala",
            AnomalyType::UsbHubDevice => "Dispositivo USB Hub",
        }
    }
    
    pub fn severity(&self) -> AnomalySeverity {
        match self {
            AnomalyType::MissingManufacturer => AnomalySeverity::Low,
            AnomalyType::MissingProduct => AnomalySeverity::Low,
            AnomalyType::MissingSerial => AnomalySeverity::Low,
            AnomalyType::VendorSpecificClass => AnomalySeverity::Medium,
            AnomalyType::SuspiciousVidPid => AnomalySeverity::Critical,
            AnomalyType::DuplicateVidPid => AnomalySeverity::Critical,
            AnomalyType::UnusualInterfaceCount => AnomalySeverity::Low,
            AnomalyType::SuspiciousInterfaceCombination => AnomalySeverity::High,
            AnomalyType::AnomalousEndpointConfig => AnomalySeverity::Medium,
            AnomalyType::SimplifiedStructure => AnomalySeverity::High,
            AnomalyType::InvalidUsagePage => AnomalySeverity::Medium,
            AnomalyType::SuspiciousPollingRate => AnomalySeverity::High,
            AnomalyType::UnexpectedReportDescriptor => AnomalySeverity::Medium,
            AnomalyType::LineCodingFailed => AnomalySeverity::Medium,
            AnomalyType::RoundtripMismatch => AnomalySeverity::High,
            AnomalyType::UnexpectedResponse => AnomalySeverity::Medium,
            AnomalyType::HighJitter => AnomalySeverity::Medium,
            AnomalyType::InconsistentTiming => AnomalySeverity::High,
            AnomalyType::EmulationPattern => AnomalySeverity::Critical,
            AnomalyType::SuspiciousTimingCoherence => AnomalySeverity::Medium,
            AnomalyType::UnknownStack => AnomalySeverity::Low,
            AnomalyType::StackMismatch => AnomalySeverity::Medium,
            AnomalyType::SuspiciousDescriptorOrdering => AnomalySeverity::High,
            AnomalyType::DevelopmentBootloader => AnomalySeverity::High,
            AnomalyType::ModifiedBootloader => AnomalySeverity::Critical,
            AnomalyType::SuspiciousIdentityString => AnomalySeverity::Medium,
            AnomalyType::DescriptorEntropyAnomaly => AnomalySeverity::Medium,
            AnomalyType::UsbHubDevice => AnomalySeverity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Info,      
    Low,       
    Medium,    
    High,      
    Critical,  
}

impl AnomalySeverity {
    pub fn score_impact(&self) -> f32 {
        match self {
            AnomalySeverity::Info => 0.0,
            AnomalySeverity::Low => 0.02,
            AnomalySeverity::Medium => 0.05,
            AnomalySeverity::High => 0.10,
            AnomalySeverity::Critical => 0.20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub layer: String,
    pub description: String,
    pub severity: AnomalySeverity,
    pub details: Option<String>,
}

impl Anomaly {
    pub fn new(anomaly_type: AnomalyType, layer: &str) -> Self {
        let severity = anomaly_type.severity();
        Self {
            anomaly_type: anomaly_type.clone(),
            layer: layer.to_string(),
            description: anomaly_type.as_str().to_string(),
            severity,
            details: None,
        }
    }
    
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
    
    pub fn with_severity(mut self, severity: AnomalySeverity) -> Self {
        self.severity = severity;
        self
    }
}
