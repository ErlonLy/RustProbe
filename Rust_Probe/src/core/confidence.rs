use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TrustLevel {
    Genuine,
    BoardModified,
    VidPidSpoofed,
    DeepModification,
    Unknown,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Genuine => "Genuino",
            TrustLevel::BoardModified => "Placa Modificada",
            TrustLevel::VidPidSpoofed => "VID/PID Falsificado",
            TrustLevel::DeepModification => "Modificacao Profunda",
            TrustLevel::Unknown => "Desconhecido",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceScore {
    pub overall: f32,
    pub passive_score: f32,
    pub structural_score: f32,
    pub hid_score: f32,
    pub active_score: f32,
    pub stack_score: f32,
    pub protocol_score: f32,
    pub trust_level: TrustLevel,
    pub anomaly_count: usize,
    pub whitelist_match: bool,
    pub matched_profile: Option<String>,
}

impl ConfidenceScore {
    pub fn new() -> Self {
        Self {
            overall: 0.0,
            passive_score: 0.0,
            structural_score: 0.0,
            hid_score: 0.0,
            active_score: 0.0,
            stack_score: 0.0,
            protocol_score: 0.0,
            trust_level: TrustLevel::Unknown,
            anomaly_count: 0,
            whitelist_match: false,
            matched_profile: None,
        }
    }

    pub fn classify_trust_level(confidence: f32, anomaly_count: usize, whitelist_match: bool) -> TrustLevel {
        if whitelist_match {
            return TrustLevel::Genuine;
        }

        if confidence >= 0.85 {
            TrustLevel::Genuine
        } else if confidence >= 0.60 {
            TrustLevel::BoardModified
        } else if confidence >= 0.30 && anomaly_count >= 3 {
            TrustLevel::VidPidSpoofed
        } else if confidence >= 0.10 {
            TrustLevel::DeepModification
        } else {
            TrustLevel::Unknown
        }
    }
}

impl Default for ConfidenceScore {
    fn default() -> Self {
        Self::new()
    }
}
