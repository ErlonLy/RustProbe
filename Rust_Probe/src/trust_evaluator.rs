use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    Genuine,
    BoardModified,
    VidPidSpoofed,
    DeepModification,
    Unknown,
}

impl TrustLevel {
    pub fn as_str(&self) -> &str {
        match self {
            TrustLevel::Genuine => "GENUINE",
            TrustLevel::BoardModified => "BOARD MODIFIED",
            TrustLevel::VidPidSpoofed => "VID/PID SPOOFED",
            TrustLevel::DeepModification => "DEEP MODIFICATION",
            TrustLevel::Unknown => "UNKNOWN",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            TrustLevel::Genuine => 0,
            TrustLevel::BoardModified => 1,
            TrustLevel::VidPidSpoofed => 2,
            TrustLevel::DeepModification => 3,
            TrustLevel::Unknown => 4,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeepAnalysis {
    pub endpoint_count: u8,
    pub interface_count: u8,
    pub configuration_count: u8,
    pub max_power_ma: u16,
    pub usb_version: String,
    pub device_version: String,
    pub timing_anomaly: bool,
    pub endpoint_anomalies: Vec<String>,
    pub power_anomaly: bool,
    pub firmware_signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAnalysis {
    pub bus: u8,
    pub address: u8,
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub trust_level: TrustLevel,
    pub confidence: f32,
    pub flags: Vec<String>,
    pub descriptor_anomalies: Vec<String>,
    pub deep_analysis: Option<DeepAnalysis>,
}

impl DeviceAnalysis {
    pub fn new(
        bus: u8,
        address: u8,
        vid: u16,
        pid: u16,
        manufacturer: Option<String>,
        product: Option<String>,
        serial: Option<String>,
        trust_level: TrustLevel,
        confidence: f32,
        flags: Vec<String>,
        descriptor_anomalies: Vec<String>,
    ) -> Self {
        Self {
            bus,
            address,
            vid,
            pid,
            manufacturer,
            product,
            serial,
            trust_level,
            confidence,
            flags,
            descriptor_anomalies,
            deep_analysis: None,
        }
    }

    pub fn set_deep_analysis(&mut self, analysis: DeepAnalysis) {
        self.deep_analysis = Some(analysis);
    }
}
