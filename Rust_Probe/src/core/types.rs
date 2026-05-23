use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::core::LayerType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            TrustLevel::Genuine => "Genuino",
            TrustLevel::BoardModified => "Placa Modificada",
            TrustLevel::VidPidSpoofed => "VID/PID Falsificado",
            TrustLevel::DeepModification => "Modificacao Profunda",
            TrustLevel::Unknown => "Desconhecido",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum USBStack {
    LUFA,
    TinyUSB,
    ESPIDF,
    ArduinoAVR,
    STM32Cube,
    Zephyr,
    PJRC,
    Unknown,
}

impl USBStack {
    pub fn as_str(&self) -> &str {
        match self {
            USBStack::LUFA => "LUFA",
            USBStack::TinyUSB => "TinyUSB",
            USBStack::ESPIDF => "ESP-IDF",
            USBStack::ArduinoAVR => "Arduino AVR",
            USBStack::STM32Cube => "STM32Cube",
            USBStack::Zephyr => "Zephyr",
            USBStack::PJRC => "PJRC/Teensy",
            USBStack::Unknown => "Desconhecido",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeviceCategory {
    ArduinoLeonardo,
    ArduinoMicro,
    ArduinoUno,
    ArduinoMega,
    ESP32S3,
    ESP32S2,
    Teensy3x,
    Teensy4x,
    LogitechMouse,
    LogitechKeyboard,
    MicrosoftMouse,
    MicrosoftKeyboard,
    CP2102Serial,
    FTDISerial,
    CH340Serial,
    GenericHID,
    GenericCDC,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

impl From<rusb::TransferType> for TransferType {
    fn from(tt: rusb::TransferType) -> Self {
        match tt {
            rusb::TransferType::Control => TransferType::Control,
            rusb::TransferType::Isochronous => TransferType::Isochronous,
            rusb::TransferType::Bulk => TransferType::Bulk,
            rusb::TransferType::Interrupt => TransferType::Interrupt,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl From<rusb::Direction> for Direction {
    fn from(dir: rusb::Direction) -> Self {
        match dir {
            rusb::Direction::In => Direction::In,
            rusb::Direction::Out => Direction::Out,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyData {
    pub num_interfaces: u8,
    pub interface_classes: Vec<u8>,
    pub endpoint_addresses: Vec<u8>,
    pub endpoint_types: Vec<u8>,
    pub endpoint_directions: Vec<u8>,
    pub endpoint_max_packet_sizes: Vec<u16>,
    pub endpoint_intervals: Vec<u8>,
    pub has_iad: bool,
    pub cdc_functional_descriptors: Vec<u8>,
}

impl TopologyData {
    pub fn new() -> Self {
        Self {
            num_interfaces: 0,
            interface_classes: Vec::new(),
            endpoint_addresses: Vec::new(),
            endpoint_types: Vec::new(),
            endpoint_directions: Vec::new(),
            endpoint_max_packet_sizes: Vec::new(),
            endpoint_intervals: Vec::new(),
            has_iad: false,
            cdc_functional_descriptors: Vec::new(),
        }
    }
}

impl Default for TopologyData {
    fn default() -> Self {
        Self::new()
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
}

impl Default for ConfidenceScore {
    fn default() -> Self {
        Self::new()
    }
}

pub trait LayerResult {
    fn score(&self) -> f32;
    fn anomalies(&self) -> &[String];
    fn evidence(&self) -> Vec<String>;
}

#[derive(Debug, Clone)]
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
}

impl Default for AggregatedLayerResults {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineCoding {
    pub dte_rate: u32,
    pub char_format: u8,
    pub parity_type: u8,
    pub data_bits: u8,
}

impl LineCoding {
    pub fn default_115200() -> Self {
        Self {
            dte_rate: 115200,
            char_format: 0,
            parity_type: 0,
            data_bits: 8,
        }
    }
}

impl Default for LineCoding {
    fn default() -> Self {
        Self::default_115200()
    }
}

impl PartialEq for LineCoding {
    fn eq(&self, other: &Self) -> bool {
        self.dte_rate == other.dte_rate
            && self.char_format == other.char_format
            && self.parity_type == other.parity_type
            && self.data_bits == other.data_bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestResponse {
    Stall,
    Timeout,
    ValidData,
    DeviceDisconnect,
    UnexpectedAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootloaderType {
    Caterina,
    Teensy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimingClassification {
    RealHardware,
    Emulated,
    Proxied,
    Unknown,
}

impl TimingClassification {
    pub fn as_str(&self) -> &str {
        match self {
            TimingClassification::RealHardware => "Hardware Real",
            TimingClassification::Emulated => "Emulado",
            TimingClassification::Proxied => "Proxy",
            TimingClassification::Unknown => "Desconhecido",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HIDDeviceType {
    Keyboard,
    Mouse,
    Gamepad,
    ArduinoLUFA,
    TinyUSB,
    ESP32,
    Teensy,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResponse {
    Responded(Vec<u8>),
    NoResponse,
    InvalidResponse,
    Error(String),
}
