use std::fmt;

#[derive(Debug)]
pub enum LayerError {
    Critical(String),
    NonCritical(String),
    NotApplicable,
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerError::Critical(msg) => write!(f, "Critical error: {}", msg),
            LayerError::NonCritical(msg) => write!(f, "Non-critical error: {}", msg),
            LayerError::NotApplicable => write!(f, "Layer not applicable"),
        }
    }
}

impl std::error::Error for LayerError {}

#[derive(Debug)]
pub enum AnalysisError {
    UsbContextError(rusb::Error),
    AccessDenied(String),
    DeviceDisconnected,
    Timeout,
    InvalidData(String),
    LayerFailed(LayerType, LayerError),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalysisError::UsbContextError(e) => write!(f, "USB context error: {}", e),
            AnalysisError::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            AnalysisError::DeviceDisconnected => write!(f, "Device disconnected"),
            AnalysisError::Timeout => write!(f, "Operation timeout"),
            AnalysisError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            AnalysisError::LayerFailed(layer, err) => write!(f, "Layer {:?} failed: {}", layer, err),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl From<rusb::Error> for AnalysisError {
    fn from(error: rusb::Error) -> Self {
        match error {
            rusb::Error::Access => AnalysisError::AccessDenied("Insufficient permissions".to_string()),
            rusb::Error::NoDevice => AnalysisError::DeviceDisconnected,
            rusb::Error::Timeout => AnalysisError::Timeout,
            _ => AnalysisError::UsbContextError(error),
        }
    }
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
