use rusb::{Device, Context};
use std::time::Duration;
use crate::core::{LayerResult, LayerError, RequestResponse};

#[derive(Debug, Clone)]
pub struct InvalidRequestResult {
    pub invalid_descriptor_response: RequestResponse,
    pub invalid_wlength_response: RequestResponse,
    pub invalid_request_response: RequestResponse,
    pub score: f32,
    pub anomalies: Vec<String>,
}

impl InvalidRequestResult {
    pub fn new() -> Self {
        Self {
            invalid_descriptor_response: RequestResponse::Timeout,
            invalid_wlength_response: RequestResponse::Timeout,
            invalid_request_response: RequestResponse::Timeout,
            score: 1.0,
            anomalies: Vec::new(),
        }
    }
}

impl Default for InvalidRequestResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for InvalidRequestResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &self.anomalies
    }
    
    fn evidence(&self) -> Vec<String> {
        vec!["Teste de requisicoes invalidas executado".to_string()]
    }
}

pub struct InvalidRequestAnalyzer;

impl InvalidRequestAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<InvalidRequestResult, LayerError> {
        let mut result = InvalidRequestResult::new();
        
        if let Ok(handle) = device.open() {
            result.invalid_descriptor_response = self.test_invalid_descriptor_type(&handle);
            result.invalid_wlength_response = self.test_invalid_wlength(&handle);
            result.invalid_request_response = self.test_invalid_request_code(&handle);
            
            if result.invalid_descriptor_response == RequestResponse::ValidData {
                result.anomalies.push("Dados validos retornados para tipo de descritor invalido".to_string());
                result.score *= 0.7;
            }
        }
        
        Ok(result)
    }
    
    fn test_invalid_descriptor_type(&self, handle: &rusb::DeviceHandle<Context>) -> RequestResponse {
        let request_type = 0x80;
        let request = 0x06;
        let value = 0xFF00;
        let timeout = Duration::from_millis(500);
        
        let mut buffer = [0u8; 64];
        match handle.read_control(request_type, request, value, 0, &mut buffer, timeout) {
            Ok(n) if n > 0 => RequestResponse::ValidData,
            Err(rusb::Error::Pipe) => RequestResponse::Stall,
            Err(rusb::Error::Timeout) => RequestResponse::Timeout,
            Err(rusb::Error::NoDevice) => RequestResponse::DeviceDisconnect,
            _ => RequestResponse::UnexpectedAck,
        }
    }
    
    fn test_invalid_wlength(&self, handle: &rusb::DeviceHandle<Context>) -> RequestResponse {
        let request_type = 0x80;
        let request = 0x06;
        let value = 0x0100;
        let timeout = Duration::from_millis(500);
        
        let mut buffer = vec![0u8; 10000];
        match handle.read_control(request_type, request, value, 0, &mut buffer, timeout) {
            Ok(_) => RequestResponse::ValidData,
            Err(rusb::Error::Pipe) => RequestResponse::Stall,
            Err(rusb::Error::Timeout) => RequestResponse::Timeout,
            _ => RequestResponse::UnexpectedAck,
        }
    }
    
    fn test_invalid_request_code(&self, handle: &rusb::DeviceHandle<Context>) -> RequestResponse {
        let request_type = 0x80;
        let request = 0xFF;
        let timeout = Duration::from_millis(500);
        
        let mut buffer = [0u8; 64];
        match handle.read_control(request_type, request, 0, 0, &mut buffer, timeout) {
            Ok(n) if n > 0 => RequestResponse::ValidData,
            Err(rusb::Error::Pipe) => RequestResponse::Stall,
            Err(rusb::Error::Timeout) => RequestResponse::Timeout,
            _ => RequestResponse::UnexpectedAck,
        }
    }
}

impl Default for InvalidRequestAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
