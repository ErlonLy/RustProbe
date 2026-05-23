use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

/// Assinatura persistente de um dispositivo USB
/// Combina múltiplos fatores para criar uma identificação única
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSignature {
    /// Hash SHA-256 da assinatura completa
    pub signature_hash: String,
    
    /// VID:PID do dispositivo
    pub vid_pid: String,
    
    /// Hash do fingerprint estrutural
    pub structural_hash: String,
    
    /// Hash do fingerprint HID (se disponível)
    pub hid_hash: Option<String>,
    
    /// Número de série (se disponível)
    pub serial_number: Option<String>,
    
    /// Fabricante
    pub manufacturer: Option<String>,
    
    /// Produto
    pub product: Option<String>,
    
    /// Timestamp da primeira detecção
    pub first_seen: u64,
    
    /// Timestamp da última detecção
    pub last_seen: u64,
    
    /// Contador de vezes que foi visto
    pub seen_count: u32,
    
    /// Nível de confiança histórico médio
    pub avg_confidence: f32,
    
    /// Stack USB detectada
    pub detected_stack: Option<String>,
}

impl DeviceSignature {
    pub fn new(
        vid: u16,
        pid: u16,
        structural_hash: &[u8],
        hid_hash: Option<&[u8]>,
        serial_number: Option<String>,
        manufacturer: Option<String>,
        product: Option<String>,
        detected_stack: Option<String>,
        confidence: f32,
    ) -> Self {
        let vid_pid = format!("{:04X}:{:04X}", vid, pid);
        let structural_hash_str = hex_encode(structural_hash);
        let hid_hash_str = hid_hash.map(hex_encode);
        
        // Criar hash da assinatura completa
        let signature_hash = Self::calculate_signature_hash(
            &vid_pid,
            &structural_hash_str,
            hid_hash_str.as_deref(),
            serial_number.as_deref(),
        );
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            signature_hash,
            vid_pid,
            structural_hash: structural_hash_str,
            hid_hash: hid_hash_str,
            serial_number,
            manufacturer,
            product,
            first_seen: now,
            last_seen: now,
            seen_count: 1,
            avg_confidence: confidence,
            detected_stack,
        }
    }
    
    fn calculate_signature_hash(
        vid_pid: &str,
        structural_hash: &str,
        hid_hash: Option<&str>,
        serial_number: Option<&str>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(vid_pid.as_bytes());
        hasher.update(structural_hash.as_bytes());
        
        if let Some(hid) = hid_hash {
            hasher.update(hid.as_bytes());
        }
        
        if let Some(serial) = serial_number {
            hasher.update(serial.as_bytes());
        }
        
        hex_encode(&hasher.finalize())
    }
    
    pub fn update(&mut self, confidence: f32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.last_seen = now;
        self.seen_count += 1;
        
        // Atualizar média de confiança
        self.avg_confidence = (self.avg_confidence * (self.seen_count - 1) as f32 + confidence) 
            / self.seen_count as f32;
    }
    
    pub fn matches(
        &self,
        vid: u16,
        pid: u16,
        structural_hash: &[u8],
        hid_hash: Option<&[u8]>,
        serial_number: Option<&str>,
    ) -> bool {
        let vid_pid = format!("{:04X}:{:04X}", vid, pid);
        
        if self.vid_pid != vid_pid {
            return false;
        }
        
        let structural_hash_str = hex_encode(structural_hash);
        if self.structural_hash != structural_hash_str {
            return false;
        }
        
        // Se temos HID hash, deve corresponder
        if let (Some(stored_hid), Some(device_hid)) = (&self.hid_hash, hid_hash) {
            let device_hid_str = hex_encode(device_hid);
            if stored_hid != &device_hid_str {
                return false;
            }
        }
        
        // Se temos número de série, deve corresponder
        if let (Some(stored_serial), Some(device_serial)) = (&self.serial_number, serial_number) {
            if stored_serial != device_serial {
                return false;
            }
        }
        
        true
    }
    
    pub fn is_trusted(&self) -> bool {
        // Dispositivo é confiável se:
        // 1. Foi visto múltiplas vezes
        // 2. Tem confiança média alta
        self.seen_count >= 3 && self.avg_confidence >= 0.85
    }
    
    pub fn days_since_first_seen(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        (now - self.first_seen) / 86400 // segundos em um dia
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_device_signature_creation() {
        let structural = vec![0x01, 0x02, 0x03, 0x04];
        let sig = DeviceSignature::new(
            0x046D,
            0xC08B,
            &structural,
            None,
            Some("12345".to_string()),
            Some("Logitech".to_string()),
            Some("G502".to_string()),
            Some("TinyUSB".to_string()),
            0.95,
        );
        
        assert_eq!(sig.vid_pid, "046D:C08B");
        assert_eq!(sig.seen_count, 1);
        assert_eq!(sig.avg_confidence, 0.95);
    }
    
    #[test]
    fn test_device_signature_matching() {
        let structural = vec![0x01, 0x02, 0x03, 0x04];
        let sig = DeviceSignature::new(
            0x046D,
            0xC08B,
            &structural,
            None,
            Some("12345".to_string()),
            Some("Logitech".to_string()),
            Some("G502".to_string()),
            None,
            0.95,
        );
        
        assert!(sig.matches(0x046D, 0xC08B, &structural, None, Some("12345")));
        assert!(!sig.matches(0x046D, 0xC08C, &structural, None, Some("12345")));
    }
    
    #[test]
    fn test_device_signature_update() {
        let structural = vec![0x01, 0x02, 0x03, 0x04];
        let mut sig = DeviceSignature::new(
            0x046D,
            0xC08B,
            &structural,
            None,
            None,
            None,
            None,
            None,
            0.90,
        );
        
        sig.update(1.0);
        
        assert_eq!(sig.seen_count, 2);
        assert_eq!(sig.avg_confidence, 0.95);
    }
}
