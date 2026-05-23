use crate::core::DeviceSignature;
use std::collections::HashMap;
use std::path::Path;
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use log::{info, warn, error};

pub struct SignatureDatabase {
    signatures: HashMap<String, DeviceSignature>,
    database_path: String,
    dirty: bool,
}

impl SignatureDatabase {
    pub fn new(database_path: &str) -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
            database_path: database_path.to_string(),
            dirty: false,
        };
        
        if let Err(e) = db.load() {
            warn!("Falha ao carregar banco de assinaturas: {}. Criando novo banco.", e);
        }
        
        db
    }
    
    pub fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new(&self.database_path);
        
        if !path.exists() {
            info!("Banco de assinaturas não encontrado. Será criado ao salvar.");
            return Ok(());
        }
        
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        let signatures: Vec<DeviceSignature> = serde_json::from_str(&contents)?;
        
        for sig in signatures {
            self.signatures.insert(sig.signature_hash.clone(), sig);
        }
        
        info!("Carregadas {} assinaturas do banco de dados", self.signatures.len());
        Ok(())
    }
    
    pub fn save(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.dirty {
            return Ok(());
        }
        
        let path = Path::new(&self.database_path);
        
        // Criar diretório se não existir
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        
        let signatures: Vec<&DeviceSignature> = self.signatures.values().collect();
        let json = serde_json::to_string_pretty(&signatures)?;
        
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        
        self.dirty = false;
        info!("Salvas {} assinaturas no banco de dados", self.signatures.len());
        Ok(())
    }
    
    pub fn find_or_create(
        &mut self,
        vid: u16,
        pid: u16,
        structural_hash: &[u8],
        hid_hash: Option<&[u8]>,
        serial_number: Option<String>,
        manufacturer: Option<String>,
        product: Option<String>,
        detected_stack: Option<String>,
        confidence: f32,
    ) -> String {
        // Procurar assinatura existente
        for sig in self.signatures.values_mut() {
            if sig.matches(vid, pid, structural_hash, hid_hash, serial_number.as_deref()) {
                sig.update(confidence);
                self.dirty = true;
                return format!("{} {} (VID:0x{:04X} PID:0x{:04X})", 
                    sig.manufacturer.as_deref().unwrap_or("Unknown"),
                    sig.product.as_deref().unwrap_or("Device"),
                    vid, pid);
            }
        }
        
        // Criar nova assinatura
        let new_sig = DeviceSignature::new(
            vid,
            pid,
            structural_hash,
            hid_hash,
            serial_number.clone(),
            manufacturer.clone(),
            product.clone(),
            detected_stack,
            confidence,
        );
        
        let hash = new_sig.signature_hash.clone();
        let result = format!("{} {} (VID:0x{:04X} PID:0x{:04X})", 
            manufacturer.as_deref().unwrap_or("Unknown"),
            product.as_deref().unwrap_or("Device"),
            vid, pid);
        
        self.signatures.insert(hash, new_sig);
        self.dirty = true;
        
        result
    }
    
    pub fn get_signature_info(
        &self,
        vid: u16,
        pid: u16,
        structural_hash: &[u8],
        hid_hash: Option<&[u8]>,
        serial_number: Option<&str>,
    ) -> (bool, u32) {
        if let Some(sig) = self.get_signature(vid, pid, structural_hash, hid_hash, serial_number) {
            (sig.seen_count > 1, sig.seen_count)
        } else {
            (false, 0)
        }
    }
    
    pub fn get_signature(
        &self,
        vid: u16,
        pid: u16,
        structural_hash: &[u8],
        hid_hash: Option<&[u8]>,
        serial_number: Option<&str>,
    ) -> Option<&DeviceSignature> {
        self.signatures.values().find(|sig| {
            sig.matches(vid, pid, structural_hash, hid_hash, serial_number)
        })
    }
    
    pub fn get_all_signatures(&self) -> Vec<&DeviceSignature> {
        self.signatures.values().collect()
    }
    
    pub fn count(&self) -> usize {
        self.signatures.len()
    }
    
    pub fn cleanup_old_signatures(&mut self, days: u64) {
        let before_count = self.signatures.len();
        
        self.signatures.retain(|_, sig| {
            sig.days_since_first_seen() <= days
        });
        
        let removed = before_count - self.signatures.len();
        if removed > 0 {
            info!("Removidas {} assinaturas antigas (>{} dias)", removed, days);
            self.dirty = true;
        }
    }
}

impl Drop for SignatureDatabase {
    fn drop(&mut self) {
        if let Err(e) = self.save() {
            error!("Falha ao salvar banco de assinaturas: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;
    
    #[test]
    fn test_signature_database() {
        let db_path = "test_signatures.json";
        let mut db = SignatureDatabase::new(db_path);
        
        let structural = vec![0x01, 0x02, 0x03, 0x04];
        
        let sig1 = db.find_or_create(
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
        
        assert_eq!(sig1.seen_count, 1);
        
        let sig2 = db.find_or_create(
            0x046D,
            0xC08B,
            &structural,
            None,
            Some("12345".to_string()),
            Some("Logitech".to_string()),
            Some("G502".to_string()),
            None,
            1.0,
        );
        
        assert_eq!(sig2.seen_count, 2);
        assert_eq!(db.count(), 1);
        
        db.save().unwrap();
        
        // Cleanup
        let _ = remove_file(db_path);
    }
}
