use rusb::{Device, Context};
use sha2::{Sha256, Digest};
use crate::core::{LayerResult, LayerError, TopologyData, TransferType, Direction};

#[derive(Debug, Clone)]
pub struct StructuralResult {
    pub fingerprint_hash: [u8; 32],
    pub matched_profile: Option<String>,
    pub similarity: f32,
    pub score: f32,
    pub topology: TopologyData,
}

impl StructuralResult {
    pub fn new() -> Self {
        Self {
            fingerprint_hash: [0u8; 32],
            matched_profile: None,
            similarity: 0.0,
            score: 0.0,
            topology: TopologyData::new(),
        }
    }
}

impl Default for StructuralResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerResult for StructuralResult {
    fn score(&self) -> f32 {
        self.score
    }
    
    fn anomalies(&self) -> &[String] {
        &[]
    }
    
    fn evidence(&self) -> Vec<String> {
        let mut evidence = Vec::new();
        let hash_str = self.fingerprint_hash.iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        evidence.push(format!("Fingerprint estrutural: {}...", hash_str));
        evidence.push(format!("Interfaces: {}", self.topology.num_interfaces));
        evidence.push(format!("Endpoints: {}", self.topology.endpoint_addresses.len()));
        if let Some(ref profile) = self.matched_profile {
            evidence.push(format!("Perfil correspondente: {} ({:.1}%)", profile, self.similarity * 100.0));
        }
        evidence
    }
}

pub struct StructuralFingerprintAnalyzer;

impl StructuralFingerprintAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, device: &Device<Context>) -> Result<StructuralResult, LayerError> {
        let config_desc = device.active_config_descriptor()
            .map_err(|e| LayerError::Critical(format!("Falha ao ler descritor de configuracao: {}", e)))?;
        
        let topology = self.extract_topology(&config_desc)?;
        let hash = self.generate_fingerprint(&topology);
        
        Ok(StructuralResult {
            fingerprint_hash: hash,
            matched_profile: None,
            similarity: 0.0,
            score: 1.0,
            topology,
        })
    }
    
    fn extract_topology(&self, config_desc: &rusb::ConfigDescriptor) -> Result<TopologyData, LayerError> {
        let mut topology = TopologyData::new();
        topology.num_interfaces = config_desc.num_interfaces();
        
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                topology.interface_classes.push(interface_desc.class_code());
                
                if interface_desc.class_code() == 0x02 {
                    topology.has_iad = true;
                }
                
                for endpoint in interface_desc.endpoint_descriptors() {
                    topology.endpoint_addresses.push(endpoint.address());
                    
                    let transfer_type: TransferType = endpoint.transfer_type().into();
                    topology.endpoint_types.push(transfer_type as u8);
                    
                    let direction: Direction = endpoint.direction().into();
                    topology.endpoint_directions.push(direction as u8);
                    
                    topology.endpoint_max_packet_sizes.push(endpoint.max_packet_size());
                    topology.endpoint_intervals.push(endpoint.interval());
                }
            }
        }
        
        topology.endpoint_addresses.sort();
        
        Ok(topology)
    }
    
    fn generate_fingerprint(&self, topology: &TopologyData) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        
        hasher.update(&[topology.num_interfaces]);
        
        
        for &class in &topology.interface_classes {
            hasher.update(&[class]);
        }
        
        
        for &addr in &topology.endpoint_addresses {
            hasher.update(&[addr]);
        }
        
        
        let endpoint_entropy = self.calculate_endpoint_entropy(&topology.endpoint_addresses);
        hasher.update(&endpoint_entropy.to_le_bytes());
        
        
        for &ep_type in &topology.endpoint_types {
            hasher.update(&[ep_type]);
        }
        
        
        for &dir in &topology.endpoint_directions {
            hasher.update(&[dir]);
        }
        
        
        for &size in &topology.endpoint_max_packet_sizes {
            hasher.update(&size.to_le_bytes());
        }
        
        
        for &interval in &topology.endpoint_intervals {
            hasher.update(&[interval]);
        }
        
        
        hasher.update(&[if topology.has_iad { 1 } else { 0 }]);
        
        
        if !topology.cdc_functional_descriptors.is_empty() {
            hasher.update(&[topology.cdc_functional_descriptors.len() as u8]);
            hasher.update(&topology.cdc_functional_descriptors);
        }
        
        
        let class_matrix = self.build_class_matrix(topology);
        hasher.update(&class_matrix);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    
    fn calculate_endpoint_entropy(&self, endpoints: &[u8]) -> f32 {
        if endpoints.is_empty() {
            return 0.0;
        }
        
        let mut sorted = endpoints.to_vec();
        sorted.sort();
        
        let mut gaps = 0;
        for i in 1..sorted.len() {
            let diff = sorted[i].saturating_sub(sorted[i-1]);
            if diff > 1 {
                gaps += (diff - 1) as usize;
            }
        }
        
        
        gaps as f32 / endpoints.len() as f32
    }
    
    
    fn build_class_matrix(&self, topology: &TopologyData) -> Vec<u8> {
        let mut matrix = Vec::new();
        
        
        for &class in &topology.interface_classes {
            matrix.push(class);
        }
        
        
        matrix.push(topology.num_interfaces);
        
        
        matrix.push(topology.endpoint_addresses.len() as u8);
        
        matrix
    }
}

impl Default for StructuralFingerprintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
