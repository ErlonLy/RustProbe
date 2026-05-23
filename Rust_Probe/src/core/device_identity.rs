/// Device Identity Analysis - Claim vs Reality Engine
/// 
/// This module implements reverse fingerprinting to infer the TRUE origin
/// of a USB device, even when compile-time flags are used to spoof identity.

use serde::{Deserialize, Serialize};

/// Claimed identity (what the device says it is)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedIdentity {
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
}

/// Observed behavior (what the device actually does)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedBehavior {
    // Topology fingerprint
    pub num_interfaces: u8,
    pub num_endpoints: usize,
    pub endpoint_addresses: Vec<u8>,
    pub endpoint_packet_sizes: Vec<u16>,
    pub endpoint_intervals: Vec<u8>,
    
    // HID fingerprint
    pub hid_report_descriptor_hash: Option<Vec<u8>>,
    pub hid_report_descriptor_size: Option<usize>,
    pub hid_usage_page: Option<u16>,
    pub hid_usage: Option<u16>,
    pub hid_polling_interval: Option<u8>,
    
    // Stack signature
    pub detected_stack: Option<String>,
    pub stack_confidence: f32,
    
    // Timing signature
    pub enumeration_timing_us: u64,
    pub descriptor_read_jitter_us: u64,
    pub control_response_avg_us: u64,
    
    // Structural anomalies
    pub has_cdc_remnants: bool,
    pub has_interface_gaps: bool,
    pub has_endpoint_gaps: bool,
    pub descriptor_ordering_anomaly: bool,
}

/// Inferred origin (what we think it really is)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredOrigin {
    pub candidates: Vec<OriginCandidate>,
    pub confidence: f32,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginCandidate {
    pub name: String,
    pub probability: f32,
    pub evidence: Vec<String>,
}

/// Identity mismatch analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMismatch {
    pub has_mismatch: bool,
    pub severity: MismatchSeverity,
    pub mismatches: Vec<MismatchDetail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchSeverity {
    None,
    Minor,      // Small inconsistencies
    Moderate,   // Clear differences but could be variant
    Major,      // Strong evidence of spoofing
    Critical,   // Impossible combination - definite spoof
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchDetail {
    pub category: String,
    pub claimed: String,
    pub observed: String,
    pub impact: f32,
}

/// Complete identity analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAnalysis {
    pub claimed: ClaimedIdentity,
    pub observed: ObservedBehavior,
    pub inferred: InferredOrigin,
    pub mismatch: IdentityMismatch,
    pub identity_score: f32,
    pub is_spoofed: bool,
}

impl IdentityAnalysis {
    pub fn new(claimed: ClaimedIdentity, observed: ObservedBehavior) -> Self {
        Self {
            claimed,
            observed,
            inferred: InferredOrigin {
                candidates: Vec::new(),
                confidence: 0.0,
                reasoning: Vec::new(),
            },
            mismatch: IdentityMismatch {
                has_mismatch: false,
                severity: MismatchSeverity::None,
                mismatches: Vec::new(),
            },
            identity_score: 1.0,
            is_spoofed: false,
        }
    }
}
