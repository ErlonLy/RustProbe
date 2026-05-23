# Requirements: Advanced USB Fingerprinting System

## 1. Overview

### 1.1 Purpose
Transform the Rust Probe detection system from a simple VID/PID-based validator into a sophisticated multi-layer USB fingerprinting engine capable of detecting advanced spoofing techniques used in Arduino, ESP32, Teensy, and other development boards that attempt to masquerade as legitimate peripherals.

### 1.2 Problem Statement
Current detection relies heavily on easily-spoofable USB descriptors (VID, PID, Manufacturer String, Product String) that can be modified through:
- Compile flags (PlatformIO, Arduino IDE)
- USB stacks (TinyUSB, LUFA, ESP-IDF, Arduino Core)
- Custom firmware configurations
- Bootloader modifications

**Result**: High false negative rate (spoofed devices passing as legitimate) and false positive rate (legitimate devices flagged incorrectly).

### 1.3 Solution Approach
Implement a 12-layer behavioral and structural fingerprinting architecture that analyzes:
- USB structural topology
- HID report descriptors
- Active USB protocol behavior
- Timing characteristics
- Stack-specific signatures
- Bootloader behavior patterns

### 1.4 Target Devices
**Primary Detection Targets**:
- Arduino boards (Leonardo, Micro, Uno, Mega) with spoofed identities
- ESP32/ESP32-S3 boards emulating HID devices
- Teensy boards with modified descriptors
- Custom USB stacks (LUFA, TinyUSB) attempting to hide

**Legitimate Devices to Whitelist**:
- Gaming peripherals (Logitech, Microsoft, Razer, Corsair)
- USB-Serial adapters (CP2102, FTDI, CH340)
- Composite devices (webcams, audio interfaces)

### 1.5 Focus Areas
- **COM ports** (CDC ACM devices)
- **HID devices** (keyboards, mice, game controllers)
- **Composite devices** (HID + CDC combinations)

---

## 2. Functional Requirements

### FR-1: Multi-Layer Analysis Architecture

#### FR-1.1: Layer 1 - Passive Descriptor Validation
**Priority**: High  
**Description**: Collect all standard USB descriptors but assign reduced confidence weight.

**Acceptance Criteria**:
- [ ] Collect VID, PID, Manufacturer String, Product String, Serial Number
- [ ] Collect USB Version, Device Version, Device Class, Subclass, Protocol
- [ ] Collect all endpoint descriptors (address, type, direction, max packet size, interval)
- [ ] Collect all interface descriptors
- [ ] Collect all configuration descriptors
- [ ] Assign weight: 15% maximum to passive descriptor validation
- [ ] Store raw descriptor data for fingerprint generation

**Correctness Properties**:
```
Property: passive_descriptor_completeness
∀ device d: 
  IF d.is_enumerated THEN
    d.has_vid AND d.has_pid AND 
    d.has_device_descriptor AND
    d.has_config_descriptor
```

---

#### FR-1.2: Layer 2 - Structural USB Fingerprint
**Priority**: Critical  
**Description**: Generate cryptographic hash of USB topology structure independent of descriptor strings.

**Acceptance Criteria**:
- [ ] Generate fingerprint from:
  - Number of interfaces
  - Interface ordering
  - Endpoint addresses (all endpoints)
  - Endpoint transfer types (Control, Bulk, Interrupt, Isochronous)
  - Endpoint directions (IN/OUT)
  - Endpoint max packet sizes
  - Polling intervals (bInterval)
  - Configuration layout
  - Interface Association Descriptors (IAD)
  - CDC Functional Descriptors
- [ ] Create SHA-256 hash of structural signature
- [ ] Compare against known profiles database
- [ ] Assign weight: 25% to structural fingerprint match

**Known Profiles Database**:
- Arduino Leonardo (Caterina bootloader)
- Arduino Leonardo (LUFA default)
- ESP32-S3 (TinyUSB)
- ESP32-S3 (ESP-IDF USB)
- Teensy 3.x/4.x (PJRC stack)
- CP2102 (Silicon Labs)
- CH340 (QinHeng)
- FTDI FT232
- Logitech Unifying Receiver
- Microsoft USB peripherals

**Correctness Properties**:
```
Property: structural_fingerprint_determinism
∀ device d, readings r1 r2:
  IF r1.device = d AND r2.device = d THEN
    r1.structural_hash = r2.structural_hash

Property: structural_fingerprint_uniqueness
∀ stack s1 s2:
  IF s1 ≠ s2 THEN
    P(hash(s1) = hash(s2)) < 0.001  // collision probability
```

---

#### FR-1.3: Layer 3 - HID Report Descriptor Fingerprinting
**Priority**: Critical  
**Description**: Extract and fingerprint complete HID Report Descriptor for HID-capable devices.

**Acceptance Criteria**:
- [ ] Detect HID interface presence
- [ ] Read complete HID Report Descriptor via GET_DESCRIPTOR(HID_REPORT)
- [ ] Generate SHA-256 hash of report descriptor
- [ ] Compare against known HID profiles:
  - Arduino HID Keyboard (LUFA)
  - Arduino HID Mouse (LUFA)
  - TinyUSB HID Keyboard
  - TinyUSB HID Mouse
  - ESP32 TinyUSB HID
  - Teensy HID (PJRC)
  - Logitech HID profiles
  - Microsoft HID profiles
- [ ] Assign weight: 30% to HID descriptor match (highest weight)
- [ ] Flag mismatches between claimed device type and HID descriptor

**Correctness Properties**:
```
Property: hid_descriptor_consistency
∀ device d:
  IF d.claims_keyboard AND d.has_hid THEN
    d.hid_descriptor MUST contain_usage_page(0x01) AND
    d.hid_descriptor MUST contain_usage(0x06)  // Keyboard usage

Property: hid_descriptor_immutability
∀ device d, time t1 t2:
  IF d.connected_at(t1) AND d.connected_at(t2) THEN
    hash(d.hid_descriptor_at(t1)) = hash(d.hid_descriptor_at(t2))
```

---

#### FR-1.4: Layer 4 - Active USB Challenge (CDC ACM)
**Priority**: High  
**Description**: Send valid CDC ACM class requests and analyze behavioral responses.

**Acceptance Criteria**:
- [ ] Detect CDC ACM interface (class 0x02, subclass 0x02)
- [ ] Execute SET_LINE_CODING request with valid parameters
- [ ] Execute GET_LINE_CODING request and verify response
- [ ] Execute SET_CONTROL_LINE_STATE request
- [ ] Measure response timing for each request
- [ ] Verify correct response format
- [ ] Detect anomalies:
  - Timeout (no response)
  - STALL (unsupported request)
  - Incorrect response length
  - Invalid response data
  - Callback not implemented
  - Partial response
- [ ] Assign weight: 15% to CDC behavior validation

**Test Sequences**:
```
Sequence 1: Line Coding Validation
1. GET_LINE_CODING → expect 7 bytes (dwDTERate, bCharFormat, bParityType, bDataBits)
2. SET_LINE_CODING(115200, 8N1) → expect ACK
3. GET_LINE_CODING → verify 115200, 8N1 returned
4. Measure timing consistency

Sequence 2: Control Line State
1. SET_CONTROL_LINE_STATE(DTR=1, RTS=1) → expect ACK
2. SET_CONTROL_LINE_STATE(DTR=0, RTS=0) → expect ACK
3. Verify no device reset or disconnect
```

**Correctness Properties**:
```
Property: cdc_request_compliance
∀ device d:
  IF d.has_cdc_acm THEN
    d.responds_to(SET_LINE_CODING) AND
    d.responds_to(GET_LINE_CODING) AND
    response_time(d) < 100ms

Property: cdc_state_persistence
∀ device d, state s:
  IF d.set_line_coding(s) THEN
    d.get_line_coding() = s
```

---

#### FR-1.5: Layer 5 - Invalid Request Challenge
**Priority**: Medium  
**Description**: Send intentionally malformed USB requests to test error handling robustness.

**Acceptance Criteria**:
- [ ] Send invalid descriptor type requests (e.g., type 0xFF)
- [ ] Send requests with invalid wLength values
- [ ] Send invalid request combinations
- [ ] Send malformed control transfers
- [ ] Analyze responses:
  - Correct STALL response
  - Timeout behavior
  - Unexpected device reset
  - Device disconnect
  - Inconsistent behavior
- [ ] Compare behavior against known hardware profiles
- [ ] Assign weight: 5% to error handling validation

**Test Cases**:
```
Test 1: Invalid Descriptor Type
Request: GET_DESCRIPTOR(type=0xFF, index=0, length=64)
Expected: STALL or timeout
Suspicious: Valid data returned

Test 2: Invalid wLength
Request: GET_DESCRIPTOR(DEVICE, length=1000)
Expected: STALL or return only 18 bytes
Suspicious: Buffer overflow, crash, disconnect

Test 3: Invalid Request Code
Request: bRequest=0xFF, wValue=0, wIndex=0, wLength=0
Expected: STALL
Suspicious: ACK, data returned
```

**Correctness Properties**:
```
Property: error_handling_robustness
∀ device d, invalid_request r:
  IF r.is_invalid THEN
    d.response(r) ∈ {STALL, TIMEOUT} AND
    d.remains_connected

Property: error_handling_consistency
∀ device d, invalid_request r, trials t1 t2:
  d.response(r, t1) = d.response(r, t2)
```

---

#### FR-1.6: Layer 6 - Timing Fingerprinting
**Priority**: High  
**Description**: Measure and analyze timing characteristics across multiple operations.

**Acceptance Criteria**:
- [ ] Measure enumeration latency (device detection to ready)
- [ ] Measure descriptor read latency (per descriptor type)
- [ ] Measure control transfer latency (setup, data, status phases)
- [ ] Measure repeated read variance (100 consecutive reads)
- [ ] Measure burst response stability (rapid sequential requests)
- [ ] Measure endpoint throughput stability
- [ ] Calculate statistics:
  - Mean (μ)
  - Standard deviation (σ)
  - Jitter (max - min)
  - Variance score (σ²)
- [ ] Compare against known hardware timing profiles
- [ ] Assign weight: 10% to timing consistency

**Timing Profiles**:
- Real hardware: Low variance (σ < 5ms)
- Emulated devices: High variance (σ > 20ms)
- Proxied devices: Inconsistent jitter
- Software stacks: Burst instability

**Correctness Properties**:
```
Property: timing_consistency_real_hardware
∀ device d:
  IF d.is_real_hardware THEN
    std_dev(d.response_times) < 5ms

Property: timing_variance_emulation
∀ device d:
  IF d.is_emulated THEN
    std_dev(d.response_times) > 20ms
```

---

#### FR-1.7: Layer 7 - Repeated Descriptor Consistency
**Priority**: Medium  
**Description**: Verify descriptor determinism through repeated reads.

**Acceptance Criteria**:
- [ ] Read same descriptor 100 consecutive times
- [ ] Verify identical size for all reads
- [ ] Verify identical content (byte-by-byte)
- [ ] Verify identical ordering
- [ ] Measure timing consistency across reads
- [ ] Generate checksum (CRC32) for each read
- [ ] Compare all checksums for equality
- [ ] Flag any inconsistencies as suspicious
- [ ] Assign weight: 5% to descriptor consistency

**Correctness Properties**:
```
Property: descriptor_determinism
∀ device d, descriptor_type t, reads r[1..100]:
  ∀ i,j ∈ [1..100]:
    checksum(r[i]) = checksum(r[j])

Property: descriptor_stability
∀ device d, time_span Δt:
  IF Δt < 1_minute THEN
    descriptor(d, t0) = descriptor(d, t0 + Δt)
```

---

#### FR-1.8: Layer 8 - Bootloader Verification
**Priority**: Medium  
**Description**: Validate bootloader behavior for devices claiming to be known boards.

**Acceptance Criteria**:
- [ ] Detect devices claiming Arduino Leonardo identity
- [ ] Execute Caterina bootloader validation:
  - Open serial port at 1200 baud
  - Close port immediately
  - Monitor for device reset
  - Verify re-enumeration with bootloader VID/PID
  - Measure timing profile (reset → re-enum)
- [ ] Detect devices claiming Teensy identity
- [ ] Execute Teensy HID bootloader validation
- [ ] Compare behavior against known bootloader profiles
- [ ] Assign weight: 10% to bootloader validation

**Bootloader Profiles**:
```
Arduino Leonardo (Caterina):
- Normal mode: VID=0x2341, PID=0x8036
- 1200 baud reset trigger
- Bootloader mode: VID=0x2341, PID=0x0036
- Re-enumeration time: 750ms ± 100ms

Teensy 3.x/4.x:
- Normal mode: VID=0x16C0, PID=0x0486
- HID bootloader trigger
- Bootloader mode: VID=0x16C0, PID=0x0478
```

**Correctness Properties**:
```
Property: bootloader_transition_genuine
∀ device d:
  IF d.claims_leonardo AND d.is_genuine THEN
    trigger_1200_baud(d) →
      d.disconnects AND
      d.reenumerates_as_bootloader AND
      timing(d.reset_to_renum) ∈ [650ms, 850ms]

Property: bootloader_transition_spoofed
∀ device d:
  IF d.claims_leonardo AND d.is_spoofed THEN
    trigger_1200_baud(d) →
      (d.no_response OR d.crashes OR timing(d) ∉ [650ms, 850ms])
```

---

#### FR-1.9: Layer 9 - Stack Fingerprinting
**Priority**: High  
**Description**: Identify probable USB firmware stack independent of VID/PID.

**Acceptance Criteria**:
- [ ] Analyze descriptor ordering patterns
- [ ] Analyze callback behavior patterns
- [ ] Analyze endpoint structure patterns
- [ ] Analyze timing profiles
- [ ] Detect CDC-specific quirks
- [ ] Detect HID descriptor style
- [ ] Classify probable stack:
  - LUFA (Lightweight USB Framework for AVRs)
  - TinyUSB (cross-platform USB stack)
  - ESP-IDF USB (Espressif)
  - Arduino AVR Core
  - STM32Cube USB
  - Zephyr USB
  - PJRC/Teensy stack
- [ ] Assign weight: 15% to stack identification

**Stack Signatures**:
```
LUFA:
- Descriptor ordering: Config → Interface → Endpoint
- CDC functional descriptors: Header → ACM → Union → Call Management
- Endpoint addresses: Sequential (0x81, 0x82, 0x03, 0x04)
- Timing: Fast enumeration (<200ms)

TinyUSB:
- Descriptor ordering: Config → IAD → Interface → Endpoint
- CDC functional descriptors: Header → Call Management → ACM → Union
- Endpoint addresses: Grouped by interface (0x81, 0x01, 0x82)
- Timing: Medium enumeration (200-400ms)

ESP-IDF USB:
- Descriptor ordering: Config → Interface → Endpoint → IAD
- CDC functional descriptors: Non-standard ordering
- Endpoint addresses: Non-sequential (0x81, 0x02, 0x83)
- Timing: Slow enumeration (>400ms)
```

**Correctness Properties**:
```
Property: stack_signature_uniqueness
∀ stack s1 s2:
  IF s1 ≠ s2 THEN
    signature(s1) ≠ signature(s2)

Property: stack_detection_accuracy
∀ device d:
  IF d.uses_stack(s) THEN
    P(detect_stack(d) = s) > 0.90
```

---

#### FR-1.10: Layer 10 - Protocol Probe
**Priority**: Medium  
**Description**: Execute ecosystem-specific protocol probes beyond USB descriptors.

**Acceptance Criteria**:
- [ ] Arduino protocol probes:
  - STK500 sync patterns (0x30 0x20)
  - Caterina signatures
  - AVR109 probe sequences
- [ ] ESP protocol probes:
  - ROM bootloader sync patterns (0xC0 0x00 ...)
  - ESP-IDF specific responses
- [ ] Teensy protocol probes:
  - HID bootloader behavior
  - Teensy-specific HID reports
- [ ] Measure response to each probe
- [ ] Classify device based on protocol responses
- [ ] Assign weight: 5% to protocol validation

**Correctness Properties**:
```
Property: protocol_response_genuine
∀ device d, protocol p:
  IF d.is_genuine(p) THEN
    d.responds_correctly_to(p.probe_sequence)

Property: protocol_response_spoofed
∀ device d, protocol p:
  IF d.is_spoofed(p) THEN
    (d.no_response(p) OR d.incorrect_response(p))
```

---

### FR-2: Confidence Scoring Engine

#### FR-2.1: Weighted Score Calculation
**Priority**: Critical  
**Description**: Replace binary trust levels with weighted multi-factor confidence scoring.

**Acceptance Criteria**:
- [ ] Implement weighted scoring system:
  - **Passive Score** (15%): VID/PID/strings/descriptors
  - **Structural Score** (25%): Endpoint layout, interface topology
  - **HID Score** (30%): HID descriptor fingerprint (if applicable)
  - **Active Score** (15%): CDC behavior, control requests, timing
  - **Stack Score** (10%): Probable firmware stack identification
  - **Protocol Score** (5%): Bootloader/protocol probes
- [ ] Calculate final confidence: 0.0 to 1.0 (0% to 100%)
- [ ] Classify trust level based on confidence:
  - **Genuine**: confidence ≥ 0.85
  - **Board Modified**: 0.60 ≤ confidence < 0.85
  - **VID/PID Spoofed**: 0.30 ≤ confidence < 0.60
  - **Deep Modification**: 0.10 ≤ confidence < 0.30
  - **Unknown**: confidence < 0.10

**Scoring Formula**:
```
confidence = 
  (passive_score × 0.15) +
  (structural_score × 0.25) +
  (hid_score × 0.30) +        // if HID present, else redistribute
  (active_score × 0.15) +
  (stack_score × 0.10) +
  (protocol_score × 0.05)

where each score ∈ [0.0, 1.0]
```

**Correctness Properties**:
```
Property: confidence_bounds
∀ device d:
  0.0 ≤ confidence(d) ≤ 1.0

Property: confidence_monotonicity
∀ device d, evidence e:
  IF e.supports_genuine(d) THEN
    confidence(d + e) ≥ confidence(d)

Property: trust_level_consistency
∀ device d:
  IF confidence(d) ≥ 0.85 THEN
    trust_level(d) = Genuine
```

---

#### FR-2.2: False Positive Reduction
**Priority**: Critical  
**Description**: Implement behavioral whitelist to prevent legitimate devices from being flagged.

**Acceptance Criteria**:
- [ ] Create behavioral whitelist profiles:
  - Logitech peripherals (structural + HID fingerprints)
  - Microsoft peripherals (structural + HID fingerprints)
  - Corsair peripherals (structural + HID fingerprints)
  - Razer peripherals (structural + HID fingerprints)
  - CP2102 USB-Serial (structural fingerprint)
  - FTDI USB-Serial (structural fingerprint)
  - CH340 USB-Serial (structural fingerprint)
  - Legitimate composite devices (webcams, audio interfaces)
- [ ] Do NOT flag devices solely for HID + CDC coexistence
- [ ] Require combination of multiple anomalies:
  - Structural fingerprint mismatch
  - Active challenge failure
  - Timing anomaly
  - Stack inference mismatch
- [ ] Minimum 3 anomalies required for "Spoofed" classification
- [ ] Whitelist match overrides anomaly detection

**Correctness Properties**:
```
Property: whitelist_protection
∀ device d:
  IF d.matches_whitelist_profile THEN
    trust_level(d) ≠ VidPidSpoofed

Property: multi_factor_requirement
∀ device d:
  IF trust_level(d) = VidPidSpoofed THEN
    count(d.anomalies) ≥ 3

Property: false_positive_rate
∀ legitimate_devices D:
  P(flagged_as_spoofed | legitimate) < 0.05  // <5% FPR
```

---

### FR-3: Reporting and Visualization

#### FR-3.1: Detailed Analysis Report
**Priority**: High  
**Description**: Generate comprehensive report showing all layer results.

**Acceptance Criteria**:
- [ ] Display passive descriptor data
- [ ] Display structural fingerprint hash
- [ ] Display HID descriptor hash (if applicable)
- [ ] Display active challenge results (pass/fail per request)
- [ ] Display timing statistics (mean, σ, jitter)
- [ ] Display descriptor consistency results
- [ ] Display bootloader validation results (if applicable)
- [ ] Display detected USB stack
- [ ] Display protocol probe results
- [ ] Display per-layer scores
- [ ] Display final confidence score
- [ ] Display trust level classification
- [ ] Color-code results (green/yellow/red)

---

#### FR-3.2: Comparison Mode
**Priority**: Medium  
**Description**: Allow comparison of device fingerprint against known profiles.

**Acceptance Criteria**:
- [ ] Display matched profile name (if any)
- [ ] Display similarity percentage
- [ ] Highlight differences between device and profile
- [ ] Show which layers matched vs. mismatched

---

## 3. Non-Functional Requirements

### NFR-1: Performance
- [ ] Complete analysis of single device: < 5 seconds
- [ ] Structural fingerprint generation: < 100ms
- [ ] HID descriptor read: < 200ms
- [ ] Active challenge sequence: < 1 second
- [ ] Timing analysis (100 reads): < 2 seconds

### NFR-2: Reliability
- [ ] Handle device disconnection gracefully
- [ ] Handle timeout scenarios without crashing
- [ ] Recover from STALL conditions
- [ ] No memory leaks during repeated analysis

### NFR-3: Accuracy
- [ ] True positive rate (genuine devices): > 95%
- [ ] True negative rate (spoofed devices): > 90%
- [ ] False positive rate (legitimate flagged): < 5%
- [ ] False negative rate (spoofed passing): < 10%

### NFR-4: Maintainability
- [ ] Modular layer architecture (each layer independent)
- [ ] Easy to add new fingerprint profiles
- [ ] Easy to update whitelist
- [ ] Comprehensive logging for debugging

### NFR-5: Portability
- [ ] Windows support (libusb/WinUSB)
- [ ] Linux support (libusb)
- [ ] macOS support (libusb)

---

## 4. User Stories

### US-1: Security Analyst Detecting Spoofed Arduino
**As a** security analyst  
**I want to** detect Arduino boards with spoofed VID/PID attempting to hide as legitimate peripherals  
**So that** I can identify potential security threats in my environment

**Acceptance Criteria**:
- Device with spoofed Logitech VID/PID but Arduino LUFA stack is detected
- Confidence score < 0.60 (VID/PID Spoofed)
- Report shows structural fingerprint mismatch
- Report shows HID descriptor mismatch
- Report shows detected stack: LUFA

---

### US-2: Anti-Cheat System Blocking Modified Devices
**As an** anti-cheat system  
**I want to** block devices with modified bootloaders or firmware stacks  
**So that** I can prevent cheating via hardware-based input manipulation

**Acceptance Criteria**:
- Device claiming Arduino Leonardo identity fails bootloader validation
- Confidence score < 0.30 (Deep Modification)
- Report shows bootloader transition failure
- Report shows timing profile mismatch

---

### US-3: IT Administrator Whitelisting Legitimate Devices
**As an** IT administrator  
**I want to** ensure legitimate gaming peripherals are not flagged  
**So that** users can work without false alarms

**Acceptance Criteria**:
- Logitech mouse passes all checks
- Confidence score > 0.85 (Genuine)
- Structural fingerprint matches Logitech profile
- HID descriptor matches Logitech profile
- No false positive flags

---

### US-4: Researcher Analyzing USB Stack Behavior
**As a** security researcher  
**I want to** identify which USB firmware stack a device is using  
**So that** I can understand its implementation and potential vulnerabilities

**Acceptance Criteria**:
- Device analyzed across all 12 layers
- Stack fingerprinting identifies: TinyUSB
- Report shows stack-specific signatures detected
- Confidence in stack detection: > 90%

---

## 5. Constraints

### Technical Constraints
- Must use `rusb` library for USB communication
- Must work with libusb 1.0 backend
- Must handle devices that don't support all requests gracefully
- Cannot perform destructive operations on devices

### Regulatory Constraints
- Must not violate USB specification
- Must not damage connected devices
- Must respect device access permissions

### Time Constraints
- Analysis must complete within reasonable time (< 5 seconds per device)
- Must not block system USB operations

---

## 6. Assumptions

1. User has appropriate USB device access permissions
2. libusb drivers are correctly installed
3. Devices remain connected during analysis
4. USB bus is not saturated with other traffic
5. Known fingerprint profiles database is maintained and updated

---

## 7. Dependencies

### External Dependencies
- `rusb` crate (USB communication)
- `sha2` crate (SHA-256 hashing)
- `serde` crate (serialization)
- `colored` crate (terminal output)

### Internal Dependencies
- Fingerprint profiles database (JSON/binary format)
- Whitelist profiles database
- Stack signature database

---

## 8. Success Metrics

### Detection Accuracy
- [ ] Detect 95% of spoofed Arduino devices
- [ ] Detect 90% of spoofed ESP32 devices
- [ ] Detect 85% of modified Teensy devices
- [ ] False positive rate < 5% on legitimate peripherals

### Performance
- [ ] Average analysis time < 3 seconds
- [ ] Support 10+ devices simultaneously
- [ ] Memory usage < 100MB per device

### User Satisfaction
- [ ] Clear, actionable reports
- [ ] Easy to understand confidence scores
- [ ] Minimal false alarms

---

## 9. Out of Scope

The following are explicitly **not** included in this specification:

- Real-time monitoring of USB traffic
- Packet-level USB protocol analysis
- Firmware extraction or reverse engineering
- Automated device blocking or quarantine
- GUI interface (CLI only)
- Network-based device analysis
- Bluetooth device analysis
- Thunderbolt device analysis

---

## 10. Future Enhancements

Potential future additions (not in current scope):

- Machine learning-based anomaly detection
- Cloud-based fingerprint database
- Real-time monitoring daemon
- Integration with EDR/XDR systems
- Automated threat intelligence sharing
- GUI dashboard
- Mobile device support (Android/iOS)

---

## 11. Glossary

- **CDC ACM**: Communication Device Class - Abstract Control Model
- **HID**: Human Interface Device
- **VID**: Vendor ID (16-bit USB identifier)
- **PID**: Product ID (16-bit USB identifier)
- **LUFA**: Lightweight USB Framework for AVRs
- **TinyUSB**: Cross-platform USB device stack
- **ESP-IDF**: Espressif IoT Development Framework
- **Caterina**: Arduino Leonardo bootloader
- **STALL**: USB error condition indicating unsupported request
- **IAD**: Interface Association Descriptor
- **Fingerprint**: Cryptographic hash of device characteristics
- **Stack**: USB firmware implementation (LUFA, TinyUSB, etc.)

---

## 12. Approval

This requirements document must be reviewed and approved before proceeding to design phase.

**Stakeholders**:
- Security Team
- Development Team
- QA Team
- Product Owner

---

**Document Version**: 1.0  
**Last Updated**: 2026-05-23  
**Status**: Draft - Awaiting Approval
