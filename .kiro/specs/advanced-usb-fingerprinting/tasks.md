# Implementation Plan: Advanced USB Fingerprinting System

## Overview

This implementation plan transforms the Rust Probe detection system from a simple VID/PID-based validator into a sophisticated 12-layer USB fingerprinting engine. The system will detect advanced spoofing techniques used in Arduino, ESP32, Teensy, and other development boards attempting to masquerade as legitimate peripherals.

The implementation follows a 6-phase roadmap spanning 12 weeks, building from core infrastructure through passive and active analysis layers, culminating in a complete confidence scoring and reporting system.

## Tasks

### Phase 1: Core Infrastructure (Week 1-2)

- [ ] 1. Set up project structure and core data models
  - Create Cargo workspace with proper module organization
  - Define core data structures: `UsbFingerprint`, `LayerResult`, `DeviceProfile`, `ConfidenceScore`, `TimingProfile`
  - Implement Serialize/Deserialize traits for all data structures
  - Create `LayerError` and `AnalysisError` enum types with proper error conversion
  - Set up logging infrastructure with `log` and `env_logger` crates
  - _Requirements: NFR-4 (Maintainability), NFR-2 (Reliability)_

- [ ]* 1.1 Write property test for data structure serialization
  - **Property: Round-trip serialization**
  - **Validates: Data integrity during serialization/deserialization**
  - Test that all core data structures can be serialized to JSON and deserialized back without data loss
  - _Requirements: NFR-4_

- [ ] 2. Implement mock USB device framework for testing
  - Create `UsbDevice` and `UsbHandle` traits for abstraction
  - Implement `MockUsbDevice` with configurable descriptors and responses
  - Create mock device factories: `arduino_leonardo()`, `esp32_s3()`, `logitech_mouse()`, `teensy_3x()`
  - Implement control transfer simulation with configurable timing
  - _Requirements: NFR-4 (Maintainability)_

- [ ] 3. Create custom proptest generators
  - Implement `device_descriptor_generator()` for random USB device descriptors
  - Implement `config_descriptor_generator()` for random configuration descriptors
  - Implement `topology_generator()` for random USB topology data
  - Implement `hid_descriptor_generator()` for random HID report descriptors
  - Implement `fingerprint_generator()` for random SHA-256 hashes
  - Implement `timing_generator()` for random timing measurements
  - Implement `layer_results_generator()` for random layer results
  - _Requirements: NFR-3 (Accuracy)_

- [ ] 4. Checkpoint - Verify core infrastructure
  - Ensure all tests pass, ask the user if questions arise.

### Phase 2: Passive Layers (Week 3-4)

- [ ] 5. Implement Layer 1: Passive Descriptor Validation
  - [ ] 5.1 Create `layers/passive_descriptor.rs` module
    - Implement `PassiveDescriptorAnalyzer` struct
    - Implement `analyze()` method to read device, configuration, interface, and endpoint descriptors
    - Extract VID, PID, manufacturer string, product string, serial number
    - Extract USB version, device version, device class, subclass, protocol
    - Extract all interface and endpoint descriptors
    - Calculate passive score (0.0-1.0) based on descriptor completeness
    - Detect anomalies: missing strings, unusual class codes, vendor-specific protocols
    - _Requirements: FR-1.1, NFR-1 (Performance < 100ms)_

  - [ ]* 5.2 Write property test for descriptor extraction completeness
    - **Property 1: Descriptor Extraction Completeness**
    - **Validates: Requirements FR-1.1.1, FR-1.1.2, FR-1.1.3, FR-1.1.4, FR-1.1.5**
    - Test that all available descriptor fields are extracted or explicitly marked as None
    - _Requirements: FR-1.1_

- [ ] 6. Implement Layer 2: Structural Fingerprint
  - [ ] 6.1 Create `layers/structural_fingerprint.rs` module
    - Implement `StructuralFingerprintAnalyzer` struct with profile database reference
    - Implement `extract_topology()` to collect: interface count, interface classes, endpoint addresses, endpoint types, endpoint directions, max packet sizes, polling intervals, IAD presence, CDC functional descriptors
    - Implement `generate_fingerprint()` to create canonical byte representation and SHA-256 hash
    - Implement profile matching against known device profiles
    - Calculate structural score based on profile match similarity
    - _Requirements: FR-1.2, NFR-1 (Performance < 100ms)_

  - [ ]* 6.2 Write property test for structural fingerprint determinism
    - **Property 2: Fingerprint Determinism**
    - **Validates: Requirements FR-1.2.2**
    - Test that same topology data always produces identical SHA-256 hash
    - _Requirements: FR-1.2_

  - [ ]* 6.3 Write property test for profile database query success
    - **Property 3: Profile Database Query Success**
    - **Validates: Requirements FR-1.2.3**
    - Test that all fingerprint queries return valid results without errors
    - _Requirements: FR-1.2_

- [ ] 7. Implement Layer 3: HID Fingerprint
  - [ ] 7.1 Create `layers/hid_fingerprint.rs` module
    - Implement `HIDFingerprintAnalyzer` struct with profile database reference
    - Implement HID interface detection (class 0x03)
    - Implement `read_hid_report_descriptor()` using GET_DESCRIPTOR(HID_REPORT) control transfer
    - Generate SHA-256 hash of HID report descriptor
    - Extract usage page and usage from descriptor
    - Match against known HID profiles (Arduino LUFA, TinyUSB, ESP32, Teensy, Logitech, Microsoft)
    - Calculate HID score based on profile match
    - Detect anomalies: usage page/usage mismatch with claimed device type
    - _Requirements: FR-1.3, NFR-1 (Performance < 200ms)_

  - [ ]* 7.2 Write property test for HID fingerprint determinism
    - **Property 2: Fingerprint Determinism (HID)**
    - **Validates: Requirements FR-1.3.3**
    - Test that same HID descriptor always produces identical SHA-256 hash
    - _Requirements: FR-1.3_

  - [ ]* 7.3 Write property test for HID interface detection
    - **Property 4: Interface Detection Accuracy (HID)**
    - **Validates: Requirements FR-1.3.1**
    - Test that devices with HID interface (class 0x03) are correctly detected
    - _Requirements: FR-1.3_

- [ ] 8. Create profile database infrastructure
  - [ ] 8.1 Create `profile_database.rs` module
    - Implement `ProfileDatabase` struct with structural profiles, HID profiles, stack signatures
    - Implement LRU cache for profile lookups (capacity: 100 entries)
    - Implement `load_from_file()` to load profiles from JSON
    - Implement `match_structural()` with exact and partial matching (Hamming distance)
    - Implement `match_hid()` with exact and partial matching
    - Implement `match_stack()` for USB stack identification
    - _Requirements: FR-1.2, FR-1.3, NFR-1 (Performance < 50ms with caching)_

  - [ ] 8.2 Create initial profile database JSON
    - Add profiles for: Arduino Leonardo (LUFA), Arduino Leonardo (Caterina bootloader), ESP32-S3 (TinyUSB), ESP32-S3 (ESP-IDF), Teensy 3.x/4.x, CP2102, CH340, FTDI FT232, Logitech peripherals, Microsoft peripherals
    - Include structural fingerprints, HID fingerprints, timing profiles, VID/PID combinations
    - _Requirements: FR-1.2, FR-1.3_

- [ ] 9. Checkpoint - Verify passive layers
  - Ensure all tests pass, ask the user if questions arise.

### Phase 3: Active Layers (Week 5-6)

- [ ] 10. Implement Layer 4: CDC ACM Challenge
  - [ ] 10.1 Create `layers/cdc_challenge.rs` module
    - Implement `CDCChallengeAnalyzer` struct
    - Implement CDC ACM interface detection (class 0x02, subclass 0x02)
    - Implement `execute_set_line_coding()` with timing measurement
    - Implement `execute_get_line_coding()` with timing measurement
    - Implement `execute_set_control_line_state()` with timing measurement
    - Verify line coding round-trip (SET → GET → verify)
    - Calculate CDC score based on request success and timing consistency
    - Detect anomalies: STALL responses, timeouts, incorrect response format, slow response (>100ms)
    - _Requirements: FR-1.4, NFR-1 (Performance < 1 second)_

  - [ ]* 10.2 Write property test for CDC interface detection
    - **Property 4: Interface Detection Accuracy (CDC)**
    - **Validates: Requirements FR-1.4.1**
    - Test that devices with CDC ACM interface (class 0x02, subclass 0x02) are correctly detected
    - _Requirements: FR-1.4_

- [ ] 11. Implement Layer 5: Invalid Request Challenge
  - [ ] 11.1 Create `layers/invalid_request.rs` module
    - Implement `InvalidRequestAnalyzer` struct
    - Implement `test_invalid_descriptor_type()` (request type 0xFF)
    - Implement `test_invalid_wlength()` (excessive length value)
    - Implement `test_invalid_request_code()` (request code 0xFF)
    - Classify responses: STALL (expected), Timeout (expected), ValidData (suspicious), DeviceDisconnect (suspicious), UnexpectedAck (suspicious)
    - Calculate invalid request score based on proper error handling
    - Detect anomalies: unexpected data returned, device crash/disconnect
    - _Requirements: FR-1.5, NFR-1 (Performance < 500ms)_

  - [ ]* 11.2 Write property test for response classification
    - **Property 6: Response Classification Correctness**
    - **Validates: Requirements FR-1.4.7, FR-1.5.3**
    - Test that all USB control transfer responses are correctly classified
    - _Requirements: FR-1.5_

- [ ] 12. Implement Layer 6: Timing Analysis
  - [ ] 12.1 Create `layers/timing_analysis.rs` module
    - Implement `TimingAnalyzer` struct
    - Implement `measure_repeated_reads()` to perform 100 consecutive descriptor reads
    - Implement `calculate_statistics()` to compute mean, standard deviation, min, max, jitter, variance
    - Measure enumeration latency, descriptor read latency, control transfer latency
    - Classify timing profile: RealHardware (σ < 5ms), Emulated (σ > 20ms), Proxied (high jitter)
    - Calculate timing score based on consistency
    - Detect anomalies: high variance, burst instability, inconsistent jitter
    - _Requirements: FR-1.6, NFR-1 (Performance < 2 seconds for 100 reads)_

  - [ ]* 12.2 Write property test for timing statistics correctness
    - **Property 5: Timing Statistics Correctness**
    - **Validates: Requirements FR-1.6.5**
    - Test that calculated statistics (mean, std dev, min, max, jitter, variance) are mathematically correct
    - _Requirements: FR-1.6_

- [ ] 13. Implement Layer 7: Descriptor Consistency
  - [ ] 13.1 Create `layers/descriptor_consistency.rs` module
    - Implement `DescriptorConsistencyAnalyzer` struct
    - Implement `read_descriptor_repeatedly()` to read same descriptor 100 times
    - Implement `verify_consistency()` to check size and content equality
    - Calculate CRC32 checksum for each read
    - Verify all checksums are identical
    - Calculate consistency score (1.0 if consistent, 0.0 if inconsistent)
    - Detect anomalies: size mismatch, content mismatch, checksum mismatch
    - _Requirements: FR-1.7, NFR-1 (Performance < 1 second)_

  - [ ]* 13.2 Write property test for descriptor consistency verification
    - **Property 7: Descriptor Consistency Verification**
    - **Validates: Requirements FR-1.7.2, FR-1.7.3, FR-1.7.5**
    - Test that identical reads are reported as consistent and different reads as inconsistent
    - _Requirements: FR-1.7_

- [ ] 14. Checkpoint - Verify active layers
  - Ensure all tests pass, ask the user if questions arise.

### Phase 4: Advanced Layers (Week 7-8)

- [ ] 15. Implement Layer 8: Bootloader Verification
  - [ ] 15.1 Create `layers/bootloader_verification.rs` module
    - Implement `BootloaderVerifier` struct
    - Implement `test_caterina_bootloader()` for Arduino Leonardo
      - Open serial port at 1200 baud, close immediately
      - Monitor for device disconnect and re-enumeration
      - Verify bootloader VID/PID (0x2341:0x0036)
      - Measure timing (expected: 650-850ms)
    - Implement `test_teensy_bootloader()` for Teensy devices
      - Trigger HID bootloader mode
      - Verify bootloader VID/PID (0x16C0:0x0478)
    - Calculate bootloader score based on validation success
    - Detect anomalies: no reset, incorrect timing, wrong VID/PID in bootloader mode
    - _Requirements: FR-1.8, NFR-1 (Performance < 2 seconds)_

- [ ] 16. Implement Layer 9: Stack Fingerprinting
  - [ ] 16.1 Create `layers/stack_fingerprint.rs` module
    - Implement `StackFingerprintAnalyzer` struct
    - Implement `detect_lufa_signatures()` - check descriptor ordering, endpoint pattern, CDC functional descriptor order
    - Implement `detect_tinyusb_signatures()` - check IAD presence, endpoint grouping, CDC functional descriptor order
    - Implement `detect_esp_idf_signatures()` - check non-standard descriptor ordering, endpoint addresses
    - Implement `detect_arduino_avr_signatures()`
    - Implement `detect_pjrc_signatures()` for Teensy
    - Classify probable USB stack based on signature matches
    - Calculate stack score based on confidence in detection
    - _Requirements: FR-1.9, NFR-1 (Performance < 200ms)_

  - [ ]* 16.2 Write property test for stack classification determinism
    - **Property 8: Stack Classification Determinism**
    - **Validates: Requirements FR-1.9.5**
    - Test that same stack signatures always produce same classification
    - _Requirements: FR-1.9_

- [ ] 17. Implement Layer 10: Protocol Probe
  - [ ] 17.1 Create `layers/protocol_probe.rs` module
    - Implement `ProtocolProber` struct
    - Implement `probe_stk500()` - send STK500 sync pattern (0x30 0x20)
    - Implement `probe_avr109()` - send AVR109 probe sequence
    - Implement `probe_esp_bootloader()` - send ESP ROM bootloader sync pattern
    - Implement `probe_teensy_hid()` - send Teensy-specific HID reports
    - Classify responses: Responded (suspicious), NoResponse (expected), InvalidResponse (suspicious)
    - Calculate protocol score based on response patterns
    - _Requirements: FR-1.10, NFR-1 (Performance < 1 second)_

- [ ] 18. Create stack signature database
  - Create JSON database with stack signatures for: LUFA, TinyUSB, ESP-IDF, Arduino AVR Core, STM32Cube USB, Zephyr USB, PJRC/Teensy
  - Include descriptor ordering patterns, endpoint patterns, CDC functional descriptor ordering, timing characteristics
  - _Requirements: FR-1.9_

- [ ] 19. Checkpoint - Verify advanced layers
  - Ensure all tests pass, ask the user if questions arise.

### Phase 5: Scoring and Reporting (Week 9-10)

- [ ] 20. Implement confidence scoring engine
  - [ ] 20.1 Create `confidence_engine.rs` module
    - Implement `ConfidenceEngine` struct with whitelist reference
    - Implement `calculate_confidence()` with weighted scoring:
      - Passive: 15%, Structural: 25%, HID: 30%, Active: 15%, Stack: 10%, Protocol: 5%
    - Implement `calculate_active_score()` to aggregate CDC, invalid request, timing, consistency, bootloader scores
    - Implement `count_anomalies()` across all layers
    - Implement `classify_trust_level()` with thresholds:
      - Genuine: ≥0.85
      - BoardModified: 0.60-0.85
      - VidPidSpoofed: 0.30-0.60 (requires ≥3 anomalies)
      - DeepModification: 0.10-0.30
      - Unknown: <0.10
    - Implement whitelist override logic
    - _Requirements: FR-2.1, NFR-3 (Accuracy targets)_

  - [ ]* 20.2 Write property test for confidence score bounds
    - **Property 9: Confidence Score Bounds**
    - **Validates: Requirements FR-2.1.2**
    - Test that all confidence scores are in range [0.0, 1.0]
    - _Requirements: FR-2.1_

  - [ ]* 20.3 Write property test for trust level classification
    - **Property 10: Trust Level Classification Correctness**
    - **Validates: Requirements FR-2.1.3**
    - Test that trust levels are assigned according to defined thresholds
    - _Requirements: FR-2.1_

  - [ ]* 20.4 Write property test for whitelist override
    - **Property 11: Whitelist Override**
    - **Validates: Requirements FR-2.2.4**
    - Test that whitelist match always results in Genuine trust level
    - _Requirements: FR-2.2_

  - [ ]* 20.5 Write property test for multi-factor anomaly requirement
    - **Property 12: Multi-Factor Anomaly Requirement**
    - **Validates: Requirements FR-2.2.3**
    - Test that VidPidSpoofed classification requires ≥3 anomalies
    - _Requirements: FR-2.2_

- [ ] 21. Implement whitelist system
  - [ ] 21.1 Create `whitelist.rs` module
    - Implement `Whitelist` struct with whitelist profiles
    - Implement `load_from_file()` to load whitelist from JSON
    - Implement `is_whitelisted()` to match devices against whitelist profiles
    - Implement `match_profile()` to check structural fingerprint, HID fingerprint, VID range
    - Support allowed anomalies per profile
    - _Requirements: FR-2.2, NFR-3 (False positive rate < 5%)_

  - [ ] 21.2 Create whitelist database JSON
    - Add whitelist profiles for: Logitech peripherals, Microsoft peripherals, Corsair peripherals, Razer peripherals, CP2102, FTDI, CH340, legitimate composite devices
    - Include structural/HID fingerprints, VID ranges, allowed anomalies
    - _Requirements: FR-2.2_

- [ ] 22. Implement report generator
  - [ ] 22.1 Create `report_generator.rs` module
    - Implement `ReportGenerator` struct
    - Implement `print_device_report()` to display:
      - Device identification (bus, address, VID, PID)
      - Passive descriptor data
      - Structural fingerprint hash and matched profile
      - HID descriptor hash and matched profile (if applicable)
      - Active challenge results (pass/fail per request)
      - Timing statistics (mean, σ, jitter)
      - Descriptor consistency results
      - Bootloader validation results (if applicable)
      - Detected USB stack
      - Protocol probe results
      - Per-layer scores
      - Final confidence score and trust level
    - Implement color-coding: green (Genuine), yellow (BoardModified), orange (VidPidSpoofed), red (DeepModification/Unknown)
    - Implement `print_statistics()` for batch analysis summary
    - Implement `export_json()` for machine-readable output
    - _Requirements: FR-3.1, FR-3.2_

  - [ ]* 22.2 Write property test for profile similarity bounds
    - **Property 13: Profile Similarity Bounds**
    - **Validates: Requirements FR-3.2.3**
    - Test that similarity scores are in range [0.0, 1.0]
    - _Requirements: FR-3.2_

- [ ] 23. Implement CLI interface
  - [ ] 23.1 Create enhanced `main.rs` CLI
    - Implement argument parsing with `clap` crate
    - Add options: `--device <bus:addr>`, `--all`, `--profiles <path>`, `--whitelist <path>`, `--json`, `--verbose`
    - Implement `DeviceScanner` to enumerate USB devices
    - Implement `DeviceAnalyzer` to orchestrate all 12 layers
    - Implement error handling with graceful degradation
    - Implement timeout protection (5 seconds per device)
    - Implement logging configuration via RUST_LOG environment variable
    - _Requirements: FR-1, NFR-1 (Performance < 5 seconds per device)_

- [ ] 24. Create integration tests
  - Write end-to-end tests with mock USB devices
  - Test complete analysis workflow for: genuine Arduino Leonardo, spoofed Arduino Leonardo, ESP32-S3, Teensy, Logitech mouse, CP2102
  - Test graceful degradation on layer failures
  - Test batch device analysis
  - Test whitelist override scenarios
  - _Requirements: NFR-3 (Accuracy targets)_

- [ ] 25. Checkpoint - Verify scoring and reporting
  - Ensure all tests pass, ask the user if questions arise.

### Phase 6: Optimization and Polish (Week 11-12)

- [ ] 26. Implement performance optimizations
  - [ ] 26.1 Add parallel layer execution
    - Use `rayon` crate for parallel execution of independent layers
    - Execute Layers 1, 2, 6 in parallel (no dependencies)
    - Execute dependent layers sequentially (Layers 3, 4, 7, 8, 9, 10)
    - _Requirements: NFR-1 (Performance < 5 seconds)_

  - [ ] 26.2 Optimize profile matching with caching
    - Verify LRU cache is working correctly
    - Add cache hit/miss metrics
    - Tune cache size based on benchmarks
    - _Requirements: NFR-1 (Performance < 50ms for profile matching)_

  - [ ] 26.3 Add buffer pooling for memory efficiency
    - Implement `BufferPool` for reusable descriptor buffers
    - Pool size: 10 buffers × 100 KB
    - _Requirements: NFR-1 (Memory usage < 50 MB)_

- [ ] 27. Write comprehensive documentation
  - Write API documentation with rustdoc comments for all public interfaces
  - Create user guide with examples: basic usage, interpreting results, updating databases
  - Document profile database format and update process
  - Document whitelist database format and update process
  - Document stack signature database format
  - Create troubleshooting guide for common issues
  - _Requirements: NFR-4 (Maintainability)_

- [ ] 28. Set up CI/CD pipeline
  - Create GitHub Actions workflow for: build, test, clippy, rustfmt
  - Run all unit tests and property tests (100 iterations each)
  - Run integration tests
  - Generate code coverage report
  - Build release binaries for Linux, Windows, macOS
  - _Requirements: NFR-4 (Maintainability)_

- [ ] 29. Run performance benchmarks
  - Benchmark single device analysis time (target: < 5 seconds)
  - Benchmark structural fingerprint generation (target: < 100ms)
  - Benchmark HID descriptor read (target: < 200ms)
  - Benchmark CDC challenge sequence (target: < 1 second)
  - Benchmark timing analysis (target: < 2 seconds)
  - Benchmark profile matching (target: < 50ms)
  - Benchmark batch analysis of 10 devices (target: < 30 seconds)
  - Measure memory usage (target: < 50 MB)
  - _Requirements: NFR-1 (Performance)_

- [ ] 30. Create release build
  - Configure Cargo.toml for release optimizations (opt-level = 3, lto = true, codegen-units = 1)
  - Strip debug symbols
  - Test release build on all target platforms
  - Create installation instructions
  - Package profile databases and whitelist
  - _Requirements: NFR-5 (Portability)_

- [ ] 31. Final checkpoint - Complete system verification
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-based test tasks and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at the end of each phase
- Property tests validate universal correctness properties from the design document
- The implementation uses Rust as specified in the design document
- All 12 layers operate independently with graceful degradation
- The system achieves <5% false positive rate through multi-factor anomaly detection and whitelist matching
- Performance targets: <5 seconds per device, <50 MB memory usage
- The 6-phase roadmap spans 12 weeks with clear deliverables at each phase
