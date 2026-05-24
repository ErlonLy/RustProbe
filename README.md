# RustProbe v1.0.0

RustProbe e um analisador forense USB em Rust para identificar dispositivos HID legitimos versus dispositivos externos spoofados/modificados (Arduino, ESP32-S3, RP2040, STM32, LUFA/TinyUSB e similares), sem dependencia de marca/modelo especifico.

## Objetivo

Detectar inconsistencias entre **identidade alegada** (VID/PID e strings USB) e **comportamento real observado** (topologia, descritores, stack, timing, protocolos), classificando risco com evidencias multiplas.

## Plataformas suportadas

- Windows
- Linux

## Requisitos

- Rust 1.75+ (recomendado: stable mais recente)
- Cargo
- libusb runtime

### Windows

1. Instale Rust via [rustup](https://rustup.rs/).
2. Garanta driver USB compativel para leitura em user-space quando necessario (ex.: WinUSB via Zadig para dispositivos de teste).
3. No PowerShell, dentro da pasta do projeto:

```powershell
cargo check
cargo test
cargo run
```

### Linux

1. Instale Rust via [rustup](https://rustup.rs/).
2. Instale libusb e permissoes udev:

```bash
sudo apt-get update
sudo apt-get install -y libusb-1.0-0-dev
```

3. Rode com permissao adequada (ou configure regras udev):

```bash
cargo check
cargo test
cargo run
```

## Como usar

1. Conecte o dispositivo USB alvo.
2. Execute `cargo run`.
3. Revise no output:
- Identity Score
- TrustLevel
- Anomalias por camada
- Inferencia de origem
- Nearest fingerprints

## Build

### Debug

```bash
cargo build
```

### Release

```bash
cargo build --release
```

Binario gerado:
- Windows: `target/release/RustProbe.exe`
- Linux: `target/release/rust_probe` (nome pode variar conforme crate/bin)

## Estrutura do projeto

- [Cargo.toml](Rust_Probe/Cargo.toml)
- [data/device_signatures.json](Rust_Probe/data/device_signatures.json)
- [profiles/profiles.json](profiles/profiles.json)
- [Rust_Probe/src/lib.rs](Rust_Probe/src/lib.rs)
- [Rust_Probe/src/main.rs](Rust_Probe/src/main.rs)
- [Rust_Probe/src/device_analyzer.rs](Rust_Probe/src/device_analyzer.rs)
- [Rust_Probe/src/device_database.rs](Rust_Probe/src/device_database.rs)
- [Rust_Probe/src/report_generator.rs](Rust_Probe/src/report_generator.rs)
- [Rust_Probe/src/trust_evaluator.rs](Rust_Probe/src/trust_evaluator.rs)

### Core

- [Rust_Probe/src/core/mod.rs](Rust_Probe/src/core/mod.rs)
- [Rust_Probe/src/core/anomaly.rs](Rust_Probe/src/core/anomaly.rs)
- [Rust_Probe/src/core/confidence.rs](Rust_Probe/src/core/confidence.rs)
- [Rust_Probe/src/core/device_identity.rs](Rust_Probe/src/core/device_identity.rs)
- [Rust_Probe/src/core/device_signature.rs](Rust_Probe/src/core/device_signature.rs)
- [Rust_Probe/src/core/errors.rs](Rust_Probe/src/core/errors.rs)
- [Rust_Probe/src/core/fingerprint.rs](Rust_Probe/src/core/fingerprint.rs)
- [Rust_Probe/src/core/layer_result.rs](Rust_Probe/src/core/layer_result.rs)
- [Rust_Probe/src/core/profile.rs](Rust_Probe/src/core/profile.rs)
- [Rust_Probe/src/core/timing.rs](Rust_Probe/src/core/timing.rs)
- [Rust_Probe/src/core/types.rs](Rust_Probe/src/core/types.rs)

### Layers

- [Rust_Probe/src/layers/mod.rs](Rust_Probe/src/layers/mod.rs)
- [Rust_Probe/src/layers/passive_descriptor.rs](Rust_Probe/src/layers/passive_descriptor.rs)
- [Rust_Probe/src/layers/structural_fingerprint.rs](Rust_Probe/src/layers/structural_fingerprint.rs)
- [Rust_Probe/src/layers/hid_fingerprint.rs](Rust_Probe/src/layers/hid_fingerprint.rs)
- [Rust_Probe/src/layers/cdc_challenge.rs](Rust_Probe/src/layers/cdc_challenge.rs)
- [Rust_Probe/src/layers/invalid_request.rs](Rust_Probe/src/layers/invalid_request.rs)
- [Rust_Probe/src/layers/timing_analysis.rs](Rust_Probe/src/layers/timing_analysis.rs)
- [Rust_Probe/src/layers/descriptor_consistency.rs](Rust_Probe/src/layers/descriptor_consistency.rs)
- [Rust_Probe/src/layers/descriptor_ordering.rs](Rust_Probe/src/layers/descriptor_ordering.rs)
- [Rust_Probe/src/layers/stack_fingerprint.rs](Rust_Probe/src/layers/stack_fingerprint.rs)
- [Rust_Probe/src/layers/protocol_probe.rs](Rust_Probe/src/layers/protocol_probe.rs)
- [Rust_Probe/src/layers/bootloader_verification.rs](Rust_Probe/src/layers/bootloader_verification.rs)

### Engine

- [Rust_Probe/src/engine/mod.rs](Rust_Probe/src/engine/mod.rs)
- [Rust_Probe/src/engine/cache_layer.rs](Rust_Probe/src/engine/cache_layer.rs)
- [Rust_Probe/src/engine/confidence_engine.rs](Rust_Probe/src/engine/confidence_engine.rs)
- [Rust_Probe/src/engine/device_analyzer.rs](Rust_Probe/src/engine/device_analyzer.rs)
- [Rust_Probe/src/engine/fingerprint_collector.rs](Rust_Probe/src/engine/fingerprint_collector.rs)
- [Rust_Probe/src/engine/fingerprint_database.rs](Rust_Probe/src/engine/fingerprint_database.rs)
- [Rust_Probe/src/engine/forensic_engine.rs](Rust_Probe/src/engine/forensic_engine.rs)
- [Rust_Probe/src/engine/identity_engine.rs](Rust_Probe/src/engine/identity_engine.rs)
- [Rust_Probe/src/engine/mismatch_engine.rs](Rust_Probe/src/engine/mismatch_engine.rs)
- [Rust_Probe/src/engine/origin_inference.rs](Rust_Probe/src/engine/origin_inference.rs)
- [Rust_Probe/src/engine/profile_database.rs](Rust_Probe/src/engine/profile_database.rs)
- [Rust_Probe/src/engine/profile_loader.rs](Rust_Probe/src/engine/profile_loader.rs)
- [Rust_Probe/src/engine/scoring_engine.rs](Rust_Probe/src/engine/scoring_engine.rs)
- [Rust_Probe/src/engine/signature_database.rs](Rust_Probe/src/engine/signature_database.rs)
- [Rust_Probe/src/engine/whitelist.rs](Rust_Probe/src/engine/whitelist.rs)

### Testes

- [tests/golden_tests.rs](Rust_Probe/tests/golden_tests.rs)
- [tests/golden/g502_genuine.json](Rust_Probe/tests/golden/g502_genuine.json)
- [tests/golden/tinyusb_spoof.json](Rust_Probe/tests/golden/tinyusb_spoof.json)
- [tests/golden/lufa_clone.json](Rust_Probe/tests/golden/lufa_clone.json)
- [tests/golden/esp32_cdc_disabled.json](Rust_Probe/tests/golden/esp32_cdc_disabled.json)

## Aviso de uso

Projeto para auditoria, validacao e pesquisa de seguranca de dispositivos USB. Use apenas em ambientes autorizados.
