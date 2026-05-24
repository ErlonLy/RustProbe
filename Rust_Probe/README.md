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

- [Cargo.toml](Cargo.toml)
- [data/device_signatures.json](data/device_signatures.json)
- [profiles/profiles.json](profiles/profiles.json)
- [src/lib.rs](src/lib.rs)
- [src/main.rs](src/main.rs)
- [src/device_analyzer.rs](src/device_analyzer.rs)
- [src/device_database.rs](src/device_database.rs)
- [src/report_generator.rs](src/report_generator.rs)
- [src/trust_evaluator.rs](src/trust_evaluator.rs)

### Core

- [src/core/mod.rs](src/core/mod.rs)
- [src/core/anomaly.rs](src/core/anomaly.rs)
- [src/core/confidence.rs](src/core/confidence.rs)
- [src/core/device_identity.rs](src/core/device_identity.rs)
- [src/core/device_signature.rs](src/core/device_signature.rs)
- [src/core/errors.rs](src/core/errors.rs)
- [src/core/fingerprint.rs](src/core/fingerprint.rs)
- [src/core/layer_result.rs](src/core/layer_result.rs)
- [src/core/profile.rs](src/core/profile.rs)
- [src/core/timing.rs](src/core/timing.rs)
- [src/core/types.rs](src/core/types.rs)

### Layers

- [src/layers/mod.rs](src/layers/mod.rs)
- [src/layers/passive_descriptor.rs](src/layers/passive_descriptor.rs)
- [src/layers/structural_fingerprint.rs](src/layers/structural_fingerprint.rs)
- [src/layers/hid_fingerprint.rs](src/layers/hid_fingerprint.rs)
- [src/layers/cdc_challenge.rs](src/layers/cdc_challenge.rs)
- [src/layers/invalid_request.rs](src/layers/invalid_request.rs)
- [src/layers/timing_analysis.rs](src/layers/timing_analysis.rs)
- [src/layers/descriptor_consistency.rs](src/layers/descriptor_consistency.rs)
- [src/layers/descriptor_ordering.rs](src/layers/descriptor_ordering.rs)
- [src/layers/stack_fingerprint.rs](src/layers/stack_fingerprint.rs)
- [src/layers/protocol_probe.rs](src/layers/protocol_probe.rs)
- [src/layers/bootloader_verification.rs](src/layers/bootloader_verification.rs)

### Engine

- [src/engine/mod.rs](src/engine/mod.rs)
- [src/engine/cache_layer.rs](src/engine/cache_layer.rs)
- [src/engine/confidence_engine.rs](src/engine/confidence_engine.rs)
- [src/engine/device_analyzer.rs](src/engine/device_analyzer.rs)
- [src/engine/fingerprint_collector.rs](src/engine/fingerprint_collector.rs)
- [src/engine/fingerprint_database.rs](src/engine/fingerprint_database.rs)
- [src/engine/forensic_engine.rs](src/engine/forensic_engine.rs)
- [src/engine/identity_engine.rs](src/engine/identity_engine.rs)
- [src/engine/mismatch_engine.rs](src/engine/mismatch_engine.rs)
- [src/engine/origin_inference.rs](src/engine/origin_inference.rs)
- [src/engine/profile_database.rs](src/engine/profile_database.rs)
- [src/engine/profile_loader.rs](src/engine/profile_loader.rs)
- [src/engine/scoring_engine.rs](src/engine/scoring_engine.rs)
- [src/engine/signature_database.rs](src/engine/signature_database.rs)
- [src/engine/whitelist.rs](src/engine/whitelist.rs)

### Testes

- [tests/golden_tests.rs](tests/golden_tests.rs)
- [tests/golden/g502_genuine.json](tests/golden/g502_genuine.json)
- [tests/golden/tinyusb_spoof.json](tests/golden/tinyusb_spoof.json)
- [tests/golden/lufa_clone.json](tests/golden/lufa_clone.json)
- [tests/golden/esp32_cdc_disabled.json](tests/golden/esp32_cdc_disabled.json)

## Release v1.0

Fluxo recomendado:

```bash
git add .
git commit -m "docs: adiciona README completo para v1.0.0"
git tag -a v1.0 -m "RustProbe v1.0"
git push origin main --tags
```

Se tiver GitHub CLI autenticado:

```bash
gh release create v1.0 \
  --title "RustProbe v1.0" \
  --notes "Primeira release estavel com pipeline forense multi-camada." \
  target/release/RustProbe.exe
```

## Aviso de uso

Projeto para auditoria, validacao e pesquisa de seguranca de dispositivos USB. Use apenas em ambientes autorizados.
