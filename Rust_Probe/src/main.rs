use rusb::{Context, UsbContext};
use std::io::{self, Write};
use std::env;
use log::{info, error};
use colored::Colorize;

use RustProbe::engine::{DeviceAnalyzer, DeviceAnalysis};
use RustProbe::core::TrustLevel;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    let args: Vec<String> = env::args().collect();
    let debug_mode = args.contains(&"--debug".to_string());
    let verbose_mode = args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string());

    let context = match Context::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Erro ao inicializar contexto USB: {}", e);
            eprintln!("No Windows, voce pode precisar instalar drivers libusb.");
            eprintln!("Baixe em: https://github.com/libusb/libusb/releases");
            pause();
            std::process::exit(1);
        }
    };

    print_header();
    
    if debug_mode {
        println!("[!] MODO DEBUG: Mostrando todos os dispositivos USB\n");
    }

    info!("Escaneando dispositivos USB...");
    
    let devices = match context.devices() {
        Ok(devs) => devs,
        Err(e) => {
            error!("Erro ao listar dispositivos: {}", e);
            pause();
            std::process::exit(1);
        }
    };

    let mut analyzer = DeviceAnalyzer::new();
    let mut analyses = Vec::new();
    let mut total_devices = 0;
    
    info!("Banco de assinaturas: {} dispositivos conhecidos", analyzer.get_signature_count());
    info!("Banco de perfis: {} perfis carregados", analyzer.get_profile_count());

    for device in devices.iter() {
        total_devices += 1;
        
        if let Ok(desc) = device.device_descriptor() {
            let vid = desc.vendor_id();
            let pid = desc.product_id();
            
            if debug_mode {
                println!("Dispositivo {}: VID=0x{:04X} PID=0x{:04X}", total_devices, vid, pid);
            }
            
            if should_analyze(vid, pid, debug_mode) {
                info!("Analisando dispositivo VID=0x{:04X} PID=0x{:04X}", vid, pid);
                
                match analyzer.analyze(&device) {
                    Ok(analysis) => {
                        analyses.push(analysis);
                    }
                    Err(e) => {
                        error!("Falha ao analisar dispositivo: {}", e);
                    }
                }
            }
        }
    }
    
    // RIGOROUS CHECK: Detect duplicate VID:PID combinations (spoofing indicator)
    detect_duplicate_vidpid(&mut analyses);

    println!();
    
    if analyses.is_empty() {
        println!("Nenhum dispositivo suspeito detectado.");
        println!("Total de dispositivos USB: {}", total_devices);
        if !debug_mode {
            println!("\nExecute com --debug para ver todos os dispositivos USB.");
        }
    } else {
        println!("Encontrado(s) {} dispositivo(s) para analise detalhada\n", analyses.len());
        println!("{}", "=".repeat(80));
        
        for (i, analysis) in analyses.iter().enumerate() {
            println!("\n{} Dispositivo {}/{} {}", 
                     "[".bright_white(), 
                     i + 1, 
                     analyses.len(),
                     "]".bright_white());
            print_device_report(analysis, verbose_mode);
            println!("{}", "=".repeat(80));
        }
        
        print_statistics(&analyses);
    }
    
    pause();
}

fn print_header() {
    println!("{}", "╔════════════════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║     Sistema Avancado de Fingerprinting USB - Rust Probe v0.5.0             ║".bright_cyan());
    println!("{}", "║           Detecao Multi-Camada de Spoofing e Autenticidade                 ║".bright_cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

fn should_analyze(vid: u16, _pid: u16, debug_mode: bool) -> bool {
    if debug_mode {
        return true;
    }
    
    // Arduino VIDs (oficial e clones)
    let arduino_vids = [
        0x2341, // Arduino oficial
        0x2A03, // Arduino.org
        0x1B4F, // SparkFun
    ];
    
    // ESP32/ESP8266 VIDs
    let esp_vids = [
        0x303A, // Espressif (ESP32-S2/S3/C3)
        0x10C4, // Silicon Labs (CP210x usado em ESP)
        0x1A86, // QinHeng (CH340 usado em ESP/Arduino clones)
    ];
    
    // Teensy VIDs
    let teensy_vids = [
        0x16C0, // PJRC (Teensy)
    ];
    
    // Clone/Generic USB-Serial VIDs (muito usados em spoofing)
    let clone_vids = [
        0x1A86, // WCH CH340/CH341/CH552 (MUITO COMUM EM CLONES)
        0x0403, // FTDI (FT232, usado em muitos clones)
        0x067B, // Prolific (PL2303)
        0x10C4, // Silicon Labs CP210x
        0x0483, // STMicroelectronics (STM32)
    ];
    
    // Logitech VID (para detectar spoofing)
    let peripheral_vids = [
        0x046D, // Logitech (ALVO COMUM DE SPOOFING!)
        0x045E, // Microsoft
        0x1532, // Razer
        0x0B05, // ASUS
    ];
    
    // Check if it's a known microcontroller/dev board
    let is_dev_board = arduino_vids.contains(&vid) 
        || esp_vids.contains(&vid)
        || teensy_vids.contains(&vid)
        || clone_vids.contains(&vid);
    
    // Check if it's a peripheral VID (potential spoofing target)
    let is_peripheral = peripheral_vids.contains(&vid);
    
    // Analyze if:
    // 1. It's a dev board/microcontroller
    // 2. It's a peripheral (to detect spoofing)
    is_dev_board || is_peripheral
}

fn print_device_report(analysis: &DeviceAnalysis, verbose: bool) {
    println!("\n{} Informacoes Basicas", "[OK]".green());
    println!("  Bus: {} | Endereco: {}", analysis.bus, analysis.address);
    println!("  VID: 0x{:04X} | PID: 0x{:04X}", analysis.passive.vid, analysis.passive.pid);
    
    if let Some(ref mfr) = analysis.passive.manufacturer {
        println!("  Fabricante: {}", mfr);
    }
    if let Some(ref prod) = analysis.passive.product {
        println!("  Produto: {}", prod);
    }
    
    // Show profile information
    if let Some(ref profile_name) = analysis.matched_profile_name {
        println!("\n{} Perfil Identificado", "[OK]".green());
        println!("  Dispositivo: {}", profile_name.bright_yellow());
        if let Some(ref brand) = analysis.matched_profile_brand {
            println!("  Marca: {}", brand.bright_cyan());
        }
    } else {
        println!("\n{} Perfil nao identificado", "[!]".yellow());
    }
    
    // Show signature information
    if !analysis.signature_name.is_empty() && analysis.signature_name != "Unknown Device (VID:0x0000 PID:0x0000)" {
        println!("\n{} Assinatura Conhecida", "[OK]".green());
        println!("  Dispositivo: {}", analysis.signature_name.bright_yellow());
        if analysis.is_known_device {
            println!("  Visto anteriormente: {} vezes", analysis.seen_count);
        }
    } else {
        println!("\n{} Assinatura nao encontrada no banco de dados", "[!]".yellow());
    }
    
    // Check if it's a USB Hub
    if let Some(ref profile) = analysis.confidence.matched_profile {
        if profile == "USB Hub" {
            println!("\n{} Dispositivo USB Hub Detectado", "[INFO]".bright_blue());
            println!("  Este e um hub USB legitimo do sistema");
            return;
        }
    }
    
    println!("\n{} Fingerprint Estrutural", "[OK]".green());
    let hash_str: String = analysis.structural.fingerprint_hash.iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("  Hash: {}...", hash_str);
    println!("  Interfaces: {} | Endpoints: {}", 
             analysis.structural.topology.num_interfaces,
             analysis.structural.topology.endpoint_addresses.len());
    
    if let Some(ref hid) = analysis.hid {
        println!("\n{} Interface HID Detectada", "[OK]".green());
        if let Some(page) = hid.usage_page {
            println!("  Usage Page: 0x{:04X}", page);
        }
        if let Some(usage) = hid.usage {
            println!("  Usage: 0x{:04X}", usage);
        }
    }
    
    if let Some(ref cdc) = analysis.cdc {
        println!("\n{} Interface CDC ACM Detectada", "[OK]".green());
        println!("  SET_LINE_CODING: {}", if cdc.set_line_coding_success { "OK".green() } else { "FALHOU".red() });
        println!("  GET_LINE_CODING: {}", if cdc.get_line_coding_success { "OK".green() } else { "FALHOU".red() });
        println!("  Roundtrip: {}", if cdc.line_coding_roundtrip_valid { "Valido".green() } else { "Invalido".red() });
    }
    
    println!("\n{} Analise de Timing", "[OK]".green());
    println!("  Media: {} us", analysis.timing.repeated_read_stats.mean_us);
    println!("  Desvio Padrao: {} us", analysis.timing.repeated_read_stats.std_dev_us);
    println!("  Jitter: {} us", analysis.timing.repeated_read_stats.jitter_us);
    
    if let Some(ref stack) = analysis.stack.detected_stack {
        println!("\n{} Stack USB Detectada", "[OK]".green());
        println!("  Stack: {}", stack.as_str().bright_yellow());
        println!("  Confianca: {:.1}%", analysis.stack.confidence * 100.0);
    }
    
    // IDENTITY ANALYSIS - Claim vs Reality
    if let Some(ref identity) = analysis.identity_analysis {
        if identity.is_spoofed || identity.mismatch.has_mismatch {
            println!("\n{} ANALISE DE IDENTIDADE (Claim vs Reality)", "[!!!]".bright_red().bold());
            
            println!("\n  {} Identidade Alegada:", "CLAIM:".bright_cyan());
            println!("    VID:PID: 0x{:04X}:0x{:04X}", identity.claimed.vid, identity.claimed.pid);
            if let Some(ref mfr) = identity.claimed.manufacturer {
                println!("    Fabricante: {}", mfr);
            }
            if let Some(ref prod) = identity.claimed.product {
                println!("    Produto: {}", prod);
            }
            
            println!("\n  {} Comportamento Observado:", "REALITY:".bright_yellow());
            println!("    Interfaces: {} | Endpoints: {}", 
                     identity.observed.num_interfaces,
                     identity.observed.num_endpoints);
            if let Some(ref stack) = identity.observed.detected_stack {
                println!("    Stack Real: {}", stack.bright_red());
            }
            if identity.observed.has_cdc_remnants {
                println!("    CDC Remnants: {} (suspeito!)", "SIM".red());
            }
            
            if !identity.inferred.candidates.is_empty() {
                println!("\n  {} Origem Inferida:", "INFERRED:".bright_magenta());
                for (i, candidate) in identity.inferred.candidates.iter().enumerate() {
                    println!("    {}. {} ({:.1}%)", 
                             i + 1,
                             candidate.name.bright_yellow(),
                             candidate.probability * 100.0);
                    for evidence in &candidate.evidence {
                        println!("       - {}", evidence.dimmed());
                    }
                }
            }
            
            if !identity.mismatch.mismatches.is_empty() {
                println!("\n  {} Incompatibilidades Detectadas:", "MISMATCHES:".red().bold());
                for mismatch in &identity.mismatch.mismatches {
                    println!("    [{}] {}", mismatch.category.red(), "");
                    println!("      Alegado: {}", mismatch.claimed.dimmed());
                    println!("      Observado: {}", mismatch.observed.yellow());
                }
            }
            
            println!("\n  {} Identity Score: {:.1}%", 
                     "SCORE:".bright_white(),
                     identity.identity_score * 100.0);
            
            if identity.is_spoofed {
                println!("  {} DISPOSITIVO PROVAVELMENTE SPOOFADO!", "VERDICT:".bright_red().bold());
            }
        }
    }
    
    println!("\n{} Pontuacao de Confianca", "[!]".yellow());
    println!("  Passiva: {:.2}", analysis.confidence.passive_score);
    println!("  Estrutural: {:.2}", analysis.confidence.structural_score);
    println!("  HID: {:.2}", analysis.confidence.hid_score);
    println!("  Ativa: {:.2}", analysis.confidence.active_score);
    println!("  Stack: {:.2}", analysis.confidence.stack_score);
    println!("  Protocolo: {:.2}", analysis.confidence.protocol_score);
    
    println!("\n{} Resultado Final", "[!]".bright_yellow());
    println!("  Confianca Geral: {:.1}%", analysis.confidence.overall * 100.0);
    
    let (trust_text, trust_color) = match analysis.confidence.trust_level {
        TrustLevel::Genuine => (analysis.confidence.trust_level.as_str(), "green"),
        TrustLevel::BoardModified => (analysis.confidence.trust_level.as_str(), "yellow"),
        TrustLevel::VidPidSpoofed => (analysis.confidence.trust_level.as_str(), "red"),
        TrustLevel::DeepModification => (analysis.confidence.trust_level.as_str(), "red"),
        TrustLevel::Unknown => (analysis.confidence.trust_level.as_str(), "red"),
    };
    
    let colored_trust = match trust_color {
        "green" => trust_text.green(),
        "yellow" => trust_text.yellow(),
        "red" => trust_text.red(),
        _ => trust_text.white(),
    };
    
    println!("  Nivel de Confianca: {}", colored_trust.bold());
    println!("  Anomalias Detectadas: {}", analysis.anomalies.len());
    
    // Always show anomalies with details
    print_anomalies_detailed(analysis);
    
    if verbose {
        print_anomalies(analysis);
    }
}

fn print_anomalies(analysis: &DeviceAnalysis) {
    let mut all_anomalies = Vec::new();
    
    all_anomalies.extend(analysis.passive.anomalies.iter().cloned());
    all_anomalies.extend(analysis.timing.anomalies.iter().cloned());
    all_anomalies.extend(analysis.consistency.anomalies.iter().cloned());
    all_anomalies.extend(analysis.invalid_request.anomalies.iter().cloned());
    
    if let Some(ref hid) = analysis.hid {
        all_anomalies.extend(hid.anomalies.iter().cloned());
    }
    if let Some(ref cdc) = analysis.cdc {
        all_anomalies.extend(cdc.anomalies.iter().cloned());
    }
    
    if !all_anomalies.is_empty() {
        println!("\n{} Anomalias Detectadas (Modo Verbose):", "[!]".red());
        for (i, anomaly) in all_anomalies.iter().enumerate() {
            println!("  {}. {}", i + 1, anomaly);
        }
    }
}

fn print_anomalies_detailed(analysis: &DeviceAnalysis) {
    use RustProbe::core::AnomalySeverity;
    
    if analysis.anomalies.is_empty() {
        println!("\n{} Nenhuma anomalia detectada", "[OK]".green());
        return;
    }
    
    println!("\n{} Detalhamento de Anomalias:", "[!]".yellow());
    
    for (i, anomaly) in analysis.anomalies.iter().enumerate() {
        let severity_str = match anomaly.severity {
            AnomalySeverity::Info => "[INFO]".bright_blue(),
            AnomalySeverity::Low => "[BAIXA]".green(),
            AnomalySeverity::Medium => "[MEDIA]".yellow(),
            AnomalySeverity::High => "[ALTA]".red(),
            AnomalySeverity::Critical => "[CRITICA]".bright_red().bold(),
        };
        
        println!("  {}. {} [{}] {}", 
                 i + 1, 
                 severity_str,
                 anomaly.layer.bright_cyan(),
                 anomaly.description);
        
        if let Some(ref details) = anomaly.details {
            println!("     Detalhes: {}", details.dimmed());
        }
    }
}

fn print_statistics(analyses: &[DeviceAnalysis]) {
    println!("\n{}", "Estatisticas Gerais".bright_cyan().bold());
    println!("{}", "-".repeat(80));
    
    let genuine = analyses.iter().filter(|a| matches!(a.confidence.trust_level, TrustLevel::Genuine)).count();
    let modified = analyses.iter().filter(|a| matches!(a.confidence.trust_level, TrustLevel::BoardModified)).count();
    let spoofed = analyses.iter().filter(|a| matches!(a.confidence.trust_level, TrustLevel::VidPidSpoofed)).count();
    let deep_mod = analyses.iter().filter(|a| matches!(a.confidence.trust_level, TrustLevel::DeepModification)).count();
    let unknown = analyses.iter().filter(|a| matches!(a.confidence.trust_level, TrustLevel::Unknown)).count();
    
    println!("Total de dispositivos analisados: {}", analyses.len());
    println!("  {} Genuinos: {}", "[OK]".green(), genuine);
    println!("  {} Modificados: {}", "[!]".yellow(), modified);
    println!("  {} VID/PID Falsificado: {}", "[!]".red(), spoofed);
    println!("  {} Modificacao Profunda: {}", "[!]".red(), deep_mod);
    println!("  {} Desconhecidos: {}", "[!]".red(), unknown);
    
    let avg_confidence: f32 = analyses.iter().map(|a| a.confidence.overall).sum::<f32>() / analyses.len() as f32;
    println!("\nConfianca media: {:.1}%", avg_confidence * 100.0);
    
    let total_anomalies: usize = analyses.iter().map(|a| a.confidence.anomaly_count).sum();
    println!("Total de anomalias: {}", total_anomalies);
}

fn detect_duplicate_vidpid(analyses: &mut Vec<DeviceAnalysis>) {
    use std::collections::HashMap;
    use RustProbe::core::{Anomaly, AnomalyType, AnomalySeverity};
    
    // Group devices by VID:PID
    let mut vidpid_map: HashMap<(u16, u16), Vec<usize>> = HashMap::new();
    
    for (idx, analysis) in analyses.iter().enumerate() {
        let key = (analysis.passive.vid, analysis.passive.pid);
        vidpid_map.entry(key).or_insert_with(Vec::new).push(idx);
    }
    
    // Check for duplicates
    for ((vid, pid), indices) in vidpid_map.iter() {
        if indices.len() > 1 {
            // Multiple devices with same VID:PID - HIGHLY SUSPICIOUS!
            let anomaly = Anomaly::new(AnomalyType::DuplicateVidPid, "System")
                .with_severity(AnomalySeverity::Critical)
                .with_details(format!(
                    "Múltiplos dispositivos ({}) com mesmo VID:PID (0x{:04X}:0x{:04X}) - Indicador forte de spoofing com flags de compilação",
                    indices.len(), vid, pid
                ));
            
            // Add anomaly to all devices with this VID:PID
            for &idx in indices {
                analyses[idx].anomalies.push(anomaly.clone());
                
                // Recalculate confidence with critical anomaly
                let critical_penalty = 0.4; // 40% penalty for critical anomaly
                analyses[idx].confidence.overall = (analyses[idx].confidence.overall - critical_penalty).max(0.0);
                
                // Downgrade trust level
                if analyses[idx].confidence.overall < 0.5 {
                    analyses[idx].confidence.trust_level = RustProbe::core::TrustLevel::VidPidSpoofed;
                } else if analyses[idx].confidence.overall < 0.75 {
                    analyses[idx].confidence.trust_level = RustProbe::core::TrustLevel::BoardModified;
                }
            }
        }
    }
}

fn pause() {
    print!("\nPressione Enter para sair...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

