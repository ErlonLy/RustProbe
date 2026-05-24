use rusb::{Context, UsbContext};
use std::io::{self, Write};
use std::env;
use log::{info, error};
use colored::Colorize;

use rust_probe::engine::{DeviceAnalyzer, DeviceAnalysis, FingerprintCollector};
use rust_probe::core::TrustLevel;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    let args: Vec<String> = env::args().collect();
    let debug_mode = args.contains(&"--debug".to_string());
    let verbose_mode = args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string());
    let collect_mode = args.contains(&"--collect".to_string());

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
    
    if collect_mode {
        println!("{}", "[MODO COLETA] Coletando fingerprints de dispositivos genuínos\n".bright_green().bold());
        run_collection_mode(&context, debug_mode);
        return;
    }
    
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
    println!("{}", "║     Sistema Avancado de Fingerprinting USB - Rust Probe v1.0.0             ║".bright_cyan());
    println!("{}", "║           Detecao Multi-Camada de Spoofing e Autenticidade                 ║".bright_cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

fn should_analyze(vid: u16, _pid: u16, debug_mode: bool) -> bool {
    let _ = (vid, debug_mode);
    true
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
    
    
    if let Some(ref profile_name) = analysis.matched_profile_name {
        println!("\n{} Perfil Identificado", "[OK]".green());
        println!("  Dispositivo: {}", profile_name.bright_yellow());
        if let Some(ref brand) = analysis.matched_profile_brand {
            println!("  Marca: {}", brand.bright_cyan());
        }
    } else {
        println!("\n{} Perfil nao identificado", "[!]".yellow());
    }
    
    
    if !analysis.signature_name.is_empty() && analysis.signature_name != "Unknown Device (VID:0x0000 PID:0x0000)" {
        println!("\n{} Assinatura Conhecida", "[OK]".green());
        println!("  Dispositivo: {}", analysis.signature_name.bright_yellow());
        if analysis.is_known_device {
            println!("  Visto anteriormente: {} vezes", analysis.seen_count);
        }
    } else {
        println!("\n{} Assinatura nao encontrada no banco de dados", "[!]".yellow());
    }
    
    
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
    
    
    if let Some(ref desc_order) = analysis.descriptor_ordering {
        println!("\n{} Ordenacao de Descritores", "[OK]".green());
        let hash_str: String = desc_order.ordering_hash.iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("  Hash de Ordenacao: {}...", hash_str);
        println!("  Sequencia: {} descritores", desc_order.descriptor_sequence.len());
        println!("  Tamanho Total: {} bytes", desc_order.total_length);
        
        if let Some(ref pattern) = desc_order.detected_pattern {
            println!("  Padrao Detectado: {}", pattern.as_str().bright_yellow());
            
            
            if let Some(ref stack) = analysis.stack.detected_stack {
                let stack_name = stack.as_str();
                let pattern_name = pattern.as_str();
                
                
                if stack_name == pattern_name {
                    println!("  {} Stack e padrao de descritores COINCIDEM", "[OK]".green());
                } else {
                    println!("  {} Stack ({}) e padrao ({}) NAO COINCIDEM - SUSPEITO!", 
                             "[!!!]".red().bold(),
                             stack_name.yellow(),
                             pattern_name.yellow());
                }
            }
        }
    }
    
    
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
    
    
    if !analysis.nearest_matches.is_empty() {
        println!("\n{} BUSCA POR SIMILARIDADE (Nearest Fingerprints)", "[SEARCH]".bright_magenta().bold());
        
        for (i, match_result) in analysis.nearest_matches.iter().enumerate() {
            let similarity_color = if match_result.similarity > 0.8 {
                "green"
            } else if match_result.similarity > 0.5 {
                "yellow"
            } else {
                "red"
            };
            
            let colored_similarity = match similarity_color {
                "green" => format!("{:.1}%", match_result.similarity * 100.0).green(),
                "yellow" => format!("{:.1}%", match_result.similarity * 100.0).yellow(),
                "red" => format!("{:.1}%", match_result.similarity * 100.0).red(),
                _ => format!("{:.1}%", match_result.similarity * 100.0).white(),
            };
            
            println!("  {}. {} - {} ({})", 
                     i + 1,
                     match_result.name.bright_cyan(),
                     match_result.manufacturer.dimmed(),
                     colored_similarity);
            
            for evidence in &match_result.evidence {
                println!("     - {}", evidence.dimmed());
            }
        }
        
        
        let top_match = &analysis.nearest_matches[0];
        if top_match.similarity < 0.5 {
            println!("\n  {} Baixa similaridade com dispositivos conhecidos - possível spoof!", 
                     "[WARNING]".yellow().bold());
        } else if top_match.evidence.iter().any(|e| e.contains("MISMATCH")) {
            println!("\n  {} Incompatibilidade detectada - provável compile-flag spoofing!", 
                     "[ALERT]".red().bold());
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
    use rust_probe::core::AnomalySeverity;
    
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
    use rust_probe::core::{Anomaly, AnomalyType, AnomalySeverity};
    
    
    let mut vidpid_map: HashMap<(u16, u16), Vec<usize>> = HashMap::new();
    
    for (idx, analysis) in analyses.iter().enumerate() {
        let key = (analysis.passive.vid, analysis.passive.pid);
        vidpid_map.entry(key).or_insert_with(Vec::new).push(idx);
    }
    
    
    for ((vid, pid), indices) in vidpid_map.iter() {
        if indices.len() > 1 {
            
            let mut topology_mismatch = false;
            let mut hid_hash_mismatch = false;
            let mut stack_mismatch = false;
            let mut timing_cluster_mismatch = false;
            let mut descriptor_ordering_mismatch = false;
            let mut structural_hash_mismatch = false;
            
            
            let ref_analysis = &analyses[indices[0]];
            let ref_topology = (ref_analysis.structural.topology.num_interfaces, 
                               ref_analysis.structural.topology.endpoint_addresses.len());
            let ref_hid_hash = ref_analysis.hid.as_ref().map(|h| &h.report_descriptor);
            let ref_stack = ref_analysis.stack.detected_stack.as_ref().map(|s| s.as_str());
            let ref_timing = ref_analysis.timing.repeated_read_stats.mean_us;
            let ref_ordering_hash = ref_analysis.descriptor_ordering.as_ref().map(|d| d.ordering_hash);
            let ref_structural_hash = ref_analysis.structural.fingerprint_hash;
            
            
            for &idx in indices.iter().skip(1) {
                let analysis = &analyses[idx];
                
                
                let topology = (analysis.structural.topology.num_interfaces,
                               analysis.structural.topology.endpoint_addresses.len());
                if topology.0 != ref_topology.0 || topology.1 != ref_topology.1 {
                    topology_mismatch = true;
                }
                
                
                let hid_hash = analysis.hid.as_ref().map(|h| &h.report_descriptor);
                if hid_hash != ref_hid_hash {
                    hid_hash_mismatch = true;
                }
                
                
                let stack = analysis.stack.detected_stack.as_ref().map(|s| s.as_str());
                if stack != ref_stack {
                    stack_mismatch = true;
                }
                
                let ordering_hash = analysis.descriptor_ordering.as_ref().map(|d| d.ordering_hash);
                if ordering_hash != ref_ordering_hash {
                    descriptor_ordering_mismatch = true;
                }
                
                if analysis.structural.fingerprint_hash != ref_structural_hash {
                    structural_hash_mismatch = true;
                }
                
                
                let timing = analysis.timing.repeated_read_stats.mean_us;
                if ref_timing > 0 && timing > 0 {
                    let timing_diff = (timing as f32 - ref_timing as f32).abs() / ref_timing as f32;
                    if timing_diff > 0.3 {
                        timing_cluster_mismatch = true;
                    }
                }
            }
            
            
            let is_suspicious = topology_mismatch
                || hid_hash_mismatch
                || stack_mismatch
                || timing_cluster_mismatch
                || descriptor_ordering_mismatch
                || structural_hash_mismatch;
            
            if is_suspicious {
                let mut mismatch_details = Vec::new();
                if topology_mismatch { mismatch_details.push("topology"); }
                if hid_hash_mismatch { mismatch_details.push("HID hash"); }
                if stack_mismatch { mismatch_details.push("stack"); }
                if timing_cluster_mismatch { mismatch_details.push("timing cluster"); }
                if descriptor_ordering_mismatch { mismatch_details.push("descriptor ordering"); }
                if structural_hash_mismatch { mismatch_details.push("structural fingerprint"); }
                
                let anomaly = Anomaly::new(AnomalyType::DuplicateVidPid, "System")
                    .with_severity(AnomalySeverity::Critical)
                    .with_details(format!(
                        "Múltiplos dispositivos ({}) com mesmo VID:PID (0x{:04X}:0x{:04X}) mas características diferentes: {} - Indicador forte de spoofing",
                        indices.len(), vid, pid, mismatch_details.join(", ")
                    ));
                
                
                for &idx in indices {
                    analyses[idx].anomalies.push(anomaly.clone());
                    
                    
                    let mismatch_count = mismatch_details.len();
                    let penalty = match mismatch_count {
                        1 => 0.15, 
                        2 => 0.25, 
                        3 => 0.35, 
                        _ => 0.45, 
                    };
                    
                    analyses[idx].confidence.overall = (analyses[idx].confidence.overall - penalty).max(0.0);
                    
                    
                    if analyses[idx].confidence.overall < 0.5 {
                        analyses[idx].confidence.trust_level = rust_probe::core::TrustLevel::VidPidSpoofed;
                    } else if analyses[idx].confidence.overall < 0.75 {
                        analyses[idx].confidence.trust_level = rust_probe::core::TrustLevel::BoardModified;
                    }
                }
            } else {
                
                
                let anomaly = Anomaly::new(AnomalyType::DuplicateVidPid, "System")
                    .with_severity(AnomalySeverity::Info)
                    .with_details(format!(
                        "Múltiplos dispositivos idênticos ({}) detectados (VID:0x{:04X} PID:0x{:04X}) - Características coincidem, provavelmente legítimo",
                        indices.len(), vid, pid
                    ));
                
                for &idx in indices {
                    analyses[idx].anomalies.push(anomaly.clone());
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

fn run_collection_mode(context: &Context, debug_mode: bool) {
    let mut collector = FingerprintCollector::new("data/collected_fingerprints.json");
    let mut analyzer = DeviceAnalyzer::new();
    
    println!("Este modo coleta fingerprints de dispositivos GENUÍNOS para o banco de dados.");
    println!("Use apenas com dispositivos que você SABE que são legítimos!\n");
    
    let devices = match context.devices() {
        Ok(devs) => devs,
        Err(e) => {
            error!("Erro ao listar dispositivos: {}", e);
            pause();
            return;
        }
    };
    
    let mut device_list = Vec::new();
    
    for (idx, device) in devices.iter().enumerate() {
        if let Ok(desc) = device.device_descriptor() {
            let vid = desc.vendor_id();
            let pid = desc.product_id();
            
            if debug_mode || should_analyze(vid, pid, false) {
                device_list.push((idx + 1, device, vid, pid));
            }
        }
    }
    
    if device_list.is_empty() {
        println!("Nenhum dispositivo encontrado para coleta.");
        pause();
        return;
    }
    
    println!("Dispositivos disponíveis para coleta:\n");
    for (idx, _, vid, pid) in &device_list {
        println!("  {}. VID:0x{:04X} PID:0x{:04X}", idx, vid, pid);
    }
    
    println!("\nDigite o número do dispositivo para coletar (ou 0 para sair): ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    let choice: usize = match input.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Entrada inválida!");
            pause();
            return;
        }
    };
    
    if choice == 0 || choice > device_list.len() {
        println!("Saindo...");
        return;
    }
    
    let (_, device, vid, pid) = &device_list[choice - 1];
    
    println!("\nAnalisando dispositivo VID:0x{:04X} PID:0x{:04X}...", vid, pid);
    
    match analyzer.analyze(device) {
        Ok(analysis) => {
            println!("\n{}", "Análise concluída!".green());
            println!("  Interfaces: {}", analysis.structural.topology.num_interfaces);
            println!("  Endpoints: {}", analysis.structural.topology.endpoint_addresses.len());
            if let Some(ref stack) = analysis.stack.detected_stack {
                println!("  Stack: {}", stack.as_str());
            }
            
            println!("\nEste dispositivo é GENUÍNO? (s/n): ");
            io::stdout().flush().unwrap();
            
            let mut genuine_input = String::new();
            io::stdin().read_line(&mut genuine_input).unwrap();
            let is_genuine = genuine_input.trim().to_lowercase() == "s";
            
            println!("\nNome do dispositivo (ex: Mouse Gamer XYZ): ");
            io::stdout().flush().unwrap();
            
            let mut name_input = String::new();
            io::stdin().read_line(&mut name_input).unwrap();
            let device_name = name_input.trim();
            
            println!("\nNotas adicionais (opcional): ");
            io::stdout().flush().unwrap();
            
            let mut notes_input = String::new();
            io::stdin().read_line(&mut notes_input).unwrap();
            let notes = notes_input.trim();
            
            collector.collect_from_analysis(&analysis, device_name, is_genuine, notes);
            
            match collector.save() {
                Ok(_) => println!("\n{}", "Fingerprint salvo com sucesso!".green().bold()),
                Err(e) => println!("\n{}", format!("Erro ao salvar: {}", e).red()),
            }
            
            println!("\nTotal de fingerprints no banco: {}", 
                     collector.get_genuine_fingerprints().len() + collector.get_spoofed_fingerprints().len());
            println!("  Genuínos: {}", collector.get_genuine_fingerprints().len());
            println!("  Spoofed: {}", collector.get_spoofed_fingerprints().len());
        }
        Err(e) => {
            error!("Falha ao analisar dispositivo: {}", e);
        }
    }
    
    pause();
}

