use colored::*;
use crate::trust_evaluator::{DeviceAnalysis, TrustLevel};

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn print_device_report(&self, analysis: &DeviceAnalysis) {
        println!("\n{}", "=".repeat(70));
        println!("Dispositivo Detectado: Bus {} Device {}", analysis.bus, analysis.address);
        println!("{}", "=".repeat(70));
        
        println!("\nInformacoes Basicas:");
        println!("  VID:PID       : 0x{:04X}:0x{:04X}", analysis.vid, analysis.pid);
        
        if let Some(ref mfg) = analysis.manufacturer {
            println!("  Fabricante    : {}", mfg);
        }
        if let Some(ref prod) = analysis.product {
            println!("  Produto       : {}", prod);
        }
        if let Some(ref serial) = analysis.serial {
            println!("  Serial        : {}", serial);
        }

        println!("\nAnalise de Confianca:");
        
        let level_str = self.format_trust_level(&analysis.trust_level);
        println!("  Nivel         : {}", level_str);
        
        let confidence_str = self.format_confidence(analysis.confidence);
        println!("  Confianca     : {}", confidence_str);

        if !analysis.flags.is_empty() {
            println!("\nFlags Detectadas:");
            for flag in &analysis.flags {
                println!("  - {}", flag);
            }
        }

        if !analysis.descriptor_anomalies.is_empty() {
            println!("\nAnomalias nos Descritores:");
            for anomaly in &analysis.descriptor_anomalies {
                println!("  - {}", anomaly);
            }
        }

        if let Some(ref deep) = analysis.deep_analysis {
            println!("\n{}", "Analise Profunda (Estilo Vanguard):".bright_cyan().bold());
            println!("  Versao USB          : {}", deep.usb_version);
            println!("  Versao Dispositivo  : {}", deep.device_version);
            println!("  Configuracoes       : {}", deep.configuration_count);
            println!("  Interfaces          : {}", deep.interface_count);
            println!("  Endpoints           : {}", deep.endpoint_count);
            println!("  Consumo Maximo      : {} mA", deep.max_power_ma);
            
            if deep.timing_anomaly {
                println!("  [!] {}", "Anomalia de Timing Detectada (resposta lenta)".yellow());
            } else {
                println!("  [OK] Timing de resposta normal");
            }
            
            if deep.power_anomaly {
                println!("  [!] {}", "Consumo de energia anormal (>500mA)".yellow());
            } else {
                println!("  [OK] Consumo de energia normal");
            }

            if let Some(ref sig) = deep.firmware_signature {
                println!("  Assinatura Firmware : {}", sig.bright_magenta());
            }

            if !deep.endpoint_anomalies.is_empty() {
                println!("\n  Anomalias de Endpoints:");
                for anomaly in &deep.endpoint_anomalies {
                    println!("    - {}", anomaly.yellow());
                }
            }
        }

        println!("{}", "=".repeat(70));
    }

    pub fn print_statistics(&self, analyses: &[DeviceAnalysis]) {
        println!("\nEstatisticas:");
        
        let genuine = analyses.iter()
            .filter(|d| d.trust_level == TrustLevel::Genuine)
            .count();
        let modified = analyses.iter()
            .filter(|d| d.trust_level == TrustLevel::BoardModified)
            .count();
        let spoofed = analyses.iter()
            .filter(|d| d.trust_level == TrustLevel::VidPidSpoofed)
            .count();
        let deep = analyses.iter()
            .filter(|d| d.trust_level == TrustLevel::DeepModification)
            .count();
        let unknown = analyses.iter()
            .filter(|d| d.trust_level == TrustLevel::Unknown)
            .count();

        println!("  Genuinos             : {}", format!("{}", genuine).green());
        println!("  Placas Modificadas   : {}", format!("{}", modified).yellow());
        println!("  VID/PID Falsificado  : {}", format!("{}", spoofed).red());
        println!("  Modificacao Profunda : {}", format!("{}", deep).bright_red());
        println!("  Desconhecidos        : {}", format!("{}", unknown).white());
        
        println!("\n{}", "=".repeat(70));
    }

    fn format_trust_level(&self, level: &TrustLevel) -> ColoredString {
        let text = match level {
            TrustLevel::Genuine => "GENUINO",
            TrustLevel::BoardModified => "PLACA MODIFICADA",
            TrustLevel::VidPidSpoofed => "VID/PID FALSIFICADO",
            TrustLevel::DeepModification => "MODIFICACAO PROFUNDA",
            TrustLevel::Unknown => "DESCONHECIDO",
        };
        
        match level {
            TrustLevel::Genuine => text.green().bold(),
            TrustLevel::BoardModified => text.yellow().bold(),
            TrustLevel::VidPidSpoofed => text.red().bold(),
            TrustLevel::DeepModification => text.bright_red().bold(),
            TrustLevel::Unknown => text.white().bold(),
        }
    }

    fn format_confidence(&self, confidence: f32) -> ColoredString {
        let percentage = format!("{:.1}%", confidence * 100.0);
        
        if confidence > 0.8 {
            percentage.green().bold()
        } else if confidence > 0.5 {
            percentage.yellow().bold()
        } else {
            percentage.red().bold()
        }
    }
}
