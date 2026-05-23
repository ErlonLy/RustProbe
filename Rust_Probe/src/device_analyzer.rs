use rusb::{Context, Device, DeviceDescriptor, DeviceHandle, UsbContext};
use std::time::{Duration, Instant};

use crate::device_database::{
    is_known_vid, is_known_pid, is_clone_vid, is_esp32_vid, is_esp32_pid, 
    get_vendor_name, get_clone_vendor_name, is_development_board
};
use crate::trust_evaluator::{DeviceAnalysis, TrustLevel, DeepAnalysis};

pub struct DeviceScanner {
    context: Context,
}

impl DeviceScanner {
    pub fn new(context: Context) -> Self {
        Self { context }
    }

    pub fn scan_all_devices(&self) -> Result<Vec<(u16, u16, u8)>, rusb::Error> {
        let devices = self.context.devices()?;
        let mut all_devices = Vec::new();

        for device in devices.iter() {
            if let Ok(desc) = device.device_descriptor() {
                all_devices.push((desc.vendor_id(), desc.product_id(), desc.class_code()));
            }
        }

        Ok(all_devices)
    }

    pub fn scan_devices(&self) -> Result<Vec<DeviceAnalysis>, rusb::Error> {
        let devices = self.context.devices()?;
        let mut analyses = Vec::new();

        for device in devices.iter() {
            if let Ok(desc) = device.device_descriptor() {
                if self.is_potential_arduino(&device, &desc) {
                    let analysis = self.analyze_device(&device, &desc);
                    
                    let is_official = is_known_vid(desc.vendor_id()) || is_clone_vid(desc.vendor_id());
                    let has_flags = !analysis.flags.is_empty() || !analysis.descriptor_anomalies.is_empty();
                    
                    if is_official || has_flags {
                        analyses.push(analysis);
                    }
                }
            }
        }

        Ok(analyses)
    }

    fn is_potential_arduino(&self, device: &Device<Context>, desc: &DeviceDescriptor) -> bool {
        let vid = desc.vendor_id();
        let pid = desc.product_id();

        // Check known development boards
        if is_development_board(vid, pid) {
            return true;
        }

        // Deep inspection for disguised devices
        let mut has_hid = false;
        let mut has_cdc = false;
        let mut has_vendor_specific = false;
        
        if let Ok(config_desc) = device.active_config_descriptor() {
            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    let class = interface_desc.class_code();
                    match class {
                        0x03 => has_hid = true,
                        0x02 | 0x0A => has_cdc = true,
                        0xFF => has_vendor_specific = true,
                        _ => {}
                    }
                }
            }
        }

        // Suspicious combination: HID + CDC (common in Arduino emulators)
        if has_hid && has_cdc {
            return true;
        }

        // Vendor-specific class with CDC (ESP32 pattern)
        if has_vendor_specific && has_cdc {
            return true;
        }

        // Single CDC without known VID (potential disguised Arduino)
        if has_cdc && !self.is_legitimate_peripheral(vid, desc) {
            return true;
        }

        false
    }

    fn is_legitimate_peripheral(&self, vid: u16, desc: &DeviceDescriptor) -> bool {
        // List of legitimate peripheral manufacturers to reduce false positives
        let legitimate_vids = [
            0x046D, // Logitech
            0x045E, // Microsoft
            0x1532, // Razer
            0x0B05, // ASUS
            0x1B1C, // Corsair
            0x0951, // Kingston
            0x04D9, // Holtek (keyboards/mice)
            0x258A, // Gaming peripherals
            0x3151, // Gaming peripherals
        ];

        if legitimate_vids.contains(&vid) {
            return true;
        }

        // Check if device has typical peripheral characteristics
        let class = desc.class_code();
        let subclass = desc.sub_class_code();
        
        // Legitimate HID devices typically have class 0x00 at device level
        if class == 0x00 && subclass == 0x00 {
            // This is a common pattern for legitimate peripherals
            return false;
        }

        false
    }

    fn analyze_device(&self, device: &Device<Context>, desc: &DeviceDescriptor) -> DeviceAnalysis {
        let vid = desc.vendor_id();
        let pid = desc.product_id();
        
        let mut flags = Vec::new();
        let mut descriptor_anomalies = Vec::new();
        let mut confidence = 1.0;

        let (manufacturer, product, serial) = self.read_device_strings(device, desc, &mut flags, &mut confidence);

        // Run Vanguard-style deep checks
        self.detect_vanguard_anomalies(device, desc, &serial, &manufacturer, &product, &mut flags, &mut confidence);
        
        // ESP32-S3 specific detection
        self.detect_esp32_patterns(device, desc, &product, &mut flags, &mut confidence);

        let mut trust_level = self.determine_trust_level(
            vid,
            pid,
            &manufacturer,
            &product,
            &serial,
            desc,
            &mut flags,
            &mut descriptor_anomalies,
            &mut confidence,
        );

        // Adjust trust level based on anti-cheat rules for spoofed devices
        let mut has_hid = false;
        let mut has_cdc = false;
        if let Ok(config_desc) = device.active_config_descriptor() {
            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    let class = interface_desc.class_code();
                    if class == 0x03 {
                        has_hid = true;
                    } else if class == 0x02 || class == 0x0A {
                        has_cdc = true;
                    }
                }
            }
        }

        // Advanced spoofing detection with false positive reduction
        if !is_development_board(vid, pid) {
            if has_hid && has_cdc {
                // Strong indicator of Arduino emulator
                trust_level = TrustLevel::VidPidSpoofed;
            } else if !flags.is_empty() && confidence < 0.6 {
                // Multiple anomalies with low confidence
                trust_level = TrustLevel::VidPidSpoofed;
            } else if flags.len() >= 3 {
                // Three or more red flags
                trust_level = TrustLevel::VidPidSpoofed;
            }
        }

        let mut analysis = DeviceAnalysis::new(
            device.bus_number(),
            device.address(),
            vid,
            pid,
            manufacturer,
            product,
            serial,
            trust_level,
            confidence,
            flags,
            descriptor_anomalies,
        );

        if let Ok(deep) = self.perform_deep_analysis(device, desc) {
            analysis.set_deep_analysis(deep);
        }

        analysis
    }

    fn read_device_strings(
        &self,
        device: &Device<Context>,
        desc: &DeviceDescriptor,
        flags: &mut Vec<String>,
        confidence: &mut f32,
    ) -> (Option<String>, Option<String>, Option<String>) {
        match device.open() {
            Ok(handle) => {
                let timeout = Duration::from_secs(1);
                
                let manufacturer = desc.manufacturer_string_index()
                    .and_then(|_idx| {
                        handle.read_languages(timeout)
                            .ok()
                            .and_then(|langs| langs.first().copied())
                            .and_then(|lang| handle.read_manufacturer_string(lang, desc, timeout).ok())
                    });
                
                let product = desc.product_string_index()
                    .and_then(|_idx| {
                        handle.read_languages(timeout)
                            .ok()
                            .and_then(|langs| langs.first().copied())
                            .and_then(|lang| handle.read_product_string(lang, desc, timeout).ok())
                    });
                
                let serial = desc.serial_number_string_index()
                    .and_then(|_idx| {
                        handle.read_languages(timeout)
                            .ok()
                            .and_then(|langs| langs.first().copied())
                            .and_then(|lang| handle.read_serial_number_string(lang, desc, timeout).ok())
                    });

                (manufacturer, product, serial)
            }
            Err(_) => {
                flags.push("Não foi possível abrir o dispositivo para leitura".to_string());
                *confidence *= 0.8;
                (None, None, None)
            }
        }
    }

    fn detect_esp32_patterns(
        &self,
        device: &Device<Context>,
        desc: &DeviceDescriptor,
        product: &Option<String>,
        flags: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        let vid = desc.vendor_id();
        let pid = desc.product_id();

        // ESP32-S3 specific detection
        if is_esp32_vid(vid) || is_esp32_pid(pid) {
            flags.push("Placa de desenvolvimento ESP32 detectada".to_string());
            
            if vid == 0x303A {
                flags.push("VID oficial Espressif Systems confirmado".to_string());
            }

            if let Some(ref prod) = product {
                let prod_lower = prod.to_lowercase();
                if prod_lower.contains("esp32-s3") {
                    flags.push("ESP32-S3 identificado no descritor de produto".to_string());
                    *confidence *= 0.3;
                } else if prod_lower.contains("esp32") {
                    flags.push("Família ESP32 detectada".to_string());
                    *confidence *= 0.4;
                }
            }

            // Check for dual USB configuration (ESP32-S3 feature)
            if let Ok(config_desc) = device.active_config_descriptor() {
                let interface_count = config_desc.num_interfaces();
                if interface_count >= 2 {
                    flags.push(format!("Configuração USB dupla detectada ({} interfaces) - característica ESP32-S3", interface_count));
                    *confidence *= 0.5;
                }
            }
        }

        // Check for ESP32 with clone USB-Serial chips
        if (vid == 0x10C4 || vid == 0x1A86) && !is_esp32_pid(pid) {
            if let Some(ref prod) = product {
                let prod_lower = prod.to_lowercase();
                if prod_lower.contains("cp210") || prod_lower.contains("ch340") || prod_lower.contains("ch341") {
                    flags.push("Chip USB-Serial clone detectado (comum em placas ESP32 genéricas)".to_string());
                    *confidence *= 0.6;
                }
            }
        }
    }

    fn detect_vanguard_anomalies(
        &self,
        device: &Device<Context>,
        desc: &DeviceDescriptor,
        serial: &Option<String>,
        manufacturer: &Option<String>,
        product: &Option<String>,
        flags: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        let vid = desc.vendor_id();
        
        let mut has_hid = false;
        let mut has_cdc = false;
        let mut interface_count = 0;
        
        if let Ok(config_desc) = device.active_config_descriptor() {
            interface_count = config_desc.num_interfaces();
            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    let class = interface_desc.class_code();
                    if class == 0x03 {
                        has_hid = true;
                    } else if class == 0x02 || class == 0x0A {
                        has_cdc = true;
                    }
                }
            }
        }

        // 1. CDC ACM + HID Coexistence
        if has_hid && has_cdc {
            flags.push("Coexistência suspeita: Interface serial (CDC) e interface HID no mesmo dispositivo (característica de emuladores)".to_string());
            *confidence *= 0.35;
        }

        // 2. Interface count verification
        if has_hid && interface_count >= 3 && !is_known_vid(vid) {
            flags.push(format!("Quantidade suspeita de interfaces para periférico HID padrão ({} interfaces)", interface_count));
            *confidence *= 0.8;
        }

        // 3. bcdDevice signature check
        let dev_ver_raw = desc.device_version();
        let bcd_device = ((dev_ver_raw.0 as u16) << 8) | (dev_ver_raw.1 as u16);
        if has_hid && (bcd_device == 0x0100 || bcd_device == 0x0287 || bcd_device == 0x0200) && !is_known_vid(vid) {
            flags.push(format!("Versão bcdDevice (0x{:04X}) suspeita, correspondente a bootloaders de microcontroladores", bcd_device));
            *confidence *= 0.75;
        }

        // 4. Polling rate check
        let mut slow_polling = false;
        let mut max_binterval = 0;
        if let Ok(config_desc) = device.active_config_descriptor() {
            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    if interface_desc.class_code() == 0x03 {
                        for endpoint in interface_desc.endpoint_descriptors() {
                            if endpoint.transfer_type() == rusb::TransferType::Interrupt {
                                let interval = endpoint.interval();
                                if interval > max_binterval {
                                    max_binterval = interval;
                                }
                                if interval >= 4 {
                                    slow_polling = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        if slow_polling && !is_known_vid(vid) {
            flags.push(format!("Taxa de polling baixa para periférico gaming (bInterval = {} ms, esperado 1ms)", max_binterval));
            *confidence *= 0.8;
        }

        // 5. Serial number signature check
        if let Some(ref ser) = serial {
            let ser_lower = ser.to_lowercase();
            let suspicious_keywords = ["arduino", "leonardo", "teensy", "pico", "rp2", "esp32", "esp8266", "atmega"];
            
            for keyword in &suspicious_keywords {
                if ser_lower.contains(keyword) {
                    flags.push(format!("Número de série com assinatura de desenvolvimento: '{}'", ser));
                    *confidence *= 0.4;
                    break;
                }
            }
            
            let generic_serials = ["12345", "1.0", "0.01", "000000000001", "0000", "1234567890"];
            if generic_serials.contains(&ser.as_str()) {
                flags.push(format!("Número de série genérico associado a emuladores: '{}'", ser));
                *confidence *= 0.7;
            }
        }

        // 6. Manufacturer string analysis
        if let Some(ref mfg) = manufacturer {
            let mfg_lower = mfg.to_lowercase();
            let dev_keywords = ["arduino", "espressif", "teensy", "pjrc", "adafruit", "sparkfun", "seeed"];
            
            for keyword in &dev_keywords {
                if mfg_lower.contains(keyword) && !is_known_vid(desc.vendor_id()) {
                    flags.push(format!("Fabricante '{}' não corresponde ao VID 0x{:04X}", mfg, desc.vendor_id()));
                    *confidence *= 0.5;
                    break;
                }
            }
        }

        // 7. Product string analysis for hidden boards
        if let Some(ref prod) = product {
            let prod_lower = prod.to_lowercase();
            let board_keywords = ["arduino", "esp32", "esp8266", "teensy", "leonardo", "uno", "mega", "nano"];
            
            for keyword in &board_keywords {
                if prod_lower.contains(keyword) && !is_development_board(desc.vendor_id(), desc.product_id()) {
                    flags.push(format!("Produto '{}' indica placa de desenvolvimento, mas VID/PID não correspondem", prod));
                    *confidence *= 0.3;
                    break;
                }
            }
        }

        // 8. Memory descriptor analysis (advanced anti-cheat technique)
        self.analyze_memory_descriptors(device, flags, confidence);
    }

    fn determine_trust_level(
        &self,
        vid: u16,
        pid: u16,
        manufacturer: &Option<String>,
        product: &Option<String>,
        serial: &Option<String>,
        desc: &DeviceDescriptor,
        flags: &mut Vec<String>,
        anomalies: &mut Vec<String>,
        confidence: &mut f32,
    ) -> TrustLevel {
        let vid_known = is_known_vid(vid);
        let pid_known = is_known_pid(pid);

        if vid_known && pid_known {
            return self.evaluate_genuine_device(vid, manufacturer, serial, desc, flags, anomalies, confidence);
        }

        if vid_known || pid_known || is_clone_vid(vid) {
            return self.evaluate_spoofed_device(vid, vid_known, manufacturer, product, flags, confidence);
        }

        self.evaluate_deep_modification(product, desc, flags, anomalies, confidence)
    }

    fn evaluate_genuine_device(
        &self,
        vid: u16,
        manufacturer: &Option<String>,
        serial: &Option<String>,
        desc: &DeviceDescriptor,
        flags: &mut Vec<String>,
        anomalies: &mut Vec<String>,
        confidence: &mut f32,
    ) -> TrustLevel {
        if let Some(ref mfg) = manufacturer {
            if let Some(expected) = get_vendor_name(vid) {
                if !mfg.to_lowercase().contains(&expected.to_lowercase()) 
                   && !mfg.to_lowercase().contains("arduino") {
                    flags.push(format!("Fabricante '{}' não corresponde ao VID esperado", mfg));
                    *confidence *= 0.7;
                    return TrustLevel::BoardModified;
                }
            }
        }

        if let Some(ref ser) = serial {
            if ser.len() < 5 || ser.chars().all(|c| c == '0' || c == '1') {
                flags.push("Número de série suspeito (muito curto ou padrão muito simples)".to_string());
                *confidence *= 0.85;
            }
        } else {
            flags.push("Sem número de série registrado".to_string());
            *confidence *= 0.9;
        }

        self.check_descriptor_anomalies(desc, anomalies, confidence);

        if flags.is_empty() && anomalies.is_empty() {
            TrustLevel::Genuine
        } else {
            TrustLevel::BoardModified
        }
    }

    fn evaluate_spoofed_device(
        &self,
        vid: u16,
        vid_known: bool,
        manufacturer: &Option<String>,
        product: &Option<String>,
        flags: &mut Vec<String>,
        confidence: &mut f32,
    ) -> TrustLevel {
        if is_clone_vid(vid) {
            flags.push("VID de chip clone conhecido detectado".to_string());
            
            if let Some(vendor) = get_clone_vendor_name(vid) {
                flags.push(format!("Fabricante do chip clone: {}", vendor));
            }
            
            if let Some(ref prod) = product {
                if prod.to_lowercase().contains("arduino") {
                    flags.push("O produto afirma ser Arduino, mas usa chip clone USB-Serial".to_string());
                    *confidence *= 0.4;
                    return TrustLevel::VidPidSpoofed;
                }
            }
            
            *confidence *= 0.5;
            return TrustLevel::VidPidSpoofed;
        }
        
        flags.push("VID ou PID não correspondem aos padrões de hardware oficiais".to_string());
        *confidence *= 0.6;

        if let Some(ref mfg) = manufacturer {
            if mfg.to_lowercase().contains("arduino") && !vid_known {
                flags.push("O fabricante menciona 'Arduino', mas o VID não é oficial da Arduino SA".to_string());
                *confidence *= 0.5;
            }
        }

        TrustLevel::VidPidSpoofed
    }

    fn evaluate_deep_modification(
        &self,
        product: &Option<String>,
        desc: &DeviceDescriptor,
        flags: &mut Vec<String>,
        anomalies: &mut Vec<String>,
        confidence: &mut f32,
    ) -> TrustLevel {
        if let Some(ref prod) = product {
            if prod.to_lowercase().contains("arduino") {
                flags.push("O produto menciona 'Arduino', mas o VID/PID são completamente diferentes".to_string());
                flags.push("Possível modificação profunda de bootloader e descritores USB".to_string());
                *confidence *= 0.3;
                
                self.check_deep_modifications(desc, anomalies, confidence);
                
                return TrustLevel::DeepModification;
            }
        }

        if desc.class_code() == 0x02 || desc.class_code() == 0xFF {
            flags.push("Dispositivo possui características de classe de Arduino, mas sem identificação clara".to_string());
            *confidence *= 0.4;
            return TrustLevel::DeepModification;
        }

        TrustLevel::Unknown
    }

    fn check_descriptor_anomalies(
        &self,
        desc: &DeviceDescriptor,
        anomalies: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        let usb_version = desc.usb_version();
        if usb_version.0 < 2 {
            anomalies.push(format!("Versão antiga do USB: {}.{}", usb_version.0, usb_version.1));
            *confidence *= 0.95;
        }

        if desc.num_configurations() != 1 {
            anomalies.push(format!("Quantidade incomum de configurações: {}", desc.num_configurations()));
            *confidence *= 0.9;
        }

        if desc.class_code() == 0xFF {
            anomalies.push("Classe de dispositivo específica do fabricante (0xFF)".to_string());
            *confidence *= 0.95;
        }

        if desc.max_packet_size() != 8 && desc.max_packet_size() != 64 {
            anomalies.push(format!("Tamanho de pacote de controle incomum: {}", desc.max_packet_size()));
            *confidence *= 0.9;
        }
    }

    fn check_deep_modifications(
        &self,
        desc: &DeviceDescriptor,
        anomalies: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        anomalies.push("Análise de modificação profunda:".to_string());
        
        let device_version = desc.device_version();
        anomalies.push(format!("  - Versão do dispositivo: {}.{}", device_version.0, device_version.1));
        
        if desc.protocol_code() != 0 {
            anomalies.push(format!("  - Protocolo não-padrão: 0x{:02X}", desc.protocol_code()));
            *confidence *= 0.85;
        }

        if desc.sub_class_code() != 0 {
            anomalies.push(format!("  - Subclasse não-padrão: 0x{:02X}", desc.sub_class_code()));
            *confidence *= 0.85;
        }
    }

    fn perform_deep_analysis(&self, device: &Device<Context>, desc: &DeviceDescriptor) -> Result<DeepAnalysis, rusb::Error> {
        let mut endpoint_anomalies = Vec::new();
        let mut timing_anomaly = false;
        let mut power_anomaly = false;

        let config_count = desc.num_configurations();
        let usb_version = desc.usb_version();
        let device_version = desc.device_version();

        let mut endpoint_count = 0;
        let mut interface_count = 0;
        let mut max_power_ma = 0;

        if let Ok(handle) = device.open() {
            let start = Instant::now();
            let _ = handle.read_languages(Duration::from_millis(100));
            let elapsed = start.elapsed();
            
            if elapsed.as_millis() > 50 {
                timing_anomaly = true;
            }

            if let Ok(config_desc) = device.active_config_descriptor() {
                interface_count = config_desc.num_interfaces();
                max_power_ma = config_desc.max_power() as u16 * 2;

                if max_power_ma > 500 {
                    power_anomaly = true;
                }

                for interface in config_desc.interfaces() {
                    for interface_desc in interface.descriptors() {
                        endpoint_count += interface_desc.num_endpoints();

                        for endpoint in interface_desc.endpoint_descriptors() {
                            let ep_addr = endpoint.address();
                            let ep_type = endpoint.transfer_type();
                            let max_packet = endpoint.max_packet_size();

                            if max_packet > 1024 {
                                endpoint_anomalies.push(format!(
                                    "Endpoint 0x{:02X}: Tamanho de pacote anormal ({})",
                                    ep_addr, max_packet
                                ));
                            }

                            if ep_type == rusb::TransferType::Isochronous {
                                endpoint_anomalies.push(format!(
                                    "Endpoint 0x{:02X}: Tipo isocrônico (incomum em Arduino)",
                                    ep_addr
                                ));
                            }
                        }
                    }
                }
            }

            let firmware_sig = self.extract_firmware_signature(&handle);

            Ok(DeepAnalysis {
                endpoint_count,
                interface_count,
                configuration_count: config_count,
                max_power_ma,
                usb_version: format!("{}.{}", usb_version.0, usb_version.1),
                device_version: format!("{}.{}", device_version.0, device_version.1),
                timing_anomaly,
                endpoint_anomalies,
                power_anomaly,
                firmware_signature: firmware_sig,
            })
        } else {
            Ok(DeepAnalysis {
                endpoint_count: 0,
                interface_count: 0,
                configuration_count: config_count,
                max_power_ma: 0,
                usb_version: format!("{}.{}", usb_version.0, usb_version.1),
                device_version: format!("{}.{}", device_version.0, device_version.1),
                timing_anomaly: false,
                endpoint_anomalies: vec!["Não foi possível abrir o dispositivo para análise profunda".to_string()],
                power_anomaly: false,
                firmware_signature: None,
            })
        }
    }

    fn extract_firmware_signature(&self, handle: &DeviceHandle<Context>) -> Option<String> {
        let timeout = Duration::from_millis(100);
        
        if let Ok(langs) = handle.read_languages(timeout) {
            if let Some(&lang) = langs.first() {
                let mut signature = String::new();
                
                for idx in 0..10 {
                    if let Ok(string) = handle.read_string_descriptor(lang, idx, timeout) {
                        if !string.is_empty() {
                            signature.push_str(&format!("{}:", string.len()));
                        }
                    }
                }
                
                if !signature.is_empty() {
                    return Some(signature);
                }
            }
        }
        
        None
    }

    fn analyze_memory_descriptors(
        &self,
        device: &Device<Context>,
        flags: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        // Advanced anti-cheat technique: analyze descriptor memory patterns
        if let Ok(handle) = device.open() {
            let timeout = Duration::from_millis(50);
            
            // Try to read configuration descriptor multiple times
            let mut read_times = Vec::new();
            for _ in 0..3 {
                let start = Instant::now();
                let _ = handle.read_languages(timeout);
                read_times.push(start.elapsed().as_micros());
            }

            // Check for timing consistency (real hardware is consistent)
            if read_times.len() >= 3 {
                let avg = read_times.iter().sum::<u128>() / read_times.len() as u128;
                let variance: u128 = read_times.iter()
                    .map(|&t| {
                        let diff = if t > avg { t - avg } else { avg - t };
                        diff * diff
                    })
                    .sum::<u128>() / read_times.len() as u128;

                // High variance indicates emulation
                if variance > 10000 {
                    flags.push("Variação de timing alta detectada (possível emulação de hardware)".to_string());
                    *confidence *= 0.7;
                }
            }
        }
    }
}
