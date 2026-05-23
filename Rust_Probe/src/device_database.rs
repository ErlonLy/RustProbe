pub const ARDUINO_VIDS: &[(u16, &str)] = &[
    (0x2341, "Arduino SA"),
    (0x2A03, "dog hunter AG"),
    (0x1B4F, "SparkFun"),
];

pub const CLONE_VIDS: &[(u16, &str)] = &[
    (0x0403, "FTDI"),
    (0x10C4, "Silicon Labs"),
    (0x1A86, "QinHeng Electronics (CH340)"),
    (0x067B, "Prolific Technology (PL2303)"),
];

pub const ESP32_VIDS: &[(u16, &str)] = &[
    (0x303A, "Espressif Systems"),
    (0x10C4, "Silicon Labs (ESP32 CP2102)"),
    (0x1A86, "QinHeng (ESP32 CH340)"),
];

pub const ARDUINO_PIDS: &[(u16, &str)] = &[
    (0x0043, "Arduino Uno Rev3"),
    (0x0001, "Arduino Uno"),
    (0x0042, "Arduino Mega 2560 Rev3"),
    (0x0010, "Arduino Mega 2560"),
    (0x8036, "Arduino Leonardo"),
    (0x0036, "Arduino Leonardo Bootloader"),
    (0x8037, "Arduino Micro"),
    (0x0037, "Arduino Micro Bootloader"),
    (0x804D, "Arduino Zero"),
    (0x004D, "Arduino Zero Bootloader"),
    (0x8057, "Arduino Nano 33 IoT"),
];

pub const ESP32_PIDS: &[(u16, &str)] = &[
    (0x1001, "ESP32-S3 USB JTAG/Serial"),
    (0x0002, "ESP32-S2 Native USB"),
    (0x0003, "ESP32-S3 Native USB"),
    (0x1000, "ESP32-C3 USB JTAG/Serial"),
    (0xEA60, "CP2102 (ESP32)"),
    (0x7523, "CH340 (ESP32)"),
];

pub const TEENSY_VIDS: &[(u16, &str)] = &[
    (0x16C0, "PJRC (Teensy)"),
];

pub const TEENSY_PIDS: &[(u16, &str)] = &[
    (0x0483, "Teensy 2.0"),
    (0x0486, "Teensy 3.x/4.x"),
    (0x0478, "Teensy LC"),
];

pub fn is_known_vid(vid: u16) -> bool {
    ARDUINO_VIDS.iter().any(|(v, _)| *v == vid)
}

pub fn is_clone_vid(vid: u16) -> bool {
    CLONE_VIDS.iter().any(|(v, _)| *v == vid)
}

pub fn is_esp32_vid(vid: u16) -> bool {
    ESP32_VIDS.iter().any(|(v, _)| *v == vid)
}

pub fn is_teensy_vid(vid: u16) -> bool {
    TEENSY_VIDS.iter().any(|(v, _)| *v == vid)
}

pub fn is_known_pid(pid: u16) -> bool {
    ARDUINO_PIDS.iter().any(|(p, _)| *p == pid)
}

pub fn is_esp32_pid(pid: u16) -> bool {
    ESP32_PIDS.iter().any(|(p, _)| *p == pid)
}

pub fn is_teensy_pid(pid: u16) -> bool {
    TEENSY_PIDS.iter().any(|(p, _)| *p == pid)
}

pub fn get_vendor_name(vid: u16) -> Option<&'static str> {
    ARDUINO_VIDS.iter()
        .find(|(v, _)| *v == vid)
        .map(|(_, name)| *name)
        .or_else(|| ESP32_VIDS.iter()
            .find(|(v, _)| *v == vid)
            .map(|(_, name)| *name))
        .or_else(|| TEENSY_VIDS.iter()
            .find(|(v, _)| *v == vid)
            .map(|(_, name)| *name))
}

pub fn get_clone_vendor_name(vid: u16) -> Option<&'static str> {
    CLONE_VIDS.iter()
        .find(|(v, _)| *v == vid)
        .map(|(_, name)| *name)
}

pub fn get_product_name(pid: u16) -> Option<&'static str> {
    ARDUINO_PIDS.iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, name)| *name)
        .or_else(|| ESP32_PIDS.iter()
            .find(|(p, _)| *p == pid)
            .map(|(_, name)| *name))
        .or_else(|| TEENSY_PIDS.iter()
            .find(|(p, _)| *p == pid)
            .map(|(_, name)| *name))
}

pub fn is_development_board(vid: u16, pid: u16) -> bool {
    is_known_vid(vid) || is_esp32_vid(vid) || is_teensy_vid(vid) ||
    is_known_pid(pid) || is_esp32_pid(pid) || is_teensy_pid(pid) ||
    is_clone_vid(vid)
}
