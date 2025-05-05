use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct HardwareConfig {
    pub product_name: String,
    pub io_mac_address: [u8; 6],
    pub platform_serial_number: String,
    pub platform_uuid: String,
    pub root_disk_uuid: String,
    pub board_id: String,
    pub os_build_num: String,
    pub platform_serial_number_enc: Vec<u8>,
    pub platform_uuid_enc: Vec<u8>,
    pub root_disk_uuid_enc: Vec<u8>,
    pub rom: Vec<u8>,
    pub rom_enc: Vec<u8>,
    pub mlb: String,
    pub mlb_enc: Vec<u8>,
}

impl HardwareConfig {}
