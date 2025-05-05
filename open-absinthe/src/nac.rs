use crate::AbsintheError;
use log::{debug, info};
use plist::Data;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::alloc::{Layout, alloc, dealloc};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::raw::c_void;
use std::process::{Child, Command, Stdio};

#[derive(Serialize, Deserialize, Clone)]
pub struct InitialPayload {
    pub hardware_config: HardwareConfig,
    pub cert_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionInfoPayload {
    pub session_info: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResultPayload {
    pub result: Vec<u8>,
}

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

impl HardwareConfig {
    pub fn from_validation_data(data: &[u8]) -> Result<HardwareConfig, AbsintheError> {
        panic!("Unsupported operation");
    }
}

pub struct ValidationCtx {
    child_process: Child,
}

impl ValidationCtx {

    pub fn new(
        certs: &Vec<u8>,
        output_req: &mut Vec<u8>,
        hardware_config_pointer: &HardwareConfig,
    ) -> Result<ValidationCtx, AbsintheError> {

        // Get the Android package identifier.
        let mut app_package_name = String::new();

        File::open("/proc/self/cmdline")
            .expect("Failed to open cmdline")
            .read_to_string(&mut app_package_name)
            .expect("Failed to read cmdline");

        let app_package_name = app_package_name
            .split('\0')
            .next()
            .expect("Failed to get app package name")
            .to_string();

        let app_data_directory = format!("/data/data/{app_package_name}/files");

        // Get the native library directory.
        let mut app_native_library_directory = String::new();

        // TODO: This is awful - we need a good way to get the native library directory, maybe JNI.
        File::open(format!("{app_data_directory}/native_library_directory"))
            .expect("Failed to open cmdline")
            .read_to_string(&mut app_native_library_directory)
            .expect("Failed to read cmdline");

        // Spawn the child process
        let mut child_process = Command::new("./qemu-x86_64")
            .args(&[
                "-E".to_string(),
                "LD_LIBRARY_PATH=.".to_string(),
                "./rust-test".to_string(),
            ])
            .env("LD_LIBRARY_PATH", ".")
            .current_dir(app_native_library_directory)
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        let mut result = ValidationCtx { child_process };

        // Write the initial payload to the child's stdin
        let initial_payload = InitialPayload {
            hardware_config: hardware_config_pointer.clone(),
            cert_data: certs.clone(),
        };

        let initial_payload_json =
            serde_json::to_string(&initial_payload).expect("Failed to serialize payload");

        result
            .write_string_to_child_buffer(&initial_payload_json)
            .expect("Failed to write to child buffer");

        let initial_child_response = result
            .read_from_child_buffer()
            .expect("Failed to read from child buffer");

        let session_info_payload: SessionInfoPayload =
            serde_json::from_str(&initial_child_response)
                .expect("Failed to deserialize session info");

        output_req
            .write_all(&session_info_payload.session_info)
            .expect("Failed to write session info to output buffer");

        Ok(result)
    }

    pub fn key_establishment(&mut self, mut session_info: &Vec<u8>) -> Result<(), AbsintheError> {
        // Write Apple session info payload
        let apple_session_info_payload = SessionInfoPayload {
            session_info: session_info.clone(),
        };

        let session_info_payload_json = serde_json::to_string(&apple_session_info_payload)
            .expect("Failed to serialize payload");

        self.write_string_to_child_buffer(&session_info_payload_json)
            .expect("Failed to write to child buffer");

        Ok(())
    }

    pub fn sign(&mut self) -> Result<Vec<u8>, AbsintheError> {
        self.child_process
            .wait()
            .expect("Failed to wait for child process");

        let signed_result_payload = self
            .read_from_child_buffer()
            .expect("Failed to read from child buffer");

        let result_payload: ResultPayload = serde_json::from_str(&signed_result_payload)
            .expect("Failed to deserialize result payload");

        Ok(result_payload.result)
    }

    fn write_string_to_child_buffer(
        self: &mut ValidationCtx,
        buffer: &str,
    ) -> Result<(), std::io::Error> {
        let mut stdin = self
            .child_process
            .stdin
            .as_mut()
            .expect("Failed to open stdin");
        stdin.write_all(buffer.as_bytes())?;
        stdin.write(b"\n")?;
        stdin.flush()?;
        Ok(())
    }

    fn read_from_child_buffer(self: &mut ValidationCtx) -> Result<String, std::io::Error> {
        let mut reader = BufReader::new(self.child_process.stdout.as_mut().unwrap());
        let mut line = String::new();

        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF reached before reading any data
                let mut stderr_output = String::new();
                if let Some(mut stderr) = self.child_process.stderr.take() {
                    stderr
                        .read_to_string(&mut stderr_output)
                        .expect("Failed to read stderr");
                }
                panic!(
                    "Unexpected EOF while reading session info. Stderr: {}",
                    stderr_output
                );
            }
            Ok(_) => {
                debug!("Successfully read: {}", line);
            }
            Err(e) => {
                panic!("Failed to read from stdout: {}", e);
            }
        }

        Ok(line)
    }
}
