use hardware_config::HardwareConfig;
use validation_generator::MacValidationGenerator;
use serde::{Deserialize, Serialize};
use std::io::{stdin, stdout, BufRead, Read, Write};

pub mod validation_generator;
pub mod hardware_config;

#[derive(Serialize, Deserialize, Clone)]
struct InitialPayload {
    hardware_config: HardwareConfig,
    cert_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SessionInfoPayload {
    session_info: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ResultPayload {
    result: Vec<u8>,
}

fn main() {
    unsafe {
        let input_payload: InitialPayload =
            serde_json::from_str(&read_line()).expect("Could not parse input payload.");

        let mut validation_context = MacValidationGenerator::new();

        validation_context
            .initialize(input_payload.cert_data, input_payload.hardware_config);

        let session_data_result = SessionInfoPayload {
            session_info: validation_context
                .session_data_buffer
                .as_ref()
                .unwrap()
                .clone(),
        };

        serde_json::to_writer(stdout(), &session_data_result)
            .expect("Could not write session data buffer.");
        write_new_line();

        let session_info_payload: SessionInfoPayload =
            serde_json::from_str(&read_line()).expect("Could not read session info payload.");

        validation_context.key_establishment(session_info_payload.session_info);

        let result = validation_context.sign();
        let signed_result = ResultPayload { result };

        serde_json::to_writer(stdout(), &signed_result)
            .expect("Could not write signed result buffer.");
        write_new_line();

        validation_context.close();
    }

    fn read_line() -> String {
        let mut input = String::new();
        let stdin = stdin();
        stdin.read_line(&mut input).expect("Failed to read line");
        input.trim().to_string()
    }

    fn write_new_line() {
        let mut stdout = stdout();

        stdout
            .write_all(b"\n")
            .expect("Could not write newline to stdout.");
    }
}
