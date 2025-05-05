use crate::hardware_config::HardwareConfig;
use libloading::Library;
use std::fmt::Display;
use std::os::raw::c_void;

// x86_64 Linux Binary
// sha256 f47fbd299bf5c83449bf6485a2c00c0f059d0e059646e20c64111bc5fac84b2a
const REFERENCE_ADDRESS: usize = 0x008a39b0;
const VALIDATION_CTX_NEW_ADDRESS: usize = 0x00b897c0;
const VALIDATION_CTX_KEY_ESTABLISHMENT_ADDRESS: usize = 0x00b8b3b0;
const VALIDATION_CTX_SIGN_ADDRESS: usize = 0x00b8bb50;

pub struct MacValidationGenerator {
    pub library: Library,
    pub base_library_pointer: usize,
    pub validation_ctx_data_buffer: Option<Vec<u8>>,
    pub session_data_buffer: Option<Vec<u8>>,
}

impl MacValidationGenerator {

    pub unsafe fn new() -> MacValidationGenerator {
        let openbubbles_library = Library::new("openbubbles.so").unwrap();

        let reference_symbol: libloading::Symbol<unsafe extern "C" fn()> =
            openbubbles_library.get(b"dart_fn_deliver_output").unwrap();

        let reference_function = reference_symbol.try_as_raw_ptr().unwrap();
        let base_library_address = reference_function.wrapping_sub(REFERENCE_ADDRESS) as usize;

        MacValidationGenerator {
            library: openbubbles_library,
            base_library_pointer: base_library_address,
            validation_ctx_data_buffer: None,
            session_data_buffer: None,
        }
    }

    pub fn close(self) {
        self.library.close().unwrap();
    }

    pub unsafe fn initialize(
        &mut self,
        mut certs: Vec<u8>,
        hardware_config_pointer: HardwareConfig,
    ) {

        let function_address = self
            .base_library_pointer
            .wrapping_add(VALIDATION_CTX_NEW_ADDRESS);

        // cert_chain: &[u8], out_request_bytes: &mut Vec<u8>, hw_config: &HardwareConfig
        let create_validation_context: unsafe extern "C" fn(
            first: *const c_void,
            second: *const c_void,
            third: *const c_void,
            fourth: *const c_void,
            fifth: *const c_void,
        ) = std::mem::transmute(function_address);

        let mut session_info_buffer: Vec<u8> = vec![0; 500000];
        let mut function_result_buffer: Vec<u8> = vec![0; 500000];

        create_validation_context(
            function_result_buffer.as_mut_ptr() as *const c_void,
            certs.as_mut_ptr() as *const c_void,
            certs.as_mut_ptr().add(certs.len()) as *const c_void,
            session_info_buffer.as_mut_ptr() as *const c_void,
            &hardware_config_pointer.clone() as *const _ as *const c_void,
        );

        let session_info_output_u64s: Vec<u64> =
            std::slice::from_raw_parts(session_info_buffer.as_ptr(), 1024)
                .chunks_exact(8)
                .map(|chunk| u64::from_ne_bytes(chunk.try_into().unwrap()))
                .collect();

        let session_info_output_memory_address = session_info_output_u64s[1] as *const u8;
        let length = session_info_output_u64s[2] as usize;

        let mut copied_session_info_bytes: Vec<u8> = vec![0; length];

        std::ptr::copy_nonoverlapping(
            session_info_output_memory_address,
            copied_session_info_bytes.as_mut_ptr(),
            length,
        );

        self.validation_ctx_data_buffer = Option::from(function_result_buffer);
        self.session_data_buffer = Option::from(copied_session_info_bytes);
    }

    pub unsafe fn key_establishment(&mut self, session_info: Vec<u8>) {

        let function_address = self
            .base_library_pointer
            .wrapping_add(VALIDATION_CTX_KEY_ESTABLISHMENT_ADDRESS);

        // &mut self, response: &[u8]
        let key_establishment: unsafe extern "C" fn(
            first: *mut c_void,
            second: *mut c_void,
            third: *mut c_void,
            fourth: *mut c_void,
        ) -> *const c_void = std::mem::transmute(function_address);

        let mut function_result_buffer: Vec<u8> = vec![0; 500000];

        let mut updated_validation_ctx_buffer =
            self.validation_ctx_data_buffer.clone().unwrap();

        key_establishment(
            function_result_buffer.as_mut_ptr() as *mut c_void,
            updated_validation_ctx_buffer.as_mut_ptr() as *mut c_void,
            session_info.clone().as_mut_ptr() as *mut c_void,
            session_info.len() as *mut c_void,
        );

        self.validation_ctx_data_buffer = Some(updated_validation_ctx_buffer);
    }

    pub unsafe fn sign(&mut self) -> Vec<u8> {

        let function_address = self
            .base_library_pointer
            .wrapping_add(VALIDATION_CTX_SIGN_ADDRESS);

        // &mut self
        let sign: unsafe extern "C" fn(
            first: *mut c_void,
            second: *mut c_void,
        ) -> *const c_void = std::mem::transmute(function_address);

        let mut function_result_buffer: Vec<u8> = vec![0; 500000];

        let mut updated_validation_ctx_buffer =
            self.validation_ctx_data_buffer.clone().unwrap();

        sign(
            function_result_buffer.as_mut_ptr() as *mut c_void,
            updated_validation_ctx_buffer.as_mut_ptr() as *mut c_void,
        );

        self.validation_ctx_data_buffer = Some(updated_validation_ctx_buffer);

        let function_result_u64s: Vec<u64> =
            std::slice::from_raw_parts(function_result_buffer.as_ptr(), 1024)
                .chunks_exact(8)
                .map(|chunk| u64::from_ne_bytes(chunk.try_into().unwrap()))
                .collect();

        let sign_result_memory_address = function_result_u64s[2];
        let sign_result_length = function_result_u64s[3] as usize;

        let mut sign_result: Vec<u8> = vec![0; sign_result_length];

        std::ptr::copy_nonoverlapping(
            sign_result_memory_address as *const u8,
            sign_result.as_mut_ptr(),
            sign_result_length,
        );

        sign_result
    }
}
