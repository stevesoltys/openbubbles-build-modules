use openssl::rsa::Rsa;
use openssl::x509::X509;
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};

const START_OFFSET: u64 = 0x0136d113 - 0x0100000;
const END_OFFSET: u64 = 0x01375694 - 0x0100000;
const MAGIC_NUMBERS: [u8; 3] = [0x30, 0x82, 0x02]; // OpenSSL header

const CERT_NAMES: [&str; 10] = [
    "4056631661436364584235346952193",
    "4056631661436364584235346952194",
    "4056631661436364584235346952195",
    "4056631661436364584235346952196",
    "4056631661436364584235346952197",
    "4056631661436364584235346952198",
    "4056631661436364584235346952199",
    "4056631661436364584235346952200",
    "4056631661436364584235346952201",
    "4056631661436364584235346952208",
];

fn main() {
    // Load the file into memory
    let mut file = File::open("./openbubbles.so").expect("Unable to open file");

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Unable to read file");

    let slice = &buffer[START_OFFSET as usize..END_OFFSET as usize];

    // Split by header magic numbers
    let mut parts = Vec::new();
    let mut start = 0;
    for i in 0..slice.len() {
        if slice[i] == MAGIC_NUMBERS[0]
            && slice[i + 1] == MAGIC_NUMBERS[1]
            && slice[i + 2] == MAGIC_NUMBERS[2]
        {
            if start != i {
                parts.push(&slice[start..i]); // Push the previous part
            }
            start = i; // Include the header in the next part
        }
    }
    if start != slice.len() {
        parts.push(&slice[start..]); // Push the last part
    }

    // Combine the parts into certs and keys
    let mut certs = Vec::new();
    for i in (0..parts.len()).step_by(4) {
        if i + 3 < parts.len() {
            let cert = [parts[i], parts[i + 1], parts[i + 2]].concat();
            let key = parts[i + 3].to_vec();
            certs.push((cert, key));
        }
    }

    // Validate the certs and keys using OpenSSL
    let mut index = 0;

    for (cert, key) in certs.iter() {
        let cert_pem = X509::from_der(cert).expect("Failed to parse cert");
        let key_pem = Rsa::private_key_from_der(key).expect("Failed to parse key");

        let cert_public_key = cert_pem
            .public_key()
            .unwrap()
            .public_key_to_der()
            .expect("Failed to get public key");

        let key_public_key = key_pem
            .public_key_to_der()
            .expect("Failed to get public key");

        // Validate the cert and key
        assert_eq!(cert_public_key, key_public_key);

        println!("Cert and key {} are valid", index);
        index += 1;
    }

    // Write each cert and private key to a file
    create_dir_all("target/fairplay_certs").expect("Unable to create directory");

    for (i, part) in certs.iter().enumerate() {
        let cert_name = CERT_NAMES[i];

        let mut file = File::create_new(format!("target/fairplay_certs/{cert_name}.crt"))
            .expect("Unable to create file");

        file.write_all(&part.0).expect("Unable to write data");

        let mut file = File::create_new(format!("target/fairplay_certs/{cert_name}.pem"))
            .expect("Unable to create file");
        file.write_all(&part.1).expect("Unable to write data");
    }
}
