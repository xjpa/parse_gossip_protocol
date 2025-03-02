use base64;
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
struct Request {
    command: String,
    data: Option<String>,
    hash: Option<String>,
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    nonce_bytes
}

fn encrypt_data(key: &LessSafeKey, data: &[u8]) -> Vec<u8> {
    let mut buffer = data.to_vec();
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::empty();
    println!("Raw data before encryption: {:?}", data);
    println!("Encrypting data with nonce: {:?}", nonce_bytes);
    match key.seal_in_place_append_tag(nonce, aad, &mut buffer) {
        Ok(_) => println!("Data encrypted successfully"),
        Err(e) => panic!("Encryption failed: {:?}", e),
    };
    let encrypted_data = [nonce_bytes.as_slice(), buffer.as_slice()].concat();
    println!("Encrypted data: {:?}", encrypted_data);
    encrypted_data
}

fn decrypt_data(key: &LessSafeKey, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).ok()?;
    let aad = Aad::empty();
    let mut buffer = ciphertext.to_vec();
    println!("Decrypting data with nonce: {:?}", nonce_bytes);
    match key.open_in_place(nonce, aad, &mut buffer) {
        Ok(plaintext) => {
            println!("Data decrypted successfully");
            Some(plaintext.to_vec())
        }
        Err(e) => {
            println!("Decryption failed: {:?}", e);
            None
        }
    }
}

fn send_put_request(key: Arc<LessSafeKey>) -> String {
    let request = Request {
        command: "PUT".to_string(),
        data: Some(base64::encode("Hello, World!")),
        hash: None,
    };

    let serialized_request = serde_json::to_vec(&request).unwrap();
    let encrypted_request = encrypt_data(&key, &serialized_request);

    let mut stream = TcpStream::connect("127.0.0.1:8000").unwrap();
    stream.write_all(&encrypted_request).unwrap();

    let mut response = vec![0; 1024];
    let size = stream.read(&mut response).unwrap();
    if let Some(decrypted_response) = decrypt_data(&key, &response[..size]) {
        // received raw bytes before attempting UTF-8 conversion
        println!("Received raw decrypted response: {:?}", decrypted_response);
        // trimming the decrypted response
        let trimmed_response: Vec<u8> = decrypted_response
            .clone()
            .into_iter()
            .filter(|&x| x != 0)
            .collect();
        match String::from_utf8(trimmed_response) {
            Ok(hash) => {
                println!("Received hash from server: {}", hash);
                hash.trim().to_string()
            }
            Err(e) => {
                println!("Failed to convert decrypted data to string");
                println!("Invalid UTF-8 bytes: {:?}", decrypted_response);
                println!("Error: {:?}", e);
                panic!("UTF-8 conversion error");
            }
        }
    } else {
        panic!("Failed to decrypt response from server");
    }
}

fn send_get_request(key: Arc<LessSafeKey>, hash: &str) {
    let request = Request {
        command: "GET".to_string(),
        data: None,
        hash: Some(hash.to_string()),
    };

    let serialized_request = serde_json::to_vec(&request).unwrap();
    let encrypted_request = encrypt_data(&key, &serialized_request);

    let mut stream = TcpStream::connect("127.0.0.1:8000").unwrap();
    stream.write_all(&encrypted_request).unwrap();

    let mut response = vec![0; 1024];
    let size = stream.read(&mut response).unwrap();
    if let Some(decrypted_response) = decrypt_data(&key, &response[..size]) {
        // received raw bytes before attempting UTF-8 conversion
        println!("Received raw decrypted response: {:?}", decrypted_response);
        // trimming decrypted response
        let trimmed_response: Vec<u8> = decrypted_response
            .clone()
            .into_iter()
            .filter(|&x| x != 0)
            .collect();
        if let Ok(data) = String::from_utf8(trimmed_response) {
            println!("Decrypted response: {}", data);
        } else {
            println!("Failed to convert decrypted response to UTF-8");
        }
    } else {
        println!("Failed to decrypt response");
    }
}

fn main() {
    let key_bytes = [0; 32];
    let encryption_key = Arc::new(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap(),
    ));

    // for PUT request, capture the hash from the response
    let hash = send_put_request(encryption_key.clone());

    // GET request using the captured hash
    send_get_request(encryption_key, &hash);
}
