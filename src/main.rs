use base64;
use env_logger;
use log::{error, info};
use rand::prelude::SliceRandom;
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{Context, Digest, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

#[derive(Clone)]
struct DataNode {
    data: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl DataNode {
    fn new() -> Self {
        DataNode {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn add_content(&self, content: Vec<u8>) -> Digest {
        let mut context = Context::new(&SHA256);
        context.update(&content);
        let digest = context.finish();
        let hash = digest.as_ref().to_vec();
        self.data.write().unwrap().insert(hash.clone(), content);
        digest
    }

    fn get_content(&self, hash: &[u8]) -> Option<Vec<u8>> {
        self.data.read().unwrap().get(hash).cloned()
    }
}

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
    info!("Raw data before encryption: {:?}", data);
    info!("Encrypting data with nonce: {:?}", nonce_bytes);
    match key.seal_in_place_append_tag(nonce, aad, &mut buffer) {
        Ok(_) => info!("Data encrypted successfully"),
        Err(e) => error!("Encryption failed: {:?}", e),
    };
    let encrypted_data = [nonce_bytes.as_slice(), buffer.as_slice()].concat();
    info!("Encrypted data: {:?}", encrypted_data);
    encrypted_data
}

fn decrypt_data(key: &LessSafeKey, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        error!("Data length less than nonce length");
        return None;
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).ok()?;
    let aad = Aad::empty();
    let mut buffer = ciphertext.to_vec();
    info!("Decrypting data with nonce: {:?}", nonce_bytes);
    match key.open_in_place(nonce, aad, &mut buffer) {
        Ok(decrypted_data) => {
            info!("Data decrypted successfully");
            let valid_utf8 = decrypted_data.iter().all(|&b| b.is_ascii());
            if valid_utf8 {
                info!("Valid ASCII data: {:?}", decrypted_data);
                Some(decrypted_data.to_vec())
            } else {
                error!("Invalid ASCII data detected: {:?}", decrypted_data);
                None
            }
        }
        Err(e) => {
            error!("Decryption failed: {:?}", e);
            None
        }
    }
}

fn handle_client(mut stream: TcpStream, node: DataNode, encryption_key: Arc<LessSafeKey>) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(size) => {
            info!("Received {} bytes from client", size);
            info!("Raw received data: {:?}", &buffer[..size]);
            if let Some(decrypted_data) = decrypt_data(&encryption_key, &buffer[..size]) {
                info!("Decrypted data: {:?}", decrypted_data);
                if let Ok(decrypted_string) = String::from_utf8(decrypted_data.clone()) {
                    info!("Decrypted string: {}", decrypted_string);
                } else {
                    error!("Failed to convert decrypted data to string");
                }
                let hex_data: Vec<String> = decrypted_data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                info!("Hex data: {:?}", hex_data);
                let request: Request = match serde_json::from_slice(&decrypted_data) {
                    Ok(req) => req,
                    Err(e) => {
                        error!("Failed to parse request: {:?}", e);
                        return;
                    }
                };
                info!("Parsed request: {:?}", request);
                match request.command.as_str() {
                    "GET" => {
                        if let Some(hash_hex) = request.hash {
                            let hash = match hex::decode(hash_hex) {
                                Ok(h) => h,
                                Err(e) => {
                                    error!("Failed to decode hash: {:?}", e);
                                    return;
                                }
                            };
                            if let Some(content) = node.get_content(&hash) {
                                let response = encrypt_data(&encryption_key, &content);
                                stream.write_all(&response).unwrap();
                                info!("Sent encrypted response: {:?}", response);
                            }
                        }
                    }
                    "PUT" => {
                        if let Some(content_base64) = request.data {
                            let content = match base64::decode(content_base64) {
                                Ok(c) => c,
                                Err(e) => {
                                    error!("Failed to decode base64 content: {:?}", e);
                                    return;
                                }
                            };
                            let hash = node.add_content(content);
                            let response =
                                encrypt_data(&encryption_key, &hex::encode(hash).as_bytes());
                            stream.write_all(&response).unwrap();
                            info!("Sent encrypted response: {:?}", response);
                        }
                    }
                    _ => {
                        error!("Unknown command");
                    }
                }
            } else {
                error!("Failed to decrypt data");
            }
        }
        Err(e) => {
            error!("Failed to read from stream: {:?}", e);
        }
    }
}

fn start_server(address: &str, node: DataNode, encryption_key: Arc<LessSafeKey>) {
    let listener = TcpListener::bind(address).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let node = node.clone();
                let encryption_key = encryption_key.clone();
                thread::spawn(move || {
                    handle_client(stream, node, encryption_key);
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {:?}", e);
            }
        }
    }
}

fn gossip(node: DataNode, peers: Vec<String>, encryption_key: Arc<LessSafeKey>) {
    let mut rng = rand::thread_rng();
    loop {
        let peer = peers.choose(&mut rng).unwrap();
        if let Ok(mut stream) = TcpStream::connect(peer) {
            let data = node.data.read().unwrap();
            for (hash, content) in data.iter() {
                let message = Request {
                    command: "PUT".to_string(),
                    data: Some(base64::encode(content)),
                    hash: Some(hex::encode(hash)),
                };

                let serialized_message = serde_json::to_vec(&message).unwrap();
                let encrypted_message = encrypt_data(&encryption_key, &serialized_message);
                stream.write_all(&encrypted_message).unwrap();
                info!("Sent encrypted gossip message: {:?}", encrypted_message);
            }
        }
        thread::sleep(Duration::from_secs(10));
    }
}

fn main() {
    env_logger::init();

    let node = DataNode::new();
    let key_bytes = [0; 32];
    let encryption_key = Arc::new(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap(),
    ));

    let peers = vec!["127.0.0.1:8001".to_string(), "127.0.0.1:8002".to_string()];

    let node_clone = node.clone();
    let encryption_key_clone = encryption_key.clone();

    thread::spawn(move || {
        start_server("127.0.0.1:8000", node_clone, encryption_key_clone);
    });

    gossip(node, peers, encryption_key);
}
