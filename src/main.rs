use env_logger;
use log::error;
use rand::seq::SliceRandom;
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

#[derive(Serialize, Deserialize)]
struct Request {
    command: String,
    data: Option<Vec<u8>>,
    hash: Option<String>,
}

fn handle_client(mut stream: TcpStream, node: DataNode, encryption_key: Arc<LessSafeKey>) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(_) => {
            let nonce = Nonce::assume_unique_for_key([0u8; 12]);
            let aad = Aad::empty();
            match encryption_key.open_in_place(nonce, aad, &mut buffer) {
                Ok(decrypted_data) => {
                    let request: Request = match serde_json::from_slice(decrypted_data) {
                        Ok(req) => req,
                        Err(_) => {
                            error!("Failed to parse request");
                            return;
                        }
                    };

                    match request.command.as_str() {
                        "GET" => {
                            if let Some(hash_hex) = request.hash {
                                let hash = match hex::decode(hash_hex) {
                                    Ok(h) => h,
                                    Err(_) => {
                                        error!("Failed to decode hash");
                                        return;
                                    }
                                };
                                if let Some(content) = node.get_content(&hash) {
                                    stream.write(&content).unwrap();
                                }
                            }
                        }
                        "PUT" => {
                            if let Some(content) = request.data {
                                let hash = node.add_content(content);
                                stream.write(hex::encode(hash).as_bytes()).unwrap();
                            }
                        }
                        _ => {
                            error!("Unknown command");
                        }
                    }
                }
                Err(_) => {
                    error!("Failed to decrypt data");
                }
            }
        }
        Err(_) => {
            error!("Failed to read from stream");
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
                error!("Failed to accept connection: {}", e);
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
                    data: Some(content.clone()),
                    hash: Some(hex::encode(hash)),
                };

                let serialized_message = serde_json::to_vec(&message).unwrap();

                let mut buffer = serialized_message.clone();
                let nonce = Nonce::assume_unique_for_key([0u8; 12]);
                let aad = Aad::empty();
                encryption_key
                    .seal_in_place_append_tag(nonce, aad, &mut buffer)
                    .unwrap();

                stream.write(&buffer).unwrap();
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
