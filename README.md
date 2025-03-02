just playing around with rust, building a simple secured storage with gossip protocol

i may come back to this project later to add more

for now it's a prototype for a cryptographically secure distributed gossip protocol designed for real-time data replication and collaboration. leverages [content-addressable storage (CAS)](https://en.wikipedia.org/wiki/Content-addressable_storage) principles to ensure data integrity, using SHA-256 hashing to identify content, and uses AES-256-GCM encryption (via [ring crate](https://docs.rs/ring/latest/ring/aead/index.html)) to secure all communications between nodes

```
RUST_LOG=info cargo run --bin parse_gossip_protocol

RUST_LOG=info cargo run --bin client
```
