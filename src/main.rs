use pqcrypto_traits::sign::{DetachedSignature};
use pqcrypto_dilithium::dilithium3::{detached_sign, 
verify_detached_signature, keypair, PublicKey, SecretKey};
use serde::{Serialize, Deserialize};
use serde_json;
use sled;
use hex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    data: String,
    prev_hash: String,
    signature: Vec<u8>,
}

impl Block {
    fn create_block(validator_sk: &SecretKey, index: u64, data: String, 
prev_hash: String) -> Self {
        let message = format!("{}{}{}", index, data, prev_hash);
        let signature = detached_sign(message.as_bytes(), validator_sk);
        Block {
            index,
            data,
            prev_hash,
            signature: signature.as_bytes().to_vec(),
        }
    }

    fn mine_block(validator_sk: &SecretKey, last_block: &Block) -> Self {
        let new_index = last_block.index + 1;
        let new_data = format!("Block {}", new_index);
        let prev_hash = 
hex::encode(serde_json::to_string(last_block).unwrap());
        Block::create_block(validator_sk, new_index, new_data, prev_hash)
    }

    fn verify_block(&self, validator_pk: &PublicKey) -> bool {
        let message = format!("{}{}{}", self.index, self.data, 
self.prev_hash);
        
verify_detached_signature(&DetachedSignature::from_bytes(&self.signature).unwrap(), 
message.as_bytes(), validator_pk).is_ok()
    }
}

struct Blockchain {
    chain: Vec<Block>,
    db: sled::Db,
}

impl Blockchain {
    fn new() -> Self {
        let db = sled::open("blockchain_db").unwrap();
        let chain = vec![];
        Blockchain { chain, db }
    }

    fn add_block(&mut self, block: Block) {
        let key = block.index.to_string();
        let value = serde_json::to_string(&block).unwrap();
        self.db.insert(key, value.as_bytes()).unwrap();
        self.chain.push(block);
    }

    fn load_block(&self, index: u64) -> Option<Block> {
        self.db.get(index.to_string()).ok().flatten().map(|v| {
            serde_json::from_slice(&v).unwrap()
        })
    }

    fn latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }
}

async fn handle_client(mut stream: TcpStream, blockchain: 
Arc<Mutex<Blockchain>>) {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await.unwrap() > 0 {
        let request = line.trim();
        if request == "GET_CHAIN" {
            let chain = blockchain.lock().unwrap().chain.clone();
            let response = serde_json::to_string(&chain).unwrap();
            writer.write_all(response.as_bytes()).await.unwrap();
        }
        line.clear();
    }
}

async fn start_server(blockchain: Arc<Mutex<Blockchain>>) {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("Node listening on 127.0.0.1:8080");

    while let Ok((socket, _)) = listener.accept().await {
        let blockchain_clone = blockchain.clone();
        tokio::spawn(async move {
            handle_client(socket, blockchain_clone).await;
        });
    }
}

#[tokio::main]
async fn main() {
    let (public_key, private_key) = keypair();
    let mut blockchain = Blockchain::new();
    
    let genesis_block = Block::create_block(&private_key, 0, "Genesis 
Block".to_string(), "".to_string());
    blockchain.add_block(genesis_block.clone());

    let new_block = Block::mine_block(&private_key, 
blockchain.latest_block());
    blockchain.add_block(new_block.clone());

    println!("Genesis Block: {:?}", genesis_block);
    println!("New Block: {:?}", new_block);
    println!("Block Verified: {}", new_block.verify_block(&public_key));

    let blockchain = Arc::new(Mutex::new(blockchain));
    start_server(blockchain).await;
}

