//! bitcoin wallet

use super::*;
use bincode::{deserialize, serialize};
use bitcoincash_addr::*;
use crypto::digest::Digest;
use crypto::ed25519;
use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sled;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

// 钱包中存放真地址和对应的公钥私钥对
pub struct Wallets {
    wallets: HashMap<String, KeyPair>,
}

impl KeyPair {
    // 新建并返回公钥私钥对
    fn new() -> Self {
        let mut key: [u8; 32] = [0; 32];
        let mut rand = rand::OsRng::new().unwrap();
        rand.fill_bytes(&mut key);
        let (private_key, public_key) = ed25519::keypair(&key);
        let private_key = private_key.to_vec();
        let public_key = public_key.to_vec();
        KeyPair {
            private_key,
            public_key,
        }
    }

    // 根据公钥生成地址
    pub fn get_address(&self) -> String {
        let mut pub_hash: Vec<u8> = self.public_key.clone();
        hash_pub_key(&mut pub_hash);
        let address = Address {
            body: pub_hash,
            scheme: Scheme::Base58,
            hash_type: HashType::Script,
            ..Default::default()
        };
        address.encode().unwrap()
    }
}

//  生成地址中的body
pub fn hash_pub_key(pubKey: &mut Vec<u8>) {
    let mut hasher1 = Sha256::new();
    hasher1.input(pubKey);
    hasher1.result(pubKey);
    let mut hasher2 = Ripemd160::new();
    hasher2.input(pubKey);
    pubKey.resize(20, 0);
    hasher2.result(pubKey);
}

impl Wallets {
    // 获取本地钱包
    pub fn new() -> Result<Wallets> {
        let mut wlt = Wallets {
            wallets: HashMap::<String, KeyPair>::new(),
        };
        let db = sled::open("data/wallets")?;

        for item in db.into_iter() {
            let i = item?;
            let address = String::from_utf8(i.0.to_vec())?;
            let KeyPair = deserialize(&i.1.to_vec())?;
            wlt.wallets.insert(address, KeyPair);
        }
        drop(db);
        Ok(wlt)
    }

    // 向钱包中添加地址和对应的公钥私钥对
    pub fn create_wallet(&mut self) -> String {
        let keypair = KeyPair::new();
        let address = keypair.get_address();
        self.wallets.insert(address.clone(), keypair);
        info!("create wallet: {}", address);
        address
    }

    //  返回钱包中的所有地址
    pub fn get_all_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::<String>::new();
        for (address, _) in &self.wallets {
            addresses.push(address.clone());
        }
        addresses
    }

    // 根据地址返回对应的公钥私钥对
    pub fn get_wallet(&self, address: &str) -> Option<&KeyPair> {
        self.wallets.get(address)
    }

    //  存储钱包到本地
    pub fn save_all(&self) -> Result<()> {
        let db = sled::open("data/wallets")?;

        for (address, wallet) in &self.wallets {
            let data = serialize(wallet)?;
            db.insert(address, data)?;
        }

        db.flush()?;
        drop(db);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_wallet_and_hash() {
        let w1 = KeyPair::new();
        let w2 = KeyPair::new();
        assert_ne!(w1, w2);
        assert_ne!(w1.get_address(), w2.get_address());

        let mut p2 = w2.public_key.clone();
        hash_pub_key(&mut p2);
        assert_eq!(p2.len(), 20);
        let pub_key_hash = Address::decode(&w2.get_address()).unwrap().body;
        assert_eq!(pub_key_hash, p2);
    }

    #[test]
    fn test_wallets() {
        let mut ws = Wallets::new().unwrap();
        let wa1 = ws.create_wallet();
        let w1 = ws.get_wallet(&wa1).unwrap().clone();
        ws.save_all().unwrap();

        let ws2 = Wallets::new().unwrap();
        let w2 = ws2.get_wallet(&wa1).unwrap();
        assert_eq!(&w1, w2);
    }

    #[test]
    #[should_panic]
    fn test_wallets_not_exist() {
        let w3 = KeyPair::new();
        let ws2 = Wallets::new().unwrap();
        ws2.get_wallet(&w3.get_address()).unwrap();
    }

    #[test]
    fn test_signature() {
        let w = KeyPair::new();
        let signature = ed25519::signature("test".as_bytes(), &w.private_key);
        assert!(ed25519::verify(
            "test".as_bytes(),
            &w.public_key,
            &signature
        ));
    }
}
