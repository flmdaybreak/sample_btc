//! unspend transaction output set

use super::*;
use crate::block::*;
use crate::blockchain::*;
use crate::transaction::*;
use bincode::{deserialize, serialize};
use sled;
use std::collections::HashMap;

//  UTXO集
pub struct UTXOSet {
    pub blockchain: Blockchain,
}

impl UTXOSet {
    //  找到可以用作为交易输入（花销）的交易输出
    pub fn find_spendable_outputs(
        &self,
        pub_key_hash: &[u8],
        amount: i32,
    ) -> Result<(i32, HashMap<String, Vec<i32>>)> {
        let mut unspent_outputs: HashMap<String, Vec<i32>> = HashMap::new();
        let mut accumulated = 0;

        let db = sled::open("data/utxos")?;
        for kv in db.iter() {
            let (k, v) = kv?;
            let txid = String::from_utf8(k.to_vec())?;
            let outs: TXOutputs = deserialize(&v.to_vec())?;

            for out_idx in 0..outs.outputs.len() {
                if outs.outputs[out_idx].is_locked_with_key(pub_key_hash) && accumulated < amount {
                    accumulated += outs.outputs[out_idx].value;
                    match unspent_outputs.get_mut(&txid) {
                        Some(v) => v.push(out_idx as i32),
                        None => {
                            unspent_outputs.insert(txid.clone(), vec![out_idx as i32]);
                        }
                    }
                }
            }
        }

        Ok((accumulated, unspent_outputs))
    }

    //  根据公钥寻找UTXO
    pub fn find_UTXO(&self, pub_key_hash: &[u8]) -> Result<TXOutputs> {
        let mut utxos = TXOutputs {
            outputs: Vec::new(),
        };
        let db = sled::open("data/utxos")?;

        for kv in db.iter() {
            let (_, v) = kv?;
            let outs: TXOutputs = deserialize(&v.to_vec())?;

            for out in outs.outputs {
                if out.is_locked_with_key(pub_key_hash) {
                    utxos.outputs.push(out.clone())
                }
            }
        }

        Ok(utxos)
    }

    //  遍历UTXO集合并返回数量
    pub fn count_transactions(&self) -> Result<i32> {
        let mut counter = 0;
        let db = sled::open("data/utxos")?;
        for kv in db.iter() {
            kv?;
            counter += 1;
        }
        Ok(counter)
    }

    //  重建UTXO集
    pub fn reindex(&self) -> Result<()> {
        std::fs::remove_dir_all("data/utxos").ok();
        let db = sled::open("data/utxos")?;

        let utxos = self.blockchain.find_UTXO();

        for (txid, outs) in utxos {
            db.insert(txid.as_bytes(), serialize(&outs)?)?;
        }

        Ok(())
    }

    //  根据新加入的区块更新UTXO集
    pub fn update(&self, block: &Block) -> Result<()> {
        let db = sled::open("data/utxos")?;

        for tx in block.get_transaction() {
            if !tx.is_coinbase() {
                for vin in &tx.vin {
                    let mut update_outputs = TXOutputs {
                        outputs: Vec::new(),
                    };
                    let outs: TXOutputs = deserialize(&db.get(&vin.txid)?.unwrap().to_vec())?;
                    for out_idx in 0..outs.outputs.len() {
                        if out_idx != vin.vout as usize {
                            update_outputs.outputs.push(outs.outputs[out_idx].clone());
                        }
                    }

                    if update_outputs.outputs.is_empty() {
                        db.remove(&vin.txid)?;
                    } else {
                        db.insert(vin.txid.as_bytes(), serialize(&update_outputs)?)?;
                    }
                }
            }

            let mut new_outputs = TXOutputs {
                outputs: Vec::new(),
            };
            for out in &tx.vout {
                new_outputs.outputs.push(out.clone());
            }

            db.insert(tx.id.as_bytes(), serialize(&new_outputs)?)?;
        }
        Ok(())
    }
}
