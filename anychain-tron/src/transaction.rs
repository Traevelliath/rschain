use std::fmt;
use std::str::FromStr;

use anychain_core::libsecp256k1::SecretKey;
use protobuf::Message;

use anychain_core::ethereum_types::U256;
use anychain_core::utilities::crypto;
use anychain_core::TransactionError;
use anychain_core::TransactionId;
use anychain_core::{libsecp256k1, Transaction};

use crate::abi::{contract_function_call, Param};
use crate::protocol::tron::transaction::{Contract, Raw as TransactionRaw};
use crate::protocol::tron::Transaction as TransactionProto;
use crate::trx;
use crate::{TronAddress, TronFormat, TronPublicKey};

/// Represents the parameters for a Tron transaction
#[derive(Debug, Clone, PartialEq)]
pub struct TronTransactionParameters {
    ref_block_hash: Vec<u8>,
    ref_block_bytes: Vec<u8>,
    fee_limit: i64,
    expiration: i64,
    timestamp: i64,
    memo: String,
    contract: Contract,
}

impl TronTransactionParameters {
    fn with_ref_block_raw(mut self, block_bytes: Vec<u8>, hash: Vec<u8>) -> Self {
        self.ref_block_bytes = block_bytes;
        self.ref_block_hash = hash;
        self
    }

    pub fn with_ref_block(mut self, number: i64, hash: impl AsRef<str>) -> Self {
        self.ref_block_bytes = vec![((number & 0xff00) >> 8) as u8, (number & 0xff) as u8];
        hex::decode(hash.as_ref()).unwrap()[8..16].clone_into(&mut self.ref_block_hash);
        self
    }

    pub fn with_contract(mut self, ct: Contract) -> Self {
        self.contract = ct;
        self
    }

    pub fn with_timestamp(mut self, time: i64) -> Self {
        self.timestamp = time;
        self
    }

    pub fn with_expiration(mut self, time: i64) -> Self {
        self.expiration = time;
        self
    }

    pub fn with_fee_limit(mut self, fee: i64) -> Self {
        self.fee_limit = fee;
        self
    }

    pub fn with_memo(mut self, memo: String) -> Self {
        self.memo = memo;
        self
    }

    pub fn to_transaction_raw(&self) -> Result<TransactionRaw, TransactionError> {
        let mut raw = TransactionRaw::new();
        let mut timestamp = self.timestamp;
        // if timestamp equals 0, means the tx is new
        if self.timestamp == 0 {
            timestamp = trx::timestamp_millis();
        }
        raw.contract = vec![self.contract.clone()];
        if !self.memo.is_empty() {
            self.memo.as_bytes().clone_into(&mut raw.data);
        }

        if self.fee_limit != 0 {
            raw.fee_limit = self.fee_limit;
        }

        raw.timestamp = timestamp;
        raw.expiration = timestamp + self.expiration;
        raw.ref_block_bytes.clone_from(&self.ref_block_bytes);
        raw.ref_block_hash.clone_from(&self.ref_block_hash);

        Ok(raw)
    }
}

impl Default for TronTransactionParameters {
    fn default() -> Self {
        Self {
            ref_block_hash: Default::default(),
            ref_block_bytes: Default::default(),
            fee_limit: 0,
            timestamp: 0,
            expiration: 1000 * 60 * 5_i64,
            memo: "".to_string(),
            contract: Default::default(),
        }
    }
}

/// Represents an Ethereum transaction signature
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TronTransactionSignature(Vec<u8>);

impl TronTransactionSignature {
    pub fn new(rs: &[u8], rec_id: u8) -> Self {
        let mut vec = rs.to_owned();
        vec.push(rec_id);
        TronTransactionSignature(vec)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Represents an Ethereum transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TronTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for TronTransactionId {}

impl fmt::Display for TronTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TronTransaction {
    pub data: TronTransactionParameters,
    pub signature: Option<TronTransactionSignature>,
}

impl FromStr for TronTransaction {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&hex::decode(tx)?)
    }
}

impl Transaction for TronTransaction {
    type Address = TronAddress;
    type Format = TronFormat;
    type PublicKey = TronPublicKey;
    type TransactionId = TronTransactionId;
    type TransactionParameters = TronTransactionParameters;

    fn new(parameters: Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            data: parameters,
            signature: None,
        })
    }

    fn sign(&mut self, signature: &[u8], recid: u8) -> Result<Vec<u8>, TransactionError> {
        self.signature = Some(TronTransactionSignature::new(signature, recid));
        self.to_bytes()
    }

    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        let mut raw = TransactionRaw::parse_from_bytes(transaction)
            .map_err(|e| TransactionError::Crate("protobuf", e.to_string()))?;
        let params = Self::TransactionParameters::default()
            .with_timestamp(raw.timestamp)
            .with_expiration(raw.expiration - raw.timestamp)
            .with_ref_block_raw(raw.ref_block_bytes, raw.ref_block_hash)
            .with_memo(
                String::from_utf8(raw.data)
                    .map_err(|e| TransactionError::Crate("protobuf", e.to_string()))?,
            )
            .with_fee_limit(raw.fee_limit)
            .with_contract(raw.contract.swap_remove(0));

        Ok(Self {
            data: params,
            signature: None,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let raw = self.data.to_transaction_raw()?;
        match self.signature.as_ref() {
            Some(sign) => {
                let mut signed_tx = TransactionProto::new();
                signed_tx.raw_data = protobuf::MessageField::some(raw);
                signed_tx.signature = vec![sign.to_bytes()];
                signed_tx
                    .write_to_bytes()
                    .map_err(|e| TransactionError::Crate("protobuf", e.to_string()))
            }
            None => raw
                .write_to_bytes()
                .map_err(|e| TransactionError::Crate("protobuf", e.to_string())),
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let bytes = self
            .data
            .to_transaction_raw()?
            .write_to_bytes()
            .map_err(|e| TransactionError::Crate("protobuf", e.to_string()))?;
        Ok(Self::TransactionId {
            txid: crypto::sha256(&bytes).to_vec(),
        })
    }
}

impl TronTransaction {
    pub fn sign_transaction(mut self, secret_key: &SecretKey) -> Result<Vec<u8>, TransactionError> {
        let raw = self.data.to_transaction_raw()?;
        let hash = crypto::sha256(
            &raw.write_to_bytes()
                .map_err(|e| TransactionError::Message(e.to_string()))?,
        );
        let message = libsecp256k1::Message::parse(&hash);
        let (signature, rec_id) = libsecp256k1::sign(&message, secret_key);

        self.sign(signature.serialize().as_slice(), rec_id.serialize())
    }

    pub fn tx_param(
        owner_addr: &str,
        amount: i64,
        name: &str,
    ) -> Result<Vec<u8>, TransactionError> {
        let address = TronAddress::from_str(owner_addr)?;
        let amount = U256::from(amount);

        let mut call_data =
            contract_function_call(name, &[Param::from(&address), Param::from(amount)]);
        Ok(call_data.drain(4..).collect::<Vec<_>>())
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::common::ResourceCode;

    use anychain_core::{libsecp256k1, Address, PublicKey};
    use hex_literal::hex;
    use reqwest::blocking::Body;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct BroadcastResult {
        result: bool,
        code: String,
        txid: String,
        message: String,
        transaction: String,
    }

    fn get_now_block() -> (i64, String) {
        #[derive(Debug, Deserialize)]
        struct RawData {
            number: i64,
        }
        #[derive(Debug, Deserialize)]
        struct BlockHeader {
            raw_data: RawData,
        }
        #[derive(Debug, Deserialize)]
        struct Block {
            #[serde(rename(deserialize = "blockID"))]
            block_id: String,
            block_header: BlockHeader,
        }

        let block = reqwest::blocking::Client::new()
            .post("https://nile.trongrid.io/wallet/getnowblock")
            // .post("https://api.trongrid.io/wallet/getnowblock")
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .unwrap()
            .json::<Block>()
            .unwrap();

        (block.block_header.raw_data.number, block.block_id)
    }

    fn broadcast_hex(hex: String) -> BroadcastResult {
        reqwest::blocking::Client::new()
            .post("https://nile.trongrid.io/wallet/broadcasthex")
            // .post("https://api.trongrid.io/wallet/broadcasthex")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(Body::from(format!("{{\"transaction\": \"{}\"}}", hex)))
            .send()
            .unwrap()
            .json::<BroadcastResult>()
            .unwrap()
    }

    fn sign_transaction(secret_key: &libsecp256k1::SecretKey, mut tx: TronTransaction) -> Vec<u8> {
        let raw = tx.data.to_transaction_raw().unwrap();
        let hash = crypto::sha256(&raw.write_to_bytes().unwrap());
        let message = libsecp256k1::Message::parse(&hash);
        let (signature, rec_id) = libsecp256k1::sign(&message, secret_key);

        tx.sign(signature.serialize().as_slice(), rec_id.serialize())
            .unwrap()
    }

    // #[test]
    // fn test_txid() {
    //     let addr_from = "TCaHT65bCHb8us8kCVE4BAPqBVEGYwHE8f";
    //     let transaction = build_trx_transaction(addr_from);
    //     dbg!(transaction.to_transaction_id().unwrap());
    //     let raw = transaction.data.to_transaction_raw().unwrap();
    //     let raw_bytes = crypto::sha256(&raw.write_to_bytes().unwrap());
    //     dbg!(hex::encode(raw_bytes));
    // }

    #[test]
    fn tx_from_hex() {
        let hex = "0a02b6632208fb1feb948ee9fff240e0d4f1dbf7305a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541816cf60987aa124eed29db9a057e476861b8d8dc1215413516435fb1e706c51efff614c7e14ce2625f28e51880897a70f494e0caf7309001a0c21e";
        let tx: TronTransaction = hex.parse().unwrap();
        dbg!(&tx);
    }

    #[test]
    fn test_build_tx2() {
        let from_addr = "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm";
        let to_addr = "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr";
        let amount = "1000000"; // 以Sun为单位
        let block_height = 27007120;
        let block_hash = "00000000019c1890f87d110a81d815b9a38a3e62d44a00a7c8fd50a7b322a2df";

        let ct = trx::build_transfer_contract(from_addr, to_addr, amount).unwrap();
        let params = TronTransactionParameters::default()
            .with_timestamp(trx::timestamp_millis())
            .with_ref_block(block_height, block_hash)
            .with_contract(ct);
        let transaction = TronTransaction::new(params).unwrap();

        let bytes = transaction.to_bytes().unwrap();
        dbg!(hex::encode(bytes));
        dbg!(transaction.to_transaction_id().unwrap().to_string());
        dbg!(transaction.data);
    }

    #[test]
    fn test_from_bytes() {
        let raw = "0a0218902208f87d110a81d815b9409994dbfaac305a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541fa3146ab779ce02392d11209f524ee75d4088a45121541436d74fc1577266b7290b85801145d9c5287e19418c0843d70b9bfd7faac30900180ade204";
        let txid = "519f9d0bdc17d4a083b2676a4e9dce5679045107e7c9a9dad848891ee845235d";
        let transaction = TronTransaction::from_bytes(&hex::decode(raw).unwrap()).unwrap();
        let bytes = transaction.to_bytes().unwrap();
        //println!("{}",transaction.to_transaction_id().unwrap());
        //println!("{:?}",transaction.data);
        assert_eq!(raw, hex::encode(bytes));

        assert_eq!(txid, transaction.to_transaction_id().unwrap().to_string());
    }

    #[test]
    fn test_raw() {
        let raw = "0a025aa722088cb23bfcb18ea03c40facee394ad305a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541fa3146ab779ce02392d11209f524ee75d4088a45121541436d74fc1577266b7290b85801145d9c5287e19418c0843d709afadf94ad30900180ade204";
        let transaction = TronTransaction::from_bytes(&hex::decode(raw).unwrap()).unwrap();
        dbg!(transaction.data);
    }

    #[test]
    fn test_broadcast_trx_transfer() {
        fn build_trx_transaction(addr_from: &str) -> TronTransaction {
            let addr_to = "TQMS7mYqupnYhWDYkJNDSLbmsfiTYH2YAt";
            let amount = "10000000";

            let (number, hash) = get_now_block();
            let ct = trx::build_transfer_contract(addr_from, addr_to, amount).unwrap();
            let params = TronTransactionParameters::default()
                .with_timestamp(trx::timestamp_millis())
                .with_ref_block(number, hash)
                .with_contract(ct);

            TronTransaction::new(params).unwrap()
        }

        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
        ))
        .unwrap();
        let addr_from = TronAddress::from_secret_key(&secret_key, &TronFormat::Standard)
            .unwrap()
            .to_base58();
        let transaction = build_trx_transaction(addr_from.as_str());
        let tx_bytes = sign_transaction(&secret_key, transaction);
        dbg!(tx_bytes.len());
        // let hex = hex::encode(tx_bytes);
        // let result = broadcast_hex(hex);
        // dbg!(result);
    }

    #[test]
    fn test_broadcast_trc20_transfer() {
        fn build_trc20_transaction(addr_from: &str, addr_to: &str) -> TronTransaction {
            // let addr_to = "TDd6SSQ1tYnekfLLEmV3q2wDiFQEm9kxuV";
            // let addr_to = "TAMDRLD5cAvTjm6yxHAn9yf7aN3Jh7LYzU";
            let contract_addr = "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj"; // testnet USDT contract address
                                                                      // let contract_addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"; // testnet USDT contract address
            let amount = "4000000";

            let (number, hash) = get_now_block();
            let ct = trx::build_trc20_transfer_contract(addr_from, contract_addr, addr_to, amount)
                .unwrap();
            let params = TronTransactionParameters::default()
                .with_timestamp(trx::timestamp_millis())
                .with_ref_block(number, hash)
                .with_fee_limit(100_000_000)
                .with_contract(ct);

            TronTransaction::new(params).unwrap()
        }

        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            // "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
            "A655A7AEACF031B4CACF502BD37A0C9876D151B0C9FFDD4C62B63616AAF25E5E"
        ))
        .unwrap();
        let addr_from = TronAddress::from_secret_key(&secret_key, &TronFormat::Standard)
            .unwrap()
            .to_base58();
        let addr_to = "TF7mqB22XvwdZnBpgyrFxJBvRscHMoLoLo";

        let transaction = build_trc20_transaction(addr_from.as_str(), addr_to);
        let tx_bytes = sign_transaction(&secret_key, transaction);
        let hex = hex::encode(tx_bytes);
        let result = broadcast_hex(hex);
        dbg!(result);
    }

    #[test]
    fn test_create_account() {
        fn build_create_account(owner_addr: &str) -> TronTransaction {
            let sc = libsecp256k1::SecretKey::random(&mut rand::thread_rng());
            let public_key = TronPublicKey::from_secret_key(&sc);
            let create_addr = public_key
                .to_address(&TronFormat::Standard)
                .unwrap()
                .to_base58();
            dbg!(&create_addr);

            let (number, hash) = get_now_block();
            let ct = trx::build_account_create(owner_addr, &create_addr).unwrap();
            let params = TronTransactionParameters::default()
                .with_timestamp(trx::timestamp_millis())
                .with_ref_block(number, hash)
                .with_contract(ct);

            TronTransaction::new(params).unwrap()
        }

        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
        ))
        .unwrap();
        let owner_addr = TronAddress::from_secret_key(&secret_key, &TronFormat::Standard)
            .unwrap()
            .to_base58();
        let transaction = build_create_account(owner_addr.as_str());
        let tx_bytes = sign_transaction(&secret_key, transaction);
        let hex = hex::encode(tx_bytes);
        let result = broadcast_hex(hex);
        dbg!(result);
    }

    #[test]
    fn test_tx_from_raw() {
        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
        ))
        .unwrap();
        let raw = "0a02783f2208c5d2d4a1b181787e4080af86c2ef315a5b083612570a34747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e467265657a6542616c616e63655632436f6e7472616374121f0a15411c92861d72b63b88ab017e5951957d4fbd229449108094ebdc03180170b2dd82c2ef31";
        let transaction = TronTransaction::from_bytes(&hex::decode(raw).unwrap()).unwrap();
        let tx_bytes = sign_transaction(&secret_key, transaction);
        let hex = hex::encode(tx_bytes);
        let result = broadcast_hex(hex);
        dbg!(result);
    }

    #[test]
    fn test_freeze_tx() {
        fn build_freeze_transaction(owner_addr: &str) -> TronTransaction {
            let amount = "349043200";

            let (number, hash) = get_now_block();
            let ct =
                trx::build_freeze_balance_v2_contract(owner_addr, amount, ResourceCode::ENERGY)
                    .unwrap();
            let params = TronTransactionParameters::default()
                .with_timestamp(trx::timestamp_millis())
                .with_ref_block(number, hash)
                .with_contract(ct);

            TronTransaction::new(params).unwrap()
        }

        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
        ))
        .unwrap();
        let owner_addr = TronAddress::from_secret_key(&secret_key, &TronFormat::Standard)
            .unwrap()
            .to_base58();
        let transaction = build_freeze_transaction(&owner_addr);
        let tx_bytes = sign_transaction(&secret_key, transaction);
        let hex = hex::encode(tx_bytes);
        let result = broadcast_hex(hex);
        dbg!(result);
    }

    #[test]
    fn test_tx_param() {
        let param =
            TronTransaction::tx_param("TG12UvSbuAMFqQCzP6sWQwyApdRWp5iLPa", 100000000, "transfer")
                .unwrap();
        dbg!(hex::encode(param.as_slice()));
    }

    #[test]
    fn test_delegate_resource() {
        fn build_delegate_contract(
            owner_addr: &str,
            resource_code: ResourceCode,
        ) -> TronTransaction {
            let receiver_addr = "TDRSWaMbuYxa8TQVebJr9x7pgRrzyELNCZ";
            let amount = "100000000";

            let delegate_contract = trx::build_delegate_resource_contract(
                owner_addr,
                receiver_addr,
                resource_code,
                amount,
                false,
            )
            .unwrap();

            let (number, hash) = get_now_block();
            let params = TronTransactionParameters::default()
                .with_timestamp(trx::timestamp_millis())
                .with_ref_block(number, hash)
                .with_contract(delegate_contract);

            TronTransaction::new(params).unwrap()
        }

        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
        ))
        .unwrap();
        let owner_addr = TronAddress::from_secret_key(&secret_key, &TronFormat::Standard)
            .unwrap()
            .to_base58();
        let resource_code = ResourceCode::BANDWIDTH;

        let transaction = build_delegate_contract(&owner_addr, resource_code);

        let tx_bytes = sign_transaction(&secret_key, transaction);
        let hex = hex::encode(tx_bytes);

        let result = broadcast_hex(hex);
        dbg!(result);
    }

    #[test]
    fn test_undelegate_resource() {
        fn build_undelegate_contract(
            owner_addr: &str,
            resource_code: ResourceCode,
        ) -> TronTransaction {
            let receiver_addr = "TDRSWaMbuYxa8TQVebJr9x7pgRrzyELNCZ";
            let amount = "100000000";

            let undelegate_contract = trx::build_undelegate_resource_contract(
                owner_addr,
                receiver_addr,
                resource_code,
                amount,
            )
            .unwrap();

            let (number, hash) = get_now_block();
            let params = TronTransactionParameters::default()
                .with_timestamp(trx::timestamp_millis())
                .with_ref_block(number, hash)
                .with_contract(undelegate_contract);

            TronTransaction::new(params).unwrap()
        }

        let secret_key = libsecp256k1::SecretKey::parse(&hex!(
            "31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9"
        ))
        .unwrap();
        let owner_addr = TronAddress::from_secret_key(&secret_key, &TronFormat::Standard)
            .unwrap()
            .to_base58();
        let resource_code = ResourceCode::BANDWIDTH;

        let transaction = build_undelegate_contract(&owner_addr, resource_code);

        let tx_bytes = sign_transaction(&secret_key, transaction);
        let hex = hex::encode(tx_bytes);

        let result = broadcast_hex(hex);
        dbg!(result);
    }
}
