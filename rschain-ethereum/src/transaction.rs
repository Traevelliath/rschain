use crate::address::EthereumAddress;
use crate::amount::EthereumAmount;
use crate::format::EthereumFormat;
use crate::network::EthereumNetwork;
use crate::public_key::EthereumPublicKey;

use core::{fmt, marker::PhantomData, str::FromStr};
use ethabi::ethereum_types::H160;
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use ethereum_types::U256;
use rlp::{decode_list, RlpStream};
use rschain_core::utilities::crypto::keccak256;
use rschain_core::{hex, PublicKey, Transaction, TransactionError, TransactionId};
use serde_json::{json, Value};
use std::convert::TryInto;

/// Trim the leading zeros of a byte stream and return it
fn trim_leading_zeros(v: &[u8]) -> &[u8] {
    let count = v.iter().take_while(|b| **b == b'0').count();
    &v[count..]
}

/// Prepend a number of zeros to 'v' to make it 'to_len' bytes long
fn to_padded_with_zeros(v: &[u8], to_len: usize) -> Vec<u8> {
    if v.len() < to_len {
        let mut vec = vec![0u8; to_len - v.len()];
        vec.extend_from_slice(v);
        vec
    } else {
        v.to_vec()
    }
}

pub fn encode_transfer(func_name: &str, address: &EthereumAddress, amount: U256) -> Vec<u8> {
    #[allow(deprecated)]
    let func = Function {
        name: func_name.to_string(),
        inputs: vec![
            Param {
                name: "address".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "amount".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };

    let tokens = vec![
        Token::Address(H160::from_slice(&address.to_bytes().unwrap())),
        Token::Uint(amount),
    ];

    func.encode_input(&tokens).unwrap()
}

/// Represents the parameters for an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransactionParameters {
    /// The address of the receiver
    pub receiver: EthereumAddress,
    /// The amount (in wei)
    pub amount: EthereumAmount,
    /// The transaction gas limit
    pub gas: U256,
    /// The transaction gas price in wei
    pub gas_price: EthereumAmount,
    /// The nonce of the Ethereum account
    pub nonce: U256,
    /// The transaction data
    pub data: Vec<u8>,
}

impl EthereumTransactionParameters {
    pub fn decode_data(&self) -> Result<Value, TransactionError> {
        if self.data.len() < 4 {
            return Err(TransactionError::Message("Illegal data".into()));
        }

        let selector = &self.data[..4];

        match selector {
            // function selector for 'transfer(address,uint256)'
            [169, 5, 156, 187] => {
                #[allow(deprecated)]
                let func = Function {
                    name: "transfer".into(),
                    inputs: vec![
                        Param {
                            name: "to".into(),
                            kind: ParamType::Address,
                            internal_type: None,
                        },
                        Param {
                            name: "amount".into(),
                            kind: ParamType::Uint(256),
                            internal_type: None,
                        },
                    ],
                    outputs: vec![],
                    constant: None,
                    state_mutability: StateMutability::Payable,
                };
                match func.decode_input(&self.data[4..]) {
                    Ok(mut tokens) => {
                        let to =
                            hex::encode(tokens.swap_remove(0).into_address().unwrap().as_bytes());
                        let amount = tokens.swap_remove(0).into_uint().unwrap().as_u128();
                        Ok(json!({
                            "function": "transfer",
                            "params": {
                                "to": to,
                                "amount": amount
                            }
                        }))
                    }
                    Err(e) => Err(TransactionError::Message(e.to_string())),
                }
            }
            _ => Err(TransactionError::Message(
                "Unsupported contract function".into(),
            )),
        }
    }
}

/// Represents an Ethereum transaction signature
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionSignature {
    /// The V field of the signature protected with a chain_id
    pub v: Vec<u8>,
    /// The R field of the signature
    pub r: Vec<u8>,
    /// The S field of the signature
    pub s: Vec<u8>,
}

/// Represents an Ethereum transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for EthereumTransactionId {}

impl fmt::Display for EthereumTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}

/// Represents an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumTransaction<N: EthereumNetwork> {
    /// The address of the sender
    pub sender: Option<EthereumAddress>,
    /// The transaction parameters (gas, gas_price, nonce, data)
    pub parameters: EthereumTransactionParameters,
    /// The transaction signature
    pub signature: Option<EthereumTransactionSignature>,
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> Transaction for EthereumTransaction<N> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;
    type TransactionId = EthereumTransactionId;
    type TransactionParameters = EthereumTransactionParameters;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            sender: None,
            parameters,
            signature: None,
            _network: PhantomData,
        })
    }

    /// Returns a signed transaction given the {r,s,rec_id}.
    fn sign(&mut self, rs: &[u8], rec_id: u8) -> Result<Vec<u8>, TransactionError> {
        let message = libsecp256k1::Message::parse_slice(&self.to_transaction_id()?.txid)
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?;
        let recovery_id = libsecp256k1::RecoveryId::parse(rec_id)
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?;

        let public_key = EthereumPublicKey::from_secp256k1_public_key(
            libsecp256k1::recover(
                &message,
                &libsecp256k1::Signature::parse_standard_slice(rs).map_err(|error| {
                    TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                })?,
                &recovery_id,
            )
            .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?,
        );
        self.sender = Some(public_key.to_address(&EthereumFormat::Standard)?);
        self.signature = Some(EthereumTransactionSignature {
            v: (u32::from(rec_id) + N::CHAIN_ID * 2 + 35)
                .to_be_bytes()
                .to_vec(), // EIP155
            r: rs[..32].to_vec(),
            s: rs[32..64].to_vec(),
        });
        self.to_bytes()
    }

    /// Returns a transaction given the transaction bytes.
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md>
    fn from_bytes(transaction: &[u8]) -> Result<Self, TransactionError> {
        let list: Vec<Vec<u8>> = decode_list(transaction);
        if list.len() != 9 {
            return Err(TransactionError::InvalidRlpLength(list.len()));
        }

        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(&hex::encode(&list[3]))?,
            amount: if list[4].is_empty() {
                EthereumAmount::from_u256(U256::zero())
            } else {
                EthereumAmount::from_u256(U256::from(list[4].as_slice()))
            },
            gas: if list[2].is_empty() {
                U256::zero()
            } else {
                U256::from(list[2].as_slice())
            },
            gas_price: if list[1].is_empty() {
                EthereumAmount::from_u256(U256::zero())
            } else {
                EthereumAmount::from_u256(U256::from(list[1].as_slice()))
            },
            nonce: if list[0].is_empty() {
                U256::zero()
            } else {
                U256::from(list[0].as_slice())
            },
            data: list[5].clone(),
        };

        if list[7].is_empty() && list[8].is_empty() {
            // Raw transaction
            Self::new(parameters)
        } else {
            // Signed transaction
            let be_v: [u8; 4] = to_padded_with_zeros(&list[6], 4).try_into().unwrap();
            let v = u32::from_be_bytes(be_v);
            let r = to_padded_with_zeros(&list[7], 32);
            let s = to_padded_with_zeros(&list[8], 32);

            let signature = [r.as_slice(), s.as_slice()].concat();
            let raw_transaction = Self::new(parameters).unwrap();

            let message =
                libsecp256k1::Message::parse_slice(&raw_transaction.to_transaction_id()?.txid)
                    .map_err(|error| {
                        TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                    })?;
            let recovery_id = libsecp256k1::RecoveryId::parse((v - N::CHAIN_ID * 2 - 35) as u8)
                .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?;
            let public_key = EthereumPublicKey::from_secp256k1_public_key(
                libsecp256k1::recover(
                    &message,
                    &libsecp256k1::Signature::parse_standard_slice(signature.as_slice()).map_err(
                        |error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)),
                    )?,
                    &recovery_id,
                )
                .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?,
            );

            Ok(Self {
                sender: Some(public_key.to_address(&EthereumFormat::Standard)?),
                parameters: raw_transaction.parameters,
                signature: Some(EthereumTransactionSignature {
                    v: v.to_be_bytes().to_vec(),
                    r,
                    s,
                }),
                _network: PhantomData,
            })
        }
    }

    /// Returns the transaction in bytes.
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md>
    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        // Returns an encoded transaction in Recursive Length Prefix (RLP) format.
        // https://github.com/ethereum/wiki/wiki/RLP
        fn encode_transaction(
            transaction_rlp: &mut RlpStream,
            parameters: &EthereumTransactionParameters,
        ) -> Result<(), TransactionError> {
            transaction_rlp
                .append(&parameters.nonce)
                .append(&parameters.gas_price.0)
                .append(&parameters.gas)
                .append(&hex::decode(&parameters.receiver.to_string()[2..])?)
                .append(&parameters.amount.0)
                .append(&parameters.data);
            Ok(())
        }

        // Returns the raw transaction (in RLP).
        fn raw_transaction<N: EthereumNetwork>(
            parameters: &EthereumTransactionParameters,
        ) -> Result<RlpStream, TransactionError> {
            let mut transaction_rlp = RlpStream::new();
            transaction_rlp.begin_list(9);
            encode_transaction(&mut transaction_rlp, parameters)?;
            let chain_id = N::CHAIN_ID.to_be_bytes();
            let chain_id = trim_leading_zeros(&chain_id);
            transaction_rlp.append(&chain_id).append(&0u8).append(&0u8);
            Ok(transaction_rlp)
        }

        // Returns the signed transaction (in RLP).
        fn signed_transaction(
            parameters: &EthereumTransactionParameters,
            signature: &EthereumTransactionSignature,
        ) -> Result<RlpStream, TransactionError> {
            let mut transaction_rlp = RlpStream::new();
            transaction_rlp.begin_list(9);
            encode_transaction(&mut transaction_rlp, parameters)?;
            // trim the leading zeros of v
            let v = trim_leading_zeros(&signature.v);
            transaction_rlp.append(&v);
            // trim the leading zeros of r
            let r = trim_leading_zeros(&signature.r);
            transaction_rlp.append(&r);
            // trim the leading zeros of s
            let s = trim_leading_zeros(&signature.s);
            transaction_rlp.append(&s);
            Ok(transaction_rlp)
        }

        match &self.signature {
            Some(signature) => Ok(signed_transaction(&self.parameters, signature)?
                .out()
                .to_vec()),
            None => Ok(raw_transaction::<N>(&self.parameters)?.out().to_vec()),
        }
    }

    /// Returns the hash of the signed transaction, if the signature is present.
    /// Otherwise, returns the hash of the raw transaction.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(Self::TransactionId {
            txid: keccak256(&self.to_bytes()?).to_vec(),
        })
    }
}

impl<N: EthereumNetwork> FromStr for EthereumTransaction<N> {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = match &tx[..2] {
            "0x" => &tx[2..],
            _ => tx,
        };
        Self::from_bytes(&hex::decode(tx)?)
    }
}

impl<N: EthereumNetwork> fmt::Display for EthereumTransaction<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{}",
            &hex::encode(match self.to_bytes() {
                Ok(transaction) => transaction,
                _ => return Err(fmt::Error),
            })
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_trim_zeros() {
        let v = "0000123456700";
        assert_eq!(trim_leading_zeros(v.as_bytes()), "123456700".as_bytes());
    }
}
