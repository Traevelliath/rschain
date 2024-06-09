use crate::TronAddress;
use ethabi::{encode, Token};
use rschain_core::{ethereum_types::U256, utilities::crypto::keccak256};
use std::str::FromStr;

/// Represents a parameter that's fed to a
/// function of an on-chain contract
pub(crate) struct Param {
    pub type_: String,
    pub value: Token,
}

impl From<&TronAddress> for Param {
    fn from(address: &TronAddress) -> Self {
        Param {
            type_: "address".to_string(),
            value: address.to_token(),
        }
    }
}

impl From<U256> for Param {
    fn from(amount: U256) -> Self {
        Param {
            type_: "uint256".to_string(),
            value: Token::Uint(amount),
        }
    }
}

pub(crate) fn contract_function_call<Str: AsRef<str>>(
    function_name: Str,
    params: &[Param],
) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    let param_types = params
        .iter()
        .map(|param| param.type_.as_str())
        .collect::<Vec<&str>>()
        .join(",");

    let function_selector = format!("{}({})", function_name.as_ref(), param_types);

    data.extend_from_slice(&keccak256(function_selector.as_bytes())[..4]);

    let tokens = params
        .iter()
        .map(|param| param.value.clone())
        .collect::<Vec<Token>>();

    data.extend_from_slice(&encode(&tokens));

    data
}

pub(crate) fn trc20_transfer<Str: AsRef<str>>(address: Str, amount: Str) -> Vec<u8> {
    let address = TronAddress::from_str(address.as_ref()).unwrap();
    let amount = U256::from_dec_str(amount.as_ref()).unwrap();

    contract_function_call("transfer", &[Param::from(&address), Param::from(amount)])
}

pub(crate) fn trc20_approve<Str: AsRef<str>>(address: Str, amount: Str) -> Vec<u8> {
    let address = TronAddress::from_str(address.as_ref()).unwrap();
    let amount = U256::from_dec_str(amount.as_ref()).unwrap();

    contract_function_call("approve", &[Param::from(&address), Param::from(amount)])
}

#[cfg(test)]
mod test_mod {
    use std::str::FromStr;

    use super::{contract_function_call, Param, TronAddress};
    use ethabi::ethereum_types::U256;

    #[test]
    fn test_contract_function_call() {
        let address = TronAddress::from_str("TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr").unwrap();
        let amount = U256::from_dec_str("20000000000000000000").unwrap();

        let call_data =
            contract_function_call("transfer", &[Param::from(&address), Param::from(amount)]);

        assert_eq!(
            "a9059cbb000000000000000000000041436d74fc1577266b7\
             290b85801145d9c5287e19400000000000000000000000000\
             0000000000000000000001158e460913d00000",
            hex::encode(call_data)
        )
    }

    #[test]
    fn test_decode_tx() {
        let data = "a9059cbb000000000000000000000000069c068abc2c868d5b8dfe6efaba6955e76e4d3c0000000000000000000000000000000000000000000000000000000077359400".as_bytes();
        let data = hex::decode(data).unwrap();
        let mut params = ethabi::decode(
            &[ethabi::ParamType::Address, ethabi::ParamType::Uint(256)],
            &data[4..],
        )
        .unwrap();
        let addr_token = params.remove(0);
        let amount = params.remove(0).into_uint().unwrap().as_u64();

        let addr = TronAddress::from_token(addr_token);
        dbg!(addr);
        dbg!(amount);
    }
}
