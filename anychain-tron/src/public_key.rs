use crate::{TronAddress, TronFormat};
use anychain_core::{libsecp256k1, Address, AddressError, PublicKey, PublicKeyError};
use core::{fmt, fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronPublicKey(libsecp256k1::PublicKey);

impl PublicKey for TronPublicKey {
    type SecretKey = libsecp256k1::SecretKey;
    type Address = TronAddress;
    type Format = TronFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        Self(libsecp256k1::PublicKey::from_secret_key(secret_key))
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        TronAddress::from_public_key(self, format)
    }
}

impl TronPublicKey {
    /// Returns a public key given a secp256k1 public key.
    pub fn from_secp256k1_public_key(public_key: libsecp256k1::PublicKey) -> Self {
        Self(public_key)
    }

    /// Returns the secp256k1 public key of the public key
    pub fn to_secp256k1_public_key(&self) -> libsecp256k1::PublicKey {
        self.0
    }
}

impl FromStr for TronPublicKey {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Ok(Self(libsecp256k1::PublicKey::parse_slice(
            hex::decode(public_key)?.as_slice(),
            None,
        )?))
    }
}

impl TryFrom<String> for TronPublicKey {
    type Error = PublicKeyError;

    fn try_from(public_key: String) -> Result<Self, Self::Error> {
        Ok(Self(libsecp256k1::PublicKey::parse_slice(
            hex::decode(public_key)?.as_slice(),
            None,
        )?))
    }
}

impl TryFrom<&[u8]> for TronPublicKey {
    type Error = PublicKeyError;

    fn try_from(public_key: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(libsecp256k1::PublicKey::parse_slice(
            hex::decode(public_key)?.as_slice(),
            None,
        )?))
    }
}

impl Display for TronPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for s in &self.0.serialize() {
            write!(f, "{:02X}", s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{TronFormat, TronPublicKey};
    use anychain_core::libsecp256k1::SecretKey;
    use anychain_core::PublicKey;

    #[test]
    pub fn test_from_private() {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let seckey_hex = hex::encode(secret_key.serialize());
        dbg!(seckey_hex);
        // let sk_decoded =
        //     hex::decode("31303ed96a44750531f973e734ebf097f2eb849ffe6ec75920c13d624bfd3da9")
        //         .unwrap();
        // let secret_key = SecretKey::parse_slice(sk_decoded.as_slice()).unwrap();

        let public_key = TronPublicKey::from_secret_key(&secret_key);
        let address = public_key.to_address(&TronFormat::Standard).unwrap();
        dbg!(address.to_base58());

        // assert_eq!(address.to_base58(), "TCaHT65bCHb8us8kCVE4BAPqBVEGYwHE8f");
    }

    #[test]
    pub fn test_from_str() {
        let uncompressed_key = "0404B604296010A55D40000B798EE8454ECCC1F8900E70B1ADF47C9887625D8BAE3866351A6FA0B5370623268410D33D345F63344121455849C9C28F9389ED9731";
        let pubkey: TronPublicKey = uncompressed_key.parse().unwrap();
        assert_eq!(uncompressed_key, pubkey.to_string());
    }
}
