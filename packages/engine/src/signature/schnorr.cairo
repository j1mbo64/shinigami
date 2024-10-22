use crate::errors::Error;
use crate::signature::{constants, signature};
use starknet::secp256k1::{Secp256k1Point};

#[derive(Drop)]
pub struct SchnorrSignature {
    pub r: u256,
    pub s: u256
}

pub fn parse_schnorr_pub_key(pk_bytes: @ByteArray) -> Result<Secp256k1Point, felt252> {
    if pk_bytes.len() == 0 {
        return Result::Err(Error::TAPROOT_EMPTY_PUBKEY);
    }
    if pk_bytes.len() != 32 {
        return Result::Err(Error::TAPROOT_INVALID_PUBKEY_SIZE);
    }

    let mut key_compressed: ByteArray = "\02";
    key_compressed.append(pk_bytes);
    return Result::Ok(signature::parse_pub_key(@key_compressed)?);
}

pub fn parse_schnorr_signature(sig_bytes: @ByteArray) -> Result<SchnorrSignature, felt252> {
    let sig_len = sig_bytes.len();
    if sig_len != constants::SCHNORR_SIG_SIZE {
        return Result::Err(Error::SCHNORR_INVALID_SIG_SIZE);
    }

    let mut r: u256 = 0;
    let mut s: u256 = 0;
    for i in 0
        ..sig_bytes
            .len() {
                if i < 32 {
                    r *= 256;
                    r += sig_bytes[i].into();
                } else {
                    s *= 256;
                    s += sig_bytes[i].into();
                }
            };
    if r >= constants::SECP256_FIELD_VAL {
        return Result::Err(Error::SCHNORR_INVALID_SIG_R_FIELD);
    }

    return Result::Ok(SchnorrSignature { r: r, s: s });
}

