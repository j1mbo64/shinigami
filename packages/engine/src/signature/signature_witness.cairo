use crate::signature::{signature, sighash, constants};

// `BaseWitnessSigVerifier` is used to verify ECDSA signatures encoded in DER or BER format (segwit)
#[derive(Drop)]
pub struct BaseSigVerifier {
    // public key as a point on the secp256k1 curve, used to verify the signature
    pub_key: Secp256k1Point,
    // ECDSA signature
    sig: Signature,
    // raw byte array of the signature
    sig_bytes: @ByteArray,
    // raw byte array of the public key
    pk_bytes: @ByteArray,
    // part of the script being verified
    sub_script: ByteArray,
    // specifies how the transaction was hashed for signing
    hash_type: u32,
}

pub trait BaseWitnessSigVerifierTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>
> {
    fn new(
        ref vm: Engine<T>, sig_bytes: @ByteArray, pk_bytes: @ByteArray
    ) -> Result<BaseSigVerifier, felt252>;
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool;
}

impl BaseWitnessSigVerifierImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<I>,
    +Drop<O>,
    +Drop<T>
> of BaseWitnessSigVerifierTrait<I, O, T> {
    fn new(
        ref vm: Engine<T>, sig_bytes: @ByteArray, pk_bytes: @ByteArray
    ) -> Result<BaseSigVerifier, felt252> {
        let mut sub_script = vm.sub_script();
        sub_script = remove_signature(sub_script, sig_bytes);
        let (pub_key, sig, hash_type) = parse_base_sig_and_pk(ref vm, pk_bytes, sig_bytes)?;
        Result::Ok(BaseSigVerifier { pub_key, sig, sig_bytes, pk_bytes, sub_script, hash_type })
    }

    // TODO: add signature cache mechanism for optimization
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool {
        let sig_hash: u256 = sighash::calc_signature_hash::<
            I, O, T
        >(@self.sub_script, self.hash_type, vm.transaction, vm.tx_idx);

        is_valid_signature(sig_hash, self.sig.r, self.sig.s, self.pub_key)
    }
}
