use hshs::H;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign;
use openssl::sign::{Signer, Verifier};

//openssl doc: https://docs.rs/openssl/latest/openssl/sign/index.html
fn main() {
    // generate an new challenge
    let version = 1;
    let bits = 10;
    let challenge = H::new(version, bits);
    println!("generated the challenge {}", challenge);
    let keypair = Rsa::generate(2048).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();

    let serialized_challenge = challenge.to_bytes();

    //sign the (serialized) challenge
    let mut signer = Signer::new(MessageDigest::sha3_512(), &keypair).unwrap();
    signer.update(&serialized_challenge).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    //
}
