use hshs::H;
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

    let challenge_bytes = challenge.to_bytes();
    //sign the challenge
    //
}
