use chrono::{DateTime, Duration, Utc};
use hshs::H;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign;
use openssl::sign::{Signer, Verifier};

//openssl doc: https://docs.rs/openssl/latest/openssl/sign/index.html
// cargo run --example practical_example
fn main() {
    ///////////////////////////////////////////////////////////////////////////
    //X generates an new challenge
    let version = 1;
    let bits = 10;
    let deadline_offset = Duration::minutes(2); //hshs calls Utc::now() internally when H::new() is called(the DateTime is stored in the struct H)
                                                //deadline is Utc::now() + deadline_offset

    let challenge = H::new(version, bits, Some(&deadline_offset));
    println!("generated the challenge {}", challenge);
    let keypair = Rsa::generate(2048).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();

    let serialized_challenge = challenge.to_bytes();

    //sign the (serialized) challenge
    let mut signer = Signer::new(MessageDigest::sha3_512(), &keypair).unwrap();
    signer.update(&serialized_challenge).unwrap();
    let signature = signer.sign_to_vec().unwrap(); //use this later

    ///////////////////////////////////////////////////////////////////////////
    //Y receives the challenge from X(typically via network)
    let mut received_challenge = H::from_bytes(&serialized_challenge);
    // solve the challenge
    assert!(received_challenge.solve(None));
    assert!(received_challenge.verify());
    let serialized_solved_challenge = received_challenge.to_bytes();

    ///////////////////////////////////////////////////////////////////////////
    // X receives the solved challenge from Y
    let mut received_challenge = H::from_bytes(&serialized_solved_challenge);
    if !received_challenge.verify() {
        //invalid request
        panic!();
    }

    //clear the counter to verify signature
    received_challenge.clear_counter();
    //serialize
    let buffer = received_challenge.to_bytes();

    let mut verifier = Verifier::new(MessageDigest::sha3_512(), &keypair).unwrap();
    verifier.update(&buffer).unwrap();
    if !verifier.verify(&signature).unwrap() {
        //invalid request
        panic!();
    }
    println!("Done");
}
