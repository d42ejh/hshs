use bytecheck::CheckBytes;
use chrono::{DateTime, Duration, Utc};
use hshs::H;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use rkyv::{
    archived_root,
    ser::{serializers::AllocSerializer, Serializer},
    Archive, Deserialize, Infallible, Serialize,
};

//use serde or whatever you prefer
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Default)]
#[archive_attr(derive(CheckBytes, Debug))]
struct YourMetadata {
    pub your_program_version: u16,
    pub memo: String,
}

impl YourMetadata {
    pub fn to_bytes(&self) -> rkyv::AlignedVec {
        let mut serializer = AllocSerializer::<256>::default();
        serializer
            .serialize_value(self)
            .expect("Failed to serialize a message");
        serializer.into_serializer().into_inner()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let archived = rkyv::check_archived_root::<Self>(bytes).unwrap();
        let m: Self = archived.deserialize(&mut Infallible).unwrap();
        m
    }
}

//openssl doc: https://docs.rs/openssl/latest/openssl/sign/index.html
// cargo run --example practical_example
fn main() {
    ///////////////////////////////////////////////////////////////////////////
    let memo = "abcdefgh1234";
    let meta = YourMetadata {
        your_program_version: 3,
        memo: memo.to_owned(),
    };
    //X generates an new challenge
    let bits = 10;
    let deadline_offset = Duration::minutes(2); //hshs calls Utc::now() internally when H::new() is called(the DateTime is stored in the struct H)
                                                //deadline is Utc::now() + deadline_offset

    //let challenge = H::new(bits, Some(&deadline_offset), None);//without your metadata
    let challenge = H::new(bits, Some(&deadline_offset), Some(&meta.to_bytes())); //with your metadata
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

    //you can use the optional metadata field if you want
    assert!(received_challenge.meta.is_some());
    let meta_bytes = received_challenge.meta.unwrap();
    let meta = YourMetadata::from_bytes(&meta_bytes);
    if meta.your_program_version < 2 {
        //example usage, reject old versions
        panic!();
    }
    assert_eq!(meta.memo, memo);
    println!("Done");
}
