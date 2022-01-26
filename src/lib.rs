use bytecheck::CheckBytes;
use chrono::prelude::*;
use chrono::DateTime;
use openssl::base64;
use openssl::hash::{hash, MessageDigest};
use openssl::rand::rand_bytes;
use rkyv::{
    archived_root,
    ser::{serializers::AllocSerializer, Serializer},
    with::AsString,
    Archive, Deserialize, Infallible, Serialize,
};
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
//https://en.wikipedia.org/wiki/Hashcash
//paper: https://link.springer.com/content/pdf/10.1007%2F3-540-48071-4_10.pdf

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes, Debug))]
pub struct H {
    version: u16,
    bits: u16,
    date: String,
    rand: Vec<u8>,
    counter: Vec<u8>,
}

//todo datetime expire check

impl H {
    //generate new challenge
    #[must_use]
    pub fn new(version: u16, bits: u16) -> Self {
        let mut rand = vec![0; 64]; //todo
        rand_bytes(&mut rand).unwrap();
        H {
            version: version,
            bits: bits,
            date: Utc::now().to_rfc3339(),
            counter: vec![0; 0],
            rand: rand,
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let archived = rkyv::check_archived_root::<Self>(bytes).unwrap();
        let h: Self = archived.deserialize(&mut Infallible).unwrap();
        h
    }

    //to le bytes
    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        let mut serializer = AllocSerializer::<256>::default();
        serializer
            .serialize_value(self)
            .expect("Failed to serialize a message");
        serializer.into_serializer().into_inner().to_vec()
    }

    #[must_use]
    fn hash(&self) -> Vec<u8> {
        let hash = hash(MessageDigest::sha3_512(), &self.to_bytes()).unwrap();
        hash.to_vec()
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let hash = self.hash();
        let clz = u8_slice_clz(&hash);
        if clz == self.bits as usize {
            return true;
        }
        false
    }

    //todo timeout
    #[must_use]
    pub fn solve(&mut self, time_out: &Option<Duration>) -> bool {
        let start_time = SystemTime::now();
        let mut count = 1;
        while !self.verify() {
            if time_out.is_some() {
                if start_time.elapsed().unwrap() > time_out.unwrap() {
                    println!("solve time out");
                    return false;
                }
            }
            /*
            println!(
                "solve {} coutner: {}",
                count,
                base64::encode_block(&self.counter)
            );
            */
            //modify counter
            self.increment_counter();
            count += 1;
        }
        //println!("solved with {} attempts", count);
        return true;
    }

    fn increment_counter(&mut self) {
        //todo edge case, all 255
        let mut is_incremented = false;
        for i in (0..self.counter.len()).rev() {
            // println!("inc counter i: {}", i);
            if self.counter[i] == u8::MAX.into() {
                continue;
            }
            // increment
            self.counter[i] += 1;
            is_incremented = true;
            break;
        }

        //extend
        if !is_incremented {
            //  println!("extend counter");
            self.counter.resize(self.counter.len() + 1, 0);
        }
    }
}

impl fmt::Display for H {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode_block(&self.rand))
    }
}

pub fn u8_slice_clz(v: &[u8]) -> usize {
    for i in 0..v.len() {
        if v[i] == 0 {
            //all zero
            continue;
        }
        return i * 8 + v[i].leading_zeros() as usize;
    }
    return v.len() * 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt_u8_slice_as_bin(slice: &[u8]) -> String {
        let mut ret = String::new();
        for i in slice {
            ret.push_str(&format!("{:08b} ", i));
        }
        ret
    }

    fn fmt_u8_slice_as_dec(slice: &[u8]) -> String {
        let mut ret = String::new();
        for i in slice {
            ret.push_str(&format!("{} ", i));
        }
        ret
    }

    fn p(v: &[u8]) {
        println!("{}", fmt_u8_slice_as_dec(&v));
        println!("{}", fmt_u8_slice_as_bin(&v));
    }

    #[test]
    fn cls_test() {
        assert_eq!(u8_slice_clz(&vec![0; 0]), 0);
        let v: [u8; 2] = [0b0u8, 0b11111111u8];

        // println!("{}", fmt_u8_slice_as_dec(&v));
        // println!("{}", fmt_u8_slice_as_bin(&v));
        assert_eq!(u8_slice_clz(&v), 8);
        let v: [u8; 3] = [0b0u8, 0b00010000u8, 0b11111111u8];
        p(&v);
        assert_eq!(u8_slice_clz(&v), 11);

        assert_eq!(u8_slice_clz(&vec![255; 255]), 0);
    }

    #[test]
    #[ignore]
    fn solve_timeout_test() {
        let mut c = H::new(1, 20);
        assert_eq!(false, c.solve(&Some(Duration::from_secs(1))));
    }

    #[test]
    fn simulation_test() {
        // A generate challenge
        let mut challenge = H::new(1, 10);
        println!("Challenge: {}", challenge);

        // B receive challenge and solve
        assert!(challenge.solve(&None));
        println!("solved challenge!");

        //send to A and verify
        assert!(challenge.verify());
        println!("done");
    }

    // run tests
    // cargo test -- --nocapture
}
