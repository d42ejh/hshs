use bytecheck::CheckBytes;
use chrono::prelude::*;
use chrono::DateTime;
use openssl::base64;
use openssl::hash::{hash, MessageDigest};
use openssl::rand::rand_bytes;
use rkyv::{
    archived_root,
    ser::{serializers::AllocSerializer, Serializer},
    Archive, Deserialize, Infallible, Serialize,
};
use std::fmt;
use std::time::{Duration, SystemTime};
//https://en.wikipedia.org/wiki/Hashcash
//paper: https://link.springer.com/content/pdf/10.1007%2F3-540-48071-4_10.pdf

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes, Debug))]
pub struct H {
    bits: u16,
    date: String,
    deadline: Option<String>,
    rand: Vec<u8>,
    counter: Vec<u8>,
}

//todo datetime expire check

impl H {
    //generate new challenge
    #[must_use]
    pub fn new(bits: u16, deadline_offset: Option<&chrono::Duration>) -> Self {
        let mut rand = vec![0; 64]; //todo(64 is should be fine)
        rand_bytes(&mut rand).unwrap();
        let now = Utc::now();
        if deadline_offset.is_some() {
            let deadline = now + *deadline_offset.unwrap();
            H {
                bits: bits,
                date: now.to_rfc3339(),
                deadline: Some(deadline.to_rfc3339()),
                counter: Vec::new(),
                rand: rand,
            }
        } else {
            return H {
                bits: bits,
                date: now.to_rfc3339(),
                deadline: None,
                counter: Vec::new(),
                rand: rand,
            };
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
    pub fn to_bytes(&self) -> Vec<u8> {
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
    fn verify_deadline(&self) -> bool {
        assert!(self.deadline.is_some());
        let now = Utc::now();

        let deadline = DateTime::parse_from_rfc3339(&self.deadline.as_ref().unwrap()).unwrap();
        let deadline = DateTime::<Utc>::from_utc(deadline.naive_utc(), Utc);
        // println!("now {}\ndeadline {}", now, deadline);
        if now > deadline {
            return false;
        }
        true
    }

    #[must_use]
    fn verify_hash(&self) -> bool {
        let hash = self.hash();
        let clz = u8_slice_clz(&hash);
        if clz == self.bits as usize {
            return true;
        }
        false
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        if self.deadline.is_some() && !self.verify_deadline() {
            return false;
        }
        if !self.verify_hash() {
            return false;
        }
        true
    }

    // false == time out
    #[must_use]
    pub fn solve(&mut self, time_out: Option<Duration>) -> bool {
        let start_time = SystemTime::now();
        while !self.verify_hash() {
            if time_out.is_some() {
                if start_time.elapsed().unwrap() > time_out.unwrap() {
                    //    println!("solve time out");
                    return false;
                }
            }
            self.increment_counter();
        }
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

    pub fn clear_counter(&mut self) {
        self.counter = Vec::new();
    }
}

impl fmt::Display for H {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dl;
        if self.deadline.is_some() {
            dl = self.deadline.as_ref().unwrap().to_owned();
        } else {
            dl = String::new();
        }
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.bits,
            self.date,
            dl,
            base64::encode_block(&self.rand),
            base64::encode_block(&self.counter)
        )
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
        let mut c = H::new(20, None);
        assert_eq!(false, c.solve(Some(Duration::from_secs(1))));
    }

    #[test]
    fn test_deadline() {
        let deadline = chrono::Duration::milliseconds(1);
        let mut c = H::new(1, Some(&deadline));

        //sleep
        std::thread::sleep(Duration::from_secs(1));
        assert!(c.solve(None));

        //try verify after deadline
        println!("a");
        assert!(!c.verify_deadline());
        assert!(!c.verify());

        println!("b");
        //in time
        let deadline = chrono::Duration::hours(1);
        let mut c = H::new(1, Some(&deadline));
        assert!(c.solve(None));
        assert!(c.verify_deadline());
        assert!(c.verify());
    }

    #[test]
    fn simulation_test() {
        // A generate challenge
        let mut challenge = H::new(10, None);
        println!("Challenge: {}", challenge);

        // B receive challenge and solve
        assert!(challenge.solve(None));
        println!("solved challenge!");

        //send to A and verify
        assert!(challenge.verify());
        println!("done");
    }

    // run tests
    // cargo test -- --nocapture
}
