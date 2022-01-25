use chrono::prelude::*;
use chrono::DateTime;
use openssl::base64;
use openssl::hash::hash;
use openssl::rand::rand_bytes;
use std::fmt;
use std::str::FromStr;
//https://en.wikipedia.org/wiki/Hashcash
//paper: https://link.springer.com/content/pdf/10.1007%2F3-540-48071-4_10.pdf

pub struct H {
    version: u16,
    bits: u16,
    date: DateTime<Utc>,
    rand: Vec<u8>,
    counter: Vec<u8>,
}

impl H {
    //generate challenge
    pub fn new(version: u16, bits: u16) -> Self {
        let mut buffer = vec![0; 0]; //todo
        let mut rand = vec![0; 0]; //todo
        rand_bytes(&mut rand).unwrap();
        H {
            version: version,
            bits: bits,
            date: Utc::now(),
            counter: buffer,
            rand: rand,
        }
    }
}

impl fmt::Display for H {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode_block(&self.rand))
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
