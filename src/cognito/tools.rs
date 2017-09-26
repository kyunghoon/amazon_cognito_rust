use num::bigint::BigUint;
use base64::{encode};

pub static DEFAULT_USER_AGENT: &'static str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";

pub trait FromHex {
    fn from_hex(&self) -> Option<Vec<u8>>;
}

impl FromHex for str {
    fn from_hex(&self) -> Option<Vec<u8>> {
        // This may be an overestimate if there is any whitespace
        let mut b = Vec::with_capacity(self.len() / 2);
        let mut modulus = 0;
        let mut buf = 0;

        for (_idx, byte) in self.bytes().enumerate() {
            buf <<= 4;

            match byte {
                b'A'...b'F' => buf |= byte - b'A' + 10,
                b'a'...b'f' => buf |= byte - b'a' + 10,
                b'0'...b'9' => buf |= byte - b'0',
                b' '|b'\r'|b'\n'|b'\t' => {
                    buf >>= 4;
                    continue
                }
                _ => {
                    return None;
                }
            }

            modulus += 1;
            if modulus == 2 {
                modulus = 0;
                b.push(buf);
            }
        }

        match modulus {
            0 => Some(b.into_iter().collect()),
            _ => None
        }
    }
}

pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl ToHex for Vec<u8> {
    fn to_hex(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    }
}

impl ToHex for BigUint {
    fn to_hex(&self) -> String {
        self.to_bytes_be().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    }
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    }
}

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl ToBase64 for [u8] {
    fn to_base64(&self) -> String {
        encode(self)
    }
}
