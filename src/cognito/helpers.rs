use num::bigint::{BigUint};
use num::{Zero};
use ring::digest;
use ring::hmac::{SigningKey, SigningContext};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Sha256, Digest};
use std::cell::RefCell;
use std::iter::repeat;
use std::ops::{Rem};

use super::tools::{FromHex, ToHex, ToBase64};
use ::error::Error;

static INIT_N: &[u8] = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/**
 * Calculate the client's public value A = g^a%N
 * with the generated random number a
 * @param {BigInteger} a Randomly generated small A.
 * @param {nodeCallback<BigInteger>} callback Called on success or error.
 * @returns {void}
 * @private
 */
fn calculate_a(g: &BigUint, a: &BigUint, n: &BigUint) -> Result<BigUint, Error> {
    let a2 = mod_exp(&g, a, &n);
    if a2.clone().rem(n) == Zero::zero() {
        Err(Error::IllegalParameterError("A mod N cannot be 0.".to_string()))
    } else {
        Ok(a2)
    }
}

/**
 * Calculate a hash from a bitArray
 * @param {Buffer} buf Value to hash.
 * @returns {String} Hex-encoded hash.
 * @private
 */
fn hash(buf: &[u8]) -> String {
    let mut hasher = Sha256::default();
    hasher.input(buf);
    let hash_hex = hasher.result().to_hex();
    repeat("0").take(64 - hash_hex.len()).collect::<String>() + &hash_hex
}

/**
 * Calculate a hash from a hex string
 * @param {String} hexStr Value to hash.
 * @returns {String} Hex-encoded hash.
 * @private
 */
fn hex_hash(hex_str: &str) -> String {
    hash(hex_str.from_hex().unwrap().as_ref())
}

/**
 * Converts a BigInteger (or hex string) to hex format padded with zeroes for hashing
 * @param {BigInteger|String} bigInt Number or string to pad.
 * @returns {String} Padded hex string.
 */
fn pad_hex(big_int: &BigUint) -> String {
    let hash_str = big_int.to_str_radix(16);
    if hash_str.len() % 2 == 1 {
        format!("0{}", hash_str)
    } else if hash_str.chars().next().map(|c| "89ABCDEFabcdef".contains(c)).unwrap_or(false) {
        format!("00{}", hash_str)
    } else {
        hash_str
    }
}

// Modular exponentiation by squaring
fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let zero = BigUint::new(vec![0]);
    let one = BigUint::new(vec![1]);
    let two = BigUint::new(vec![2]);
    let mut exp = exponent.clone();
    let mut result = one.clone();
    let mut base = base % modulus;
    while exp > zero {
        if &exp % &two == one {
            result = (result * &base) % modulus;
        }
        exp = exp >> 1;
        base = (&base * &base) % modulus;
    }
    result
}

pub struct AuthHelper {
    n: BigUint,
    g: BigUint,
    k: BigUint,
    info_bits: String,
    small_a_value: BigUint,
    pool_name: String,
    large_a_value: RefCell<Option<BigUint>>,
    u_hex_hash: RefCell<Option<String>>,
    u_value: RefCell<Option<BigUint>>,

    random_password: RefCell<Option<String>>,
    salt_to_hash_devices: RefCell<Option<String>>,
    verifier_devices: RefCell<Option<String>>,
}

impl AuthHelper {
    /**
     * Constructs a new AuthenticationHelper object
     * @param {string} PoolName Cognito user pool name.
     */
    pub fn new(pool_name: &str) -> AuthHelper {
        let n = BigUint::parse_bytes(INIT_N, 16).unwrap();
        let g = BigUint::parse_bytes(b"2", 16).unwrap();
        let kstr = format!("00{}{}", n.to_hex(), g.to_hex());
        let k = BigUint::parse_bytes(hex_hash(&kstr).as_ref(), 16).unwrap();
        let small_a_value = Self::generate_random_small_a(&n);
        AuthHelper { n, g, k,
            info_bits: "Caldera Derived Key".to_string(),
            small_a_value,
            pool_name: pool_name.to_string(),
            large_a_value: RefCell::new(None),
            u_hex_hash: RefCell::new(None),
            u_value: RefCell::new(None),

            random_password: RefCell::new(None),
            salt_to_hash_devices: RefCell::new(None),
            verifier_devices: RefCell::new(None),
        }
    }

    /**
     * @param {nodeCallback<BigInteger>} callback Called on success or error.
     * @returns {BigInteger} large A, a value generated from small A
     */
    pub fn get_large_a_value(&self) -> Result<BigUint, Error> {
        {
            let cache: &Option<BigUint> = &self.large_a_value.borrow_mut();
            if let &Some(ref a) = cache {
                return Ok(a.clone());
            }
        }

        let a = calculate_a(&self.g, &self.small_a_value, &self.n)?;

        {
            let mut cache: &mut Option<BigUint> = &mut self.large_a_value.borrow_mut();
            *cache = Some(a.clone());
        }

        Ok(a)
    }

    /**
     * helper function to generate a random big integer
     * @returns {BigInteger} a random value.
     * @private
     */
    fn generate_random_small_a(n: &BigUint) -> BigUint {
        let ring = SystemRandom::new();
        let mut random: [u8;128] = [0;128];
        ring.fill(&mut random).unwrap();
        let hex_random = random.to_hex();

        let random_big_int = BigUint::parse_bytes(&hex_random.as_bytes(), 16).unwrap();
        let small_a_big_int = random_big_int % n;

        return small_a_big_int;
    }

    /**
     * Calculate the client's value U which is the hash of A and B
     * @param {BigInteger} A Large A value.
     * @param {BigInteger} B Server B value.
     * @returns {BigInteger} Computed U value.
     * @private
     */
    fn calculate_u(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let hex_str = pad_hex(a) + &pad_hex(b);
        let u_hex_hash = hex_hash(&hex_str);
        *self.u_hex_hash.borrow_mut() = Some(u_hex_hash.clone());
        let final_u = BigUint::parse_bytes(u_hex_hash.as_bytes(), 16).unwrap();
        return final_u
    }

    /**
     * Calculate mod pow with target, value and modifier.
     * @param {BigInteger} xValue Hex hashed salted username and password.
     * @param {BigInteger} serverBValue Server B value.
     * @param {nodeCallback<BigInteger>} callback Called on success or error.
     * @returns {void}
     */
    fn compute_s(&self, x_value: &BigUint, server_b_value: &BigUint) -> BigUint {
        let n = &self.n;
        let k = &self.k;
        let x = x_value;
        let g = &self.g;
        let a = &self.small_a_value;
        let b_pub = server_b_value;
        let interm = (k * mod_exp(&g, &x, &n)) % n;
        let u = self.u_value.borrow().clone().unwrap();
        // Because we do operation in modulo N we can get: (kv + g^b) < kv
        let v = if b_pub > &interm {
            (b_pub - &interm) % n
        } else {
            (n + b_pub - &interm) % n
        };
        // S = |B - kg^x| ^ (a + ux)
        let s = mod_exp(&v, &(a + (u*x) % n), n);
        s
    }

    /**
     * Standard hkdf algorithm
     * @param {Buffer} ikm Input key material.
     * @param {Buffer} salt Salt value.
     * @returns {Buffer} Strong key material.
     * @private
     */
    fn compute_hkdf(&self, ikm: &[u8], salt: &[u8]) -> Vec<u8> {
        let s_key = SigningKey::new(&digest::SHA256, salt);
        let mut s_ctx = SigningContext::with_key(&s_key);
        s_ctx.update(ikm);
        let prk = s_ctx.sign();

        let info_bits_update = vec!(
            &self.info_bits.as_bytes().to_vec(),
            &vec!(1),
            ).into_iter().flat_map(|k| k.clone()).collect::<Vec<_>>();

        let s_key2 = SigningKey::new(&digest::SHA256, prk.as_ref());
        let mut s_ctx2 = SigningContext::with_key(&s_key2);
        s_ctx2.update(&info_bits_update);
        let hmac = s_ctx2.sign();

        hmac.as_ref()[0..16].to_vec()
    }

    /**
     * Calculates the final hkdf based on computed S value, and computed U value and the key
     * @param {String} username Username.
     * @param {String} password Password.
     * @param {BigInteger} serverBValue Server B value.
     * @param {BigInteger} salt Generated salt.
     * @param {object} callback Result callback map.
     * @returns {void}
     */
    pub fn get_password_authentication_key(&self, username: &str, password: &str, server_b_value: &BigUint, salt: &BigUint) -> Result<Vec<u8>, Error> {
        if server_b_value.rem(&self.n) == Zero::zero() {
            return Err(Error::IllegalParameterError("n cannot be zero.".to_string()));
        }

        let large_a_value = self.large_a_value.borrow_mut().clone();
        let u_value = self.calculate_u(&large_a_value.unwrap(), server_b_value);
        *self.u_value.borrow_mut() = Some(u_value.clone());

        if u_value == Zero::zero() {
            return Err(Error::IllegalParameterError("u cannot be zero.".to_string()));
        }

        let username_password = format!("{}{}:{}", self.pool_name, username, password);
        let username_password_hash = hash(&username_password.as_bytes());
        let x_value = BigUint::parse_bytes(hex_hash(&(pad_hex(salt) + &username_password_hash)).as_bytes(), 16).unwrap();

        let s_value = self.compute_s(&x_value, &server_b_value);
        let hkdf = self.compute_hkdf(&pad_hex(&s_value).from_hex().unwrap(), &pad_hex(&u_value).from_hex().unwrap());

        Ok(hkdf.clone())
    }

    /**
     * helper function to generate a random string
     * @returns {string} a random value.
     * @private
     */
    fn generate_random_string(&self) -> String {
        let ring = SystemRandom::new();
        let mut random: [u8;40] = [0;40];
        ring.fill(&mut random).unwrap();
        random.to_base64()
    }

    /**
     * Generate salts and compute verifier.
     * @param {string} deviceGroupKey Devices to generate verifier for.
     * @param {string} username User to generate verifier for.
     * @returns {void}
     */
    pub fn generate_hash_device(&self, device_group_key: &str, username: &str) {
        let random_password = self.generate_random_string();
        *self.random_password.borrow_mut() = Some(random_password.to_string());
        let combined_string = format!("{}{}:{}", device_group_key, username, random_password);
        let hashed_string = hash(combined_string.as_bytes());

        let ring = SystemRandom::new();
        let mut random: [u8;16] = [0;16];
        ring.fill(&mut random).unwrap();
        let hex_random = random.to_hex();

        let salt_to_hash_devices = pad_hex(&BigUint::parse_bytes(hex_random.as_bytes(), 16).unwrap());
        *self.salt_to_hash_devices.borrow_mut() = Some(salt_to_hash_devices.clone());

        let result = mod_exp(&self.g, &BigUint::parse_bytes(hex_hash(&format!("{}{}", salt_to_hash_devices, hashed_string)).as_bytes(), 16).unwrap(), &self.n);
        let verifier_devices_not_padded = result;
        *self.verifier_devices.borrow_mut() = Some(pad_hex(&verifier_devices_not_padded));
    }

    /**
     * @returns {string} Generated random value included in password hash.
     */
    pub fn get_random_password(&self) -> String {
        self.random_password.borrow().clone().unwrap()
    }

    /**
     * @returns {string} Generated random value included in devices hash.
     */
    pub fn get_salt_devices(&self) -> String {
        self.salt_to_hash_devices.borrow().clone().unwrap()
    }

    /**
     * @returns {string} Value used to verify devices.
     */
    pub fn get_verifier_devices(&self) -> String {
        self.verifier_devices.borrow().clone().unwrap()
    }
}
