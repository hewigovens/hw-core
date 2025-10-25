use aes_gcm::aead::{AeadInPlace, Error as AeadError, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use num_bigint::{BigInt, Sign};
use num_traits::{ToPrimitive, Zero};
use sha2::{Digest, Sha256};

pub type HmacSha256 = Hmac<Sha256>;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_of_two(first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut ctx = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take any key size");
    ctx.update(data);
    ctx.finalize().into_bytes().into()
}

pub fn hkdf(chaining_key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp_key = hmac_sha256(chaining_key, input);
    let output1 = hmac_sha256(&temp_key, &[0x01]);
    let mut ctx =
        <HmacSha256 as Mac>::new_from_slice(&temp_key).expect("HMAC can take any key size");
    ctx.update(&output1);
    ctx.update(&[0x02]);
    let output2 = ctx.finalize().into_bytes().into();
    (output1, output2)
}

pub fn get_iv_from_nonce(nonce: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&nonce.to_be_bytes());
    iv
}

pub fn aes256gcm_encrypt(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), AeadError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError)?;
    let nonce = Nonce::from_slice(iv);
    let mut buffer = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(nonce, aad, &mut buffer)?;
    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(tag.as_slice());
    Ok((buffer, tag_bytes))
}

pub fn aes256gcm_decrypt(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError)?;
    let nonce = Nonce::from_slice(iv);
    let mut buffer = ciphertext.to_vec();
    let tag_array = aes_gcm::aead::generic_array::GenericArray::from_slice(tag);
    cipher.decrypt_in_place_detached(nonce, aad, &mut buffer, tag_array)?;
    Ok(buffer)
}

pub fn big_endian_bytes_to_bigint(bytes: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    for &b in bytes {
        result = (result << 8) + BigInt::from(b);
    }
    result
}

pub fn little_endian_bytes_to_bigint(bytes: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    for (i, &b) in bytes.iter().enumerate() {
        let term = BigInt::from(b) << (8 * i);
        result += term;
    }
    result
}

pub fn bigint_to_little_endian_bytes(mut value: BigInt, length: usize) -> Vec<u8> {
    if value.sign() == Sign::Minus {
        panic!("negative value not supported");
    }
    let mut out = vec![0u8; length];
    for byte in out.iter_mut() {
        let b = (&value & BigInt::from(0xffu8)).to_u8().unwrap();
        *byte = b;
        value >>= 8;
    }
    out
}

pub fn mod_reduce(value: BigInt, modulus: &BigInt) -> BigInt {
    let mut v = value % modulus;
    if v.sign() == Sign::Minus {
        v += modulus;
    }
    v
}

pub fn pow_mod(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    base.modpow(exp, modulus)
}
