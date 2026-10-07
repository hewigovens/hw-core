use num_bigint::{BigInt, Sign};
use num_traits::{ToPrimitive, Zero};
use sha2::{Digest, Sha256};

pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(super) fn hash_of_two(first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

pub(super) fn big_endian_bytes_to_bigint(bytes: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    for &b in bytes {
        result = (result << 8) + BigInt::from(b);
    }
    result
}

pub(super) fn little_endian_bytes_to_bigint(bytes: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    for (i, &b) in bytes.iter().enumerate() {
        let term = BigInt::from(b) << (8 * i);
        result += term;
    }
    result
}

pub(super) fn bigint_to_little_endian_bytes(
    mut value: BigInt,
    length: usize,
) -> Result<Vec<u8>, &'static str> {
    if value.sign() == Sign::Minus {
        return Err("negative value not supported");
    }
    let mut out = vec![0u8; length];
    for byte in out.iter_mut() {
        // SAFETY: & 0xFF guarantees value in [0, 255]
        let b = (&value & BigInt::from(0xffu8)).to_u8().unwrap();
        *byte = b;
        value >>= 8;
    }
    Ok(out)
}

pub(super) fn mod_reduce(value: BigInt, modulus: &BigInt) -> BigInt {
    let mut v = value % modulus;
    if v.sign() == Sign::Minus {
        v += modulus;
    }
    v
}

pub(super) fn pow_mod(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    base.modpow(exp, modulus)
}
