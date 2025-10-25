use std::sync::OnceLock;

use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use super::tools::{
    bigint_to_little_endian_bytes, little_endian_bytes_to_bigint, mod_reduce, pow_mod,
};

#[derive(Debug, Clone)]
pub struct Curve25519KeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

struct CurveConstants {
    p: BigInt,
    j: BigInt,
    c3: BigInt,
    c4: BigInt,
    a24: BigInt,
}

fn constants() -> &'static CurveConstants {
    static INSTANCE: OnceLock<CurveConstants> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let p = (BigInt::one() << 255) - BigInt::from(19);
        let j = BigInt::from(486_662i64);
        let c3 = BigInt::parse_bytes(
            b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
            10,
        )
        .expect("invalid constant");
        let c4 = (&p - BigInt::from(5u8)) >> 3; // (p-5)/8
        let a24 = (&j + BigInt::from(2u8)) >> 2; // (J+2)/4
        CurveConstants { p, j, c3, c4, a24 }
    })
}

fn decode_scalar(scalar: &[u8]) -> BigInt {
    assert_eq!(scalar.len(), 32);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(scalar);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    little_endian_bytes_to_bigint(&clamped)
}

fn decode_coordinate(coordinate: &[u8]) -> BigInt {
    assert_eq!(coordinate.len(), 32);
    let mut point = [0u8; 32];
    point.copy_from_slice(coordinate);
    point[31] &= 0x7f;
    little_endian_bytes_to_bigint(&point)
}

fn encode_coordinate(value: BigInt) -> [u8; 32] {
    let bytes = bigint_to_little_endian_bytes(value, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn conditional_swap(mut a: BigInt, mut b: BigInt, swap: bool) -> (BigInt, BigInt) {
    if swap {
        std::mem::swap(&mut a, &mut b);
    }
    (a, b)
}

fn ladder_operation(
    ctx: &CurveConstants,
    x1: &BigInt,
    x2: &BigInt,
    z2: &BigInt,
    x3: &BigInt,
    z3: &BigInt,
) -> (BigInt, BigInt, BigInt, BigInt) {
    let p = &ctx.p;
    let a = mod_reduce(x2 + z2, p);
    let aa = mod_reduce(&a * &a, p);
    let b = mod_reduce(x2 - z2, p);
    let bb = mod_reduce(&b * &b, p);
    let e = mod_reduce(&aa - &bb, p);
    let c = mod_reduce(x3 + z3, p);
    let d = mod_reduce(x3 - z3, p);
    let da = mod_reduce(&d * &a, p);
    let cb = mod_reduce(&c * &b, p);
    let t0 = mod_reduce(&da + &cb, p);
    let x5 = mod_reduce(&t0 * &t0, p);
    let t1 = mod_reduce(&da - &cb, p);
    let t2 = mod_reduce(&t1 * &t1, p);
    let z5 = mod_reduce(x1 * t2, p);
    let x4 = mod_reduce(&aa * &bb, p);
    let t3 = mod_reduce(&ctx.a24 * &e, p);
    let t4 = mod_reduce(&bb + &t3, p);
    let z4 = mod_reduce(&e * &t4, p);
    (x4, z4, x5, z5)
}

pub fn curve25519(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let ctx = constants();
    let p = &ctx.p;
    let k = decode_scalar(private_key);
    let u = mod_reduce(decode_coordinate(public_key), p);

    let x1 = u.clone();
    let mut x2 = BigInt::one();
    let mut z2 = BigInt::zero();
    let mut x3 = u.clone();
    let mut z3 = BigInt::one();
    let mut swap = 0;

    for i in (0..255).rev() {
        let bit = ((&k >> (i as u32)) & BigInt::one()).to_u8().unwrap();
        swap ^= bit;
        let (nx2, nx3) = conditional_swap(x2, x3, swap != 0);
        x2 = nx2;
        x3 = nx3;
        let (nz2, nz3) = conditional_swap(z2, z3, swap != 0);
        z2 = nz2;
        z3 = nz3;
        swap = bit;
        let (rx2, rz2, rx3, rz3) = ladder_operation(ctx, &x1, &x2, &z2, &x3, &z3);
        x2 = rx2;
        z2 = rz2;
        x3 = rx3;
        z3 = rz3;
    }

    let (x2, _x3) = conditional_swap(x2, x3, swap != 0);
    let (z2, _z3) = conditional_swap(z2, z3, swap != 0);

    let z2_inv = pow_mod(&z2, &(p - BigInt::from(2u8)), p);
    let x = mod_reduce(&x2 * z2_inv, p);
    encode_coordinate(x)
}

pub fn get_curve25519_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> Curve25519KeyPair {
    let mut random_priv = [0u8; 32];
    rng.fill_bytes(&mut random_priv);
    random_priv[0] &= 248;
    random_priv[31] &= 127;
    random_priv[31] |= 64;

    let secret = StaticSecret::from(random_priv);
    let public = PublicKey::from(&secret);
    Curve25519KeyPair {
        public_key: public.to_bytes(),
        private_key: random_priv,
    }
}

pub fn derive_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    public.to_bytes()
}

pub fn diffie_hellman(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*public_key);
    secret.diffie_hellman(&public).to_bytes()
}

pub fn elligator2(input: &[u8; 32]) -> [u8; 32] {
    let ctx = constants();
    let p = &ctx.p;
    let j = &ctx.j;
    let c3 = &ctx.c3;
    let c4 = &ctx.c4;

    let mut u = decode_coordinate(input);
    u = mod_reduce(u, p);

    let mut tv1 = mod_reduce(&u * &u, p);
    tv1 = mod_reduce(BigInt::from(2u8) * tv1, p);
    let xd = mod_reduce(&tv1 + BigInt::one(), p);
    let x1n = mod_reduce(-j + p, p);
    let mut tv2 = mod_reduce(&xd * &xd, p);
    let gxd = mod_reduce(&tv2 * &xd, p);
    let mut gx1 = mod_reduce(j * &tv1, p);
    gx1 = mod_reduce(&gx1 * &x1n, p);
    gx1 = mod_reduce(&gx1 + &tv2, p);
    gx1 = mod_reduce(&gx1 * &x1n, p);

    let mut tv3 = mod_reduce(&gxd * &gxd, p);
    tv2 = mod_reduce(&tv3 * &tv3, p);
    tv3 = mod_reduce(&tv3 * &gxd, p);
    tv3 = mod_reduce(&tv3 * &gx1, p);
    tv2 = mod_reduce(&tv2 * &tv3, p);

    let mut y11 = pow_mod(&tv2, c4, p);
    y11 = mod_reduce(&y11 * &tv3, p);
    let y12 = mod_reduce(&y11 * c3, p);
    tv2 = mod_reduce(&y11 * &y11, p);
    tv2 = mod_reduce(&tv2 * &gxd, p);

    let e1 = tv2 == gx1;
    let y1 = if e1 { y11 } else { y12 };
    let x2n = mod_reduce(&x1n * &tv1, p);

    tv2 = mod_reduce(&y1 * &y1, p);
    tv2 = mod_reduce(&tv2 * &gxd, p);
    let e3 = tv2 == gx1;
    let xn = if e3 { x2n } else { x1n.clone() };
    let xd_inv = pow_mod(&xd, &(p - BigInt::from(2u8)), p);
    let x = mod_reduce(&xn * xd_inv, p);

    encode_coordinate(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn diffie_hellman_matches_dalek() {
        let mut rng = StdRng::seed_from_u64(42);
        let pair_a = get_curve25519_key_pair(&mut rng);
        let pair_b = get_curve25519_key_pair(&mut rng);

        let ours = diffie_hellman(&pair_a.private_key, &pair_b.public_key);
        let secret = StaticSecret::from(pair_a.private_key);
        let public = PublicKey::from(pair_b.public_key);
        let reference = secret.diffie_hellman(&public).to_bytes();
        assert_eq!(ours, reference);
    }
}
