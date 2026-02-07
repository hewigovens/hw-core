use std::sync::OnceLock;

use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};
use rand::{CryptoRng, Rng};
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

pub fn get_curve25519_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> Curve25519KeyPair {
    let mut random_priv = [0u8; 32];
    rng.fill(&mut random_priv);
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
    // conditionalMove(x2n, x1n, e3): choose x1n when e3 is true, otherwise x2n.
    let xn = if e3 { x1n.clone() } else { x2n };
    let xd_inv = pow_mod(&xd, &(p - BigInt::from(2u8)), p);
    let x = mod_reduce(&xn * xd_inv, p);

    encode_coordinate(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

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

    #[test]
    fn curve25519_matches_dalek_for_arbitrary_u_coordinate() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..64 {
            let mut private_key = [0u8; 32];
            rng.fill(&mut private_key);
            let mut u_coordinate = [0u8; 32];
            rng.fill(&mut u_coordinate);
            // RFC7748 decodeUCoordinate ignores the top bit.
            u_coordinate[31] &= 0x7f;

            let ours = curve25519(&private_key, &u_coordinate);

            let secret = StaticSecret::from(private_key);
            let public = PublicKey::from(u_coordinate);
            let reference = secret.diffie_hellman(&public).to_bytes();
            assert_eq!(ours, reference);
        }
    }

    #[test]
    fn elligator2_matches_trezor_suite_fixtures() {
        // Copied from trezor-suite packages/protocol/tests/protocol-thp/curve25519.fixtures.ts
        let fixtures = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12",
                "04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e",
            ),
            (
                "673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f",
                "242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e",
            ),
            (
                "990b30e04e1c3620b4162b91a33429bddb9f1b70f1da6e5f76385ed3f98ab131",
                "998e98021eb4ee653effaa992f3fae4b834de777a953271baaa1fa3fef6b776e",
            ),
            (
                "341a60725b482dd0de2e25a585b208433044bc0a1ba762442df3a0e888ca063c",
                "683a71d7fca4fc6ad3d4690108be808c2e50a5af3174486741d0a83af52aeb01",
            ),
            (
                "922688fa428d42bc1fa8806998fbc5959ae801817e85a42a45e8ec25a0d7541a",
                "696f341266c64bcfa7afa834f8c34b2730be11c932e08474d1a22f26ed82410b",
            ),
            (
                "0d3b0eb88b74ed13d5f6a130e03c4ad607817057dc227152827c0506a538bb3a",
                "0b00df174d9fb0b6ee584d2cf05613130bad18875268c38b377e86dfefef177f",
            ),
            (
                "01a3ea5658f4e00622eeacf724e0bd82068992fae66ed2b04a8599be16662e35",
                "7ae4c58bc647b5646c9f5ae4c2554ccbf7c6e428e7b242a574a5a9c293c21f7e",
            ),
            (
                "1d991dff82a84afe97874c0f03a60a56616a15212fbe10d6c099aa3afcfabe35",
                "f81f235696f81df90ac2fc861ceee517bff611a394b5be5faaee45584642fb0a",
            ),
            (
                "185435d2b005a3b63f3187e64a1ef3582533e1958d30e4e4747b4d1d3376c728",
                "f938b1b320abb0635930bd5d7ced45ae97fa8b5f71cc21d87b4c60905c125d34",
            ),
        ];

        for (input, expected) in fixtures {
            let input_bytes = decode(input).expect("valid hex");
            let expected_bytes = decode(expected).expect("valid hex");
            let input_arr: [u8; 32] = input_bytes.as_slice().try_into().expect("32 bytes");
            let expected_arr: [u8; 32] = expected_bytes.as_slice().try_into().expect("32 bytes");
            assert_eq!(elligator2(&input_arr), expected_arr);
        }
    }
}
