pub mod arithmetic;
pub mod pedersen;
//pub mod proofs;
pub mod utils;

use arithmetic::Modular;
pub use bigint::U256;

pub trait Cycle<C: Curve>: Curve {
    fn is_cycle() -> bool {
        Self::PRIME_MODULUS == C::ORDER
    }
}

pub trait Curve: Clone + Copy + std::fmt::Debug + PartialEq + Eq {
    const PRIME_MODULUS: U256;
    const ORDER: U256;
    const GENERATOR_X: U256;
    const GENERATOR_Y: U256;
    const COEFF_A: U256;
    const COEFF_B: U256;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Secp256k1;

impl Curve for Secp256k1 {
    const PRIME_MODULUS: U256 =
        U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    const ORDER: U256 =
        U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const GENERATOR_X: U256 =
        U256::from_be_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const GENERATOR_Y: U256 =
        U256::from_be_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    const COEFF_A: U256 = U256::ZERO;
    const COEFF_B: U256 = U256::from_u8(7);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tom256k1;

impl Curve for Tom256k1 {
    const PRIME_MODULUS: U256 =
        U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const ORDER: U256 =
        U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    const GENERATOR_X: U256 =
        U256::from_be_hex("ac81a9587b8da43a9519bd50d96191fd8f2c4f66b8f1550e366e3c7f9ed18897");

    const GENERATOR_Y: U256 =
        U256::from_be_hex("6ad7d16db13c428e5dce61c8bfe2b3860a306d201f059826120e7ac684ee209f");
    const COEFF_A: U256 = U256::ZERO;
    const COEFF_B: U256 = U256::from_u8(7);
}

impl Cycle<Secp256k1> for Tom256k1 {}

use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub fn wasm_build_test(bignum: String) -> String {
    let parsed = u32::from_str_radix(&bignum, 16).unwrap_or(0xe2);
    let mut rng = rand_core::OsRng;
    let p = pedersen::PedersenGenerator::<Tom256k1>::new(&mut rng);
    let s = arithmetic::Scalar::new(U256::from_u32(parsed));
    let commitment = p.commit(&mut rng, s);

    format!("{}", commitment.randomness().inner())
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestCurve;

    impl Curve for TestCurve {
        const PRIME_MODULUS: U256 =
            U256::from_be_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        const ORDER: U256 = U256::ONE;
        const GENERATOR_X: U256 = U256::ONE;

        const GENERATOR_Y: U256 = U256::ONE;
        const COEFF_A: U256 = U256::ONE;
        const COEFF_B: U256 = U256::ONE;
    }

    impl Cycle<TestCurve> for Tom256k1 {}

    #[test]
    fn cycle_check() {
        assert!(<Tom256k1 as Cycle<Secp256k1>>::is_cycle());
        assert!(!<Tom256k1 as Cycle<TestCurve>>::is_cycle());
    }
}
