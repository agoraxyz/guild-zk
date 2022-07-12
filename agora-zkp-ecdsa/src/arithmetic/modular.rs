use crate::rng::CryptoCoreRng;
use bigint::subtle::ConstantTimeLess;
use bigint::{Encoding, NonZero, U256};
use num_bigint::BigUint;
use num_integer::Integer;

const TWO: U256 = U256::from_u8(2);

pub trait Modular: Sized {
    const MODULUS: U256;

    fn new(number: U256) -> Self;

    fn inner(&self) -> &U256;

    fn add(&self, other: &Self) -> Self {
        Self::new(self.inner().add_mod(other.inner(), &Self::MODULUS))
    }

    fn neg(&self) -> Self {
        Self::new(self.inner().neg_mod(&Self::MODULUS))
    }

    fn sub(&self, other: &Self) -> Self {
        Self::new(self.inner().sub_mod(other.inner(), &Self::MODULUS))
    }

    fn mul(&self, other: &Self) -> Self {
        Self::new(mul_mod_u256(self.inner(), other.inner(), &Self::MODULUS))
    }

    fn inverse(&self) -> Self {
        let mod_minus_two = Self::MODULUS.saturating_sub(&TWO);
        Self::new(exp_mod_u256(self.inner(), &mod_minus_two, &Self::MODULUS))
    }

    fn pow(&self, exponent: &Self) -> Self {
        Self::new(exp_mod_u256(self.inner(), exponent.inner(), &Self::MODULUS))
    }
}

pub fn mod_u256(number: &U256, modulus: &U256) -> U256 {
    // NOTE bigint's internal modulo operation
    // returns zero instead of number if number < modulus
    if number < modulus {
        *number
    } else {
        // NOTE unwrap is fine here because the modulus
        // can be safely assumed to be nonzero
        number % NonZero::new(*modulus).unwrap()
    }
}

#[cfg(target_pointer_width = "32")]
pub fn mul_mod_u256(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    let lhs_num_bigint = BigUint::from_bytes_le(&lhs.to_le_bytes());
    let rhs_num_bigint = BigUint::from_bytes_le(&rhs.to_le_bytes());
    let modulus_num_bigint = BigUint::from_bytes_le(&modulus.to_le_bytes());
    let (_, rem) = (lhs_num_bigint * rhs_num_bigint).div_mod_floor(&modulus_num_bigint);
    let rem_limbs = rem.to_u32_digits();
    let mut res = [0u32; 8];
    res[0..rem_limbs.len()].copy_from_slice(&rem_limbs);
    U256::from_words(res)
}

#[cfg(target_pointer_width = "64")]
pub fn mul_mod_u256(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    let lhs_num_bigint = BigUint::from_bytes_le(&lhs.to_le_bytes());
    let rhs_num_bigint = BigUint::from_bytes_le(&rhs.to_le_bytes());
    let modulus_num_bigint = BigUint::from_bytes_le(&modulus.to_le_bytes());
    let (_, rem) = (lhs_num_bigint * rhs_num_bigint).div_mod_floor(&modulus_num_bigint);
    let rem_limbs = rem.to_u64_digits();
    let mut res = [0u64; 4];
    res[0..rem_limbs.len()].copy_from_slice(&rem_limbs);
    U256::from_words(res)
}

fn exp_mod_u256(base: &U256, exponent: &U256, modulus: &U256) -> U256 {
    let mut r = U256::ONE;
    let mut q = *base;
    let mut k = *exponent;
    while k > U256::ZERO {
        if mod_u256(&k, &TWO) != U256::ZERO {
            // k is odd
            r = mul_mod_u256(&r, &q, modulus);
        }
        q = mul_mod_u256(&q, &q, modulus);
        k >>= 1; // division by 2
    }
    r
}

fn get_random_u256<R: CryptoCoreRng>(rng: &mut R) -> U256 {
    let mut bytes = [0_u8; 32];
    rng.fill_bytes(&mut bytes);
    U256::from_be_slice(&bytes)
}

pub fn random_mod_u256<T: Modular, R: CryptoCoreRng>(rng: &mut R) -> T {
    loop {
        let random_number = get_random_u256(rng);
        if random_number.ct_lt(&T::MODULUS).into() {
            return T::new(random_number);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mod_u256() {
        assert_eq!(mod_u256(&U256::ONE, &U256::ONE), U256::ZERO);
        assert_eq!(mod_u256(&U256::from_u8(9), &U256::from_u8(2)), U256::ONE);
        assert_eq!(
            mod_u256(&U256::from_u8(67), &U256::from_u8(17)),
            U256::from_u8(16)
        );
        assert_eq!(mod_u256(&U256::from_u8(178), &U256::from_u8(59)), U256::ONE);
        assert_eq!(
            mod_u256(&U256::from_u8(59), &U256::from_u8(178)),
            U256::from_u8(59)
        );

        let a =
            U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

        let b =
            U256::from_be_hex("fffffffffffffffffffffffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

        let expected = U256::from_u128(0x344012083fa64eb32f1c90621eb8adad);
        assert_eq!(mod_u256(&a, &b), a);
        assert_eq!(mod_u256(&b, &a), expected);
    }

    #[test]
    fn mul_mod_u256_small() {
        let modulus = U256::from_u32(0xfff1);

        let mut a = U256::from_u32(0x1f85);
        let mut b = U256::from_u32(0xdecc);
        assert_eq!(mul_mod_u256(&a, &b, &modulus), U256::from_u32(0xf8c));

        a = U256::from_u32(0x2f7a);
        b = U256::from_u32(0xb7d0);
        assert_eq!(mul_mod_u256(&a, &b, &modulus), U256::from_u32(0xc888));

        a = U256::from_u32(0xce4e);
        b = U256::from_u32(0xd6c5);
        assert_eq!(mul_mod_u256(&a, &b, &modulus), U256::from_u32(0x1ac8));

        a = U256::from_u32(0xe9b7);
        b = U256::from_u32(0x7ae9);
        assert_eq!(mul_mod_u256(&a, &b, &modulus), U256::from_u32(0x8113));

        a = U256::from_u32(0x81cf);
        b = U256::from_u32(0x5066);
        assert_eq!(mul_mod_u256(&a, &b, &modulus), U256::from_u32(0xcc14));
    }

    #[test]
    fn mul_mod_u256_medium() {
        let modulus = U256::from_u128(0xffffddddeeee01234577);
        let mut a = U256::from_u128(0x7ed884b0e74acae13d24);
        let mut b = U256::from_u128(0xa6e784d01d4a07b81612);
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_u128(0x72394745f2370b3c9ff)
        );

        a = U256::from_u128(0xce9ffee8f7253aa55e9c);
        b = U256::from_u128(0xc8facfc1741dff31d5ac);
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_u128(0xd136bceb80f3c7526553)
        );

        a = U256::from_u128(0xf14e3b80a32e6b760f06);
        b = U256::from_u128(0xc7cae1a1b0a233420225);
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_u128(0x133f243f42d8b0f64108)
        );

        a = U256::from_u128(0x9e389b90cafabbcf2e83);
        b = U256::from_u128(0x491520dbfb2dc5346c8b);
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_u128(0x83a9533a74aa04a01ca)
        );

        a = U256::from_u128(0xd9f35dd4b28e47de102f);
        b = U256::from_u128(0xdfe631cf3be44427e8c3);
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_u128(0x750f5a73304a09deddcf)
        );
    }

    #[test]
    fn mul_mod_u256_large() {
        let modulus =
            U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

        let mut a =
            U256::from_be_hex("617652b9bba98825bfe56f8632d46088bcbaf1dbac087c297682f9d2156e5139");
        let mut b =
            U256::from_be_hex("e7d95f100dfa1650113d52cde817ae2bbde56dffbe69d1b6afc5d6884934fc4c");
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_be_hex("d0febbc44b1942b614c343706e565dd7679efce7d1a630d386f7effbf5d5cf90")
        );

        a = U256::from_be_hex("5b864cf99e352a9e227727f1f7b06ae96156a8a9a8bf6870156835b19bb80da8");
        b = U256::from_be_hex("aa83f02c146c7039a039fed8fa82e2a2f48f1b40d7e88f4552d6c51222c948fc");
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_be_hex("2039e582a2799f7aafd4db598bc6eca5031e555a9c957401859137f3f95cbf52")
        );

        a = U256::from_be_hex("eff64d997f9210ac3eac68ed417b556c9d678ba590d8541d05be518c2963bc5c");
        b = U256::from_be_hex("373e807ff7fdfeda3a5abbcb0a4fe08c123b5cf04eea7b4dce47858fd4502c1b");
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_be_hex("5f3bb9c167e7c6a78402a58a102011d013f23d092b864ff48583053640d669f3")
        );

        a = U256::from_be_hex("a553049ab18ac4bc5b163c7c787f60cd7260e0ac505c7320872efaa6ffd3168e");
        b = U256::from_be_hex("9de6dfce877b25903632efa41f0e42ebc9c7a0aaa944f3efb8d60570e0b71b68");
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_be_hex("97bb5058bb25b849015eca05d389e38dc7f903519c37a2cd7e09ca32f07a6493")
        );

        a = U256::from_be_hex("9ab29bc62d7943d0b00d521fe643f571649e9761ffe0f7e6478829fcf9f80d5b");
        b = U256::from_be_hex("565a66c3586e6c0f23753cd5e84b0cd720630d7102172a42e706e4f724baf7dd");
        assert_eq!(
            mul_mod_u256(&a, &b, &modulus),
            U256::from_be_hex("72747f9ecbf73c44f9eec8071c9c53f1648db1bbca95fb19ed4f1cc62ccd4956")
        );
    }

    #[test]
    fn exp_mod_small() {
        let mut modulus = U256::from_u8(7);
        let mut base = U256::from_u8(10);
        let mut exponent = U256::ONE;
        assert_eq!(
            exp_mod_u256(&base, &exponent, &modulus),
            U256::from_u32(10 % 7)
        );

        exponent = U256::from_u8(2);
        assert_eq!(
            exp_mod_u256(&base, &exponent, &modulus),
            U256::from_u32(100 % 7)
        );

        exponent = U256::from_u8(3);
        assert_eq!(
            exp_mod_u256(&base, &exponent, &modulus),
            U256::from_u32(1000 % 7)
        );

        exponent = U256::from_u8(4);
        assert_eq!(
            exp_mod_u256(&base, &exponent, &modulus),
            U256::from_u32(10_000 % 7)
        );

        exponent = U256::from_u8(5);
        assert_eq!(
            exp_mod_u256(&base, &exponent, &modulus),
            U256::from_u32(100_000 % 7)
        );

        base = U256::from_u8(7);
        exponent = U256::from_u8(2);
        assert_eq!(exp_mod_u256(&base, &exponent, &modulus), U256::ZERO);
        exponent = U256::from_u8(117);
        assert_eq!(exp_mod_u256(&base, &exponent, &modulus), U256::ZERO);

        assert_eq!(exp_mod_u256(&U256::ZERO, &U256::ZERO, &modulus), U256::ONE);
        assert_eq!(exp_mod_u256(&U256::ONE, &U256::ZERO, &modulus), U256::ONE);
        assert_eq!(exp_mod_u256(&U256::ONE, &U256::ONE, &modulus), U256::ONE);

        modulus = U256::from_u8(117);
        exponent = U256::from_u8(2);
        assert_eq!(exp_mod_u256(&base, &exponent, &modulus), U256::from_u8(49));
    }

    #[test]
    fn exp_mod_large() {
        let modulus =
            U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut base =
            U256::from_be_hex("0716da9a723d4b60c4c45e60e785752035fe89f3d8f02948f137dac24d194d7b");
        let mut exponent =
            U256::from_be_hex("dcd079dee8977487cef48f01438107be65e843c8ae97812936b682ef1e1bb7d6");
        let mut expected =
            U256::from_be_hex("3fc52238ecd8428f2436c8d0e821a1cd6f3585e8f844a889c5bf63954a23a42e");

        assert_eq!(exp_mod_u256(&base, &exponent, &modulus), expected);

        base =
            U256::from_be_hex("f301bb587ec9213824e5877d3e46ef7f058a2a8aeca9bcd668e538baf6e83f1c");
        exponent =
            U256::from_be_hex("c2949e64cb2319b0b242b4ffc906db675770ac0063d29a6a3b693de8c56837ec");
        expected =
            U256::from_be_hex("ef361bc9c55de710dcebb4ca7a437d6c0267dd8b5afab7ca559081ea3fe5e234");

        assert_eq!(exp_mod_u256(&base, &exponent, &modulus), expected);

        base =
            U256::from_be_hex("380dc1a2dfcdf757ffe8384181a528bf918312dca7f9fcaa24d72195aeb84316");
        exponent =
            U256::from_be_hex("3a3cd1cda068afd82bf6813ebac8390732542fe7701a90035da68771c5931c65");
        expected =
            U256::from_be_hex("7f2de0f2d89077f70b423feea263590266e38e24f229ad6039cdbc09b410e4d5");

        assert_eq!(exp_mod_u256(&base, &exponent, &modulus), expected);
    }
}

#[cfg(test)]
mod random_test {
    use super::*;
    use rand_core::OsRng;

    use bigint::Encoding;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TestModular(U256);

    // assumed to be < 255
    const MOD: u32 = 17;

    impl Modular for TestModular {
        const MODULUS: U256 = U256::from_u32(MOD);
        fn new(number: U256) -> Self {
            let reduced = if number < Self::MODULUS {
                number
            } else {
                // NOTE unwrap is fine here because the modulus
                // can be safely assumed to be nonzero
                number % NonZero::new(Self::MODULUS).unwrap()
            };
            Self(reduced)
        }

        fn inner(&self) -> &U256 {
            &self.0
        }
    }

    // assumed: mod_byte_number <= 4
    // Only for tests
    fn get_random_small_modular<T: Modular, R: CryptoCoreRng>(
        mod_byte_number: u8,
        rng: &mut R,
    ) -> T {
        loop {
            let random_number_bytes = get_random_u256(rng).to_be_bytes();

            for small_bytes in random_number_bytes.chunks_exact(mod_byte_number as usize) {
                let mut random_number = 0_u32;
                for i in small_bytes.iter().take(mod_byte_number as usize) {
                    random_number = (random_number << 8) + (*i as u32);
                }
                let random_number = U256::from_u32(random_number);

                if random_number.ct_lt(&T::MODULUS).into() {
                    return T::new(random_number);
                }
            }
        }
    }

    // Don't do this if you value your time
    // It works, just trust me
    #[ignore]
    #[test]
    fn test_rand() {
        let mut vec = vec![0; MOD as usize];
        let mut rng = OsRng;
        for _ in 0..1000000 {
            let rand_num = get_random_small_modular::<TestModular, OsRng>(1, &mut rng);
            vec[rand_num.inner().into_limbs()[0].0 as usize] += 1;
        }
        println!("{:?}", vec);
    }
}
