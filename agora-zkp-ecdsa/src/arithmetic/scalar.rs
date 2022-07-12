use super::modular::{mod_u256, random_mod_u256, Modular};
use crate::curve::Curve;
use crate::rng::CryptoCoreRng;
use crate::U256;

use bigint::Encoding;
use borsh::{BorshDeserialize, BorshSerialize};

use std::cmp::{Ord, Ordering, PartialOrd};
use std::marker::PhantomData;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar<C>(U256, PhantomData<C>);

impl<C: Curve> PartialOrd for Scalar<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // NOTE: Constant time comparation could be used for further security
        Some(self.0.cmp(&other.0))
    }
}

impl<C: Curve> Ord for Scalar<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<C: Curve> Scalar<C> {
    pub const ONE: Self = Self(U256::ONE, PhantomData);
    pub const ZERO: Self = Self(U256::ZERO, PhantomData);

    pub fn pad_to_equal_len_strings(&self, other: &Self) -> (String, String) {
        let self_string = self.to_unpadded_string();
        let other_string = other.to_unpadded_string();
        // string represetnation length is at most 64 characters, so it's safe to cast to isize
        let pad_len = (self_string.len() as isize - other_string.len() as isize).abs();
        let mut padded = "0".repeat(pad_len as usize);
        if self_string.len() < other_string.len() {
            padded.push_str(&self_string);
            (padded, other_string)
        } else {
            padded.push_str(&other_string);
            (self_string, padded)
        }
    }

    pub fn to_unpadded_string(self) -> String {
        self.0
            .to_string()
            .chars()
            .skip_while(|&c| c == '0')
            .collect()
    }

    pub fn random<R: CryptoCoreRng>(rng: &mut R) -> Self {
        random_mod_u256::<Self, R>(rng)
    }
}

impl<C: Curve> Modular for Scalar<C> {
    const MODULUS: U256 = C::ORDER;

    fn new(number: U256) -> Self {
        Self(mod_u256(&number, &Self::MODULUS), PhantomData)
    }

    fn inner(&self) -> &U256 {
        &self.0
    }
}

impl<C> BorshSerialize for Scalar<C> {
    #[inline]
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0.to_le_bytes(), writer)?;
        Ok(())
    }
}

impl<C> BorshDeserialize for Scalar<C> {
    #[inline]
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        if buf.len() < 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected length of input",
            ));
        }

        let bytes: [u8; 32] = buf[..32].try_into().unwrap();
        let inner = U256::from_le_bytes(bytes);

        *buf = &buf[32..];

        Ok(Self(inner, PhantomData::<C>))
    }
}

impl<C: Curve> std::ops::Add for Scalar<C> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Modular::add(&self, &rhs)
    }
}

impl<C: Curve> std::ops::AddAssign for Scalar<C> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<C: Curve> std::ops::Sub for Scalar<C> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Modular::sub(&self, &rhs)
    }
}

impl<C: Curve> std::ops::SubAssign for Scalar<C> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<C: Curve> std::ops::Neg for Scalar<C> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Modular::neg(&self)
    }
}

impl<C: Curve> std::ops::Mul for Scalar<C> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Modular::mul(&self, &rhs)
    }
}

impl<'a, 'b, C: Curve> std::ops::Mul<&'b Scalar<C>> for &'a Scalar<C> {
    type Output = Scalar<C>;
    fn mul(self, rhs: &'b Scalar<C>) -> Self::Output {
        Modular::mul(self, rhs)
    }
}

impl<C: Curve> std::ops::MulAssign for Scalar<C> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<C: Curve> std::fmt::Display for Scalar<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::{Secp256k1, Tom256k1};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestCurveSmallMod;

    impl Curve for TestCurveSmallMod {
        const PRIME_MODULUS: U256 = U256::ONE;
        const ORDER: U256 = U256::from_u32(17);
        const GENERATOR_X: U256 = U256::ZERO;
        const GENERATOR_Y: U256 = U256::ZERO;
        const COEFF_A: U256 = U256::ZERO;
        const COEFF_B: U256 = U256::ZERO;
    }

    type ScalarSmall = Scalar<TestCurveSmallMod>;
    type ScalarLarge = Scalar<Secp256k1>;

    #[test]
    fn operations_with_small_modulus() {
        let a = ScalarSmall::new(U256::from_u32(15));
        let b = ScalarSmall::new(U256::from_u32(9));
        assert!(a != ScalarSmall::ZERO);
        assert!(b != ScalarSmall::ZERO);
        assert_eq!(a * b, ScalarSmall::new(U256::from_u32(16)));
        assert_eq!(a + b, ScalarSmall::new(U256::from_u32(7)));
        assert_eq!(a - b, ScalarSmall::new(U256::from_u32(6)));
        assert_eq!(b - a, ScalarSmall::new(U256::from_u32(11)));
    }

    #[test]
    fn operations_with_large_modulus() {
        let a = ScalarLarge::new(U256::from_be_hex(
            "000000000000000000000000000000000000000ffffaaaabbbb123456789eeee",
        ));
        let b = ScalarLarge::new(U256::from_be_hex(
            "000000000000000000000000000012345678901234567890ffffddddeeee7890",
        ));
        assert!(a != ScalarLarge::ZERO);
        assert!(b != ScalarLarge::ZERO);
        assert_eq!(
            a + b,
            ScalarLarge::new(U256::from_be_hex(
                "00000000000000000000000000001234567890223451233cbbb101235678677e"
            ))
        );
        assert_eq!(
            a * b,
            ScalarLarge::new(U256::from_be_hex(
                "000123450671f20a8b0a93d71f37ba2ec0d166be8a54889e735d97664ad9f5e0"
            ))
        );
        let a = ScalarLarge::new(Secp256k1::GENERATOR_X);
        let b = ScalarLarge::new(Secp256k1::GENERATOR_Y);
        assert_eq!(
            a + b,
            ScalarLarge::new(U256::from_be_hex(
                "c1f940f620808011b3455e91dc9813afffb3b123d4537cf2f63a51eb1208ec50"
            ))
        );
        assert_eq!(
            a * b,
            ScalarLarge::new(U256::from_be_hex(
                "805714a252d0c0b58910907e85b5b801fff610a36bdf46847a4bf5d9ae2d10ed"
            ))
        );

        let a_min_b = a - b;
        let b_min_a = b - a;
        assert_eq!(a_min_b, -b_min_a);

        assert_eq!(
            a_min_b,
            ScalarLarge::new(U256::from_be_hex(
                "31838c07d338f746f7fb6699c076025e058448928748d4bfbdaab0cb1be742e0"
            ))
        );
        assert_eq!(
            b_min_a,
            ScalarLarge::new(U256::from_be_hex(
                "ce7c73f82cc708b9080499663f89fda0b52a945427ffcb7c0227adc1b44efe61"
            ))
        );

        // tom curve generator points summed/multiplied using secp256k1 order as modulus
        let a = ScalarLarge::new(Tom256k1::GENERATOR_X);
        let b = ScalarLarge::new(Tom256k1::GENERATOR_Y);
        assert_eq!(
            a + b,
            ScalarLarge::new(U256::from_be_hex(
                "17597ac62cc9e6c8f2e81f1999444584deaddfa028ae4cf888aa58b9538967f5"
            ))
        );
        assert_eq!(
            a * b,
            ScalarLarge::new(U256::from_be_hex(
                "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840"
            ))
        );

        let a_min_b = a - b;
        let b_min_a = b - a;
        assert_eq!(a_min_b, -b_min_a);
    }

    fn pad_to_64(string: &str) -> String {
        format!("{:0>64}", string)
    }

    #[test]
    fn unpad_display() {
        let a = ScalarLarge::new(U256::from_u8(0xb1));
        let b = ScalarLarge::new(U256::from_be_hex(
            "00000000000000000000000000001234567890223451233cbbb101235678677e",
        ));
        let c = ScalarLarge::new(U256::from_be_hex(
            "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840",
        ));

        assert_eq!(a.to_string(), pad_to_64("b1").to_uppercase());
        assert_eq!(
            b.to_string(),
            pad_to_64("01234567890223451233cbbb101235678677e").to_uppercase()
        );
        assert_eq!(
            c.to_string(),
            "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840".to_uppercase()
        );

        assert_eq!(a.to_unpadded_string(), "B1");
        assert_eq!(
            b.to_unpadded_string(),
            "1234567890223451233cbbb101235678677e".to_uppercase()
        );
        assert_eq!(c.to_unpadded_string(), c.to_string());
    }

    #[test]
    fn pad_to_equal_length() {
        let a = ScalarLarge::new(U256::from_u8(0xb1));
        let b = ScalarLarge::new(U256::from_be_hex(
            "00000000000000000000000000001234567890223451233cbbb101235678677e",
        ));
        let c = ScalarLarge::new(U256::from_be_hex(
            "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840",
        ));

        let (a_string, same_len_string) =
            a.pad_to_equal_len_strings(&ScalarLarge::new(U256::from_u8(0xfe)));
        assert_eq!(a_string.len(), same_len_string.len());
        assert_eq!(a_string, "B1");
        assert_eq!(same_len_string, "FE");

        let (a_string, b_string) = a.pad_to_equal_len_strings(&b);
        assert_eq!(a_string.len(), b_string.len());
        assert_eq!(a_string, "0000000000000000000000000000000000B1");
        assert_eq!(
            b_string,
            "1234567890223451233cbbb101235678677e".to_uppercase()
        );

        let (b_string, a_string) = b.pad_to_equal_len_strings(&a);
        assert_eq!(a_string.len(), b_string.len());
        assert_eq!(a_string, "0000000000000000000000000000000000B1");
        assert_eq!(
            b_string,
            "1234567890223451233cbbb101235678677e".to_uppercase()
        );

        let (b_string, c_string) = b.pad_to_equal_len_strings(&c);
        assert_eq!(b_string.len(), c_string.len());
        assert_eq!(
            b_string,
            "00000000000000000000000000001234567890223451233cbbb101235678677e".to_uppercase()
        );
        assert_eq!(
            c_string,
            "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840".to_uppercase()
        );

        let (c_string, b_string) = c.pad_to_equal_len_strings(&b);
        assert_eq!(b_string.len(), c_string.len());
        assert_eq!(
            b_string,
            "00000000000000000000000000001234567890223451233cbbb101235678677e".to_uppercase()
        );
        assert_eq!(
            c_string,
            "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840".to_uppercase()
        );
    }

    #[test]
    fn random_pad_to_equal_len() {
        let mut rng = rand_core::OsRng;
        for _ in 0..50 {
            let random = ScalarLarge::random(&mut rng);
            let random_expected = U256::from_be_hex(&random.to_string());
            assert_eq!(random.inner(), &random_expected);
        }
    }

    #[test]
    fn inverse() {
        let mut a = ScalarSmall::new(U256::from_u8(10));
        assert!(a != ScalarSmall::ZERO);
        assert_eq!(a * a.inverse(), ScalarSmall::ONE);
        a = ScalarSmall::new(U256::from_u8(59));
        assert_eq!(a * a.inverse(), ScalarSmall::ONE);

        let mut b = ScalarLarge::new(U256::from_be_hex(
            "c1f940f620808011b3455e91dc9813afffb3b123d4537cf2f63a51eb1208ec50",
        ));
        assert!(b != ScalarLarge::ZERO);
        assert_eq!(b * b.inverse(), ScalarLarge::ONE);

        b = ScalarLarge::new(U256::from_be_hex(
            "354880368b136b492e8cbce77a7b5ffc3dbef5087bc30537b87ca9d57648c840",
        ));
        assert_eq!(b * b.inverse(), ScalarLarge::ONE);
        b = ScalarLarge::new(Tom256k1::ORDER);
        assert_eq!(b * b.inverse(), ScalarLarge::ONE);
        b = ScalarLarge::new(Secp256k1::GENERATOR_X);
        assert_eq!(b * b.inverse(), ScalarLarge::ONE);
    }

    #[test]
    fn serde_round() {
        let le_hex = "ce7c73f82cc708b9080499663f89fda1fa7bb76d78b72b4042554f33e418b94f";
        let sc = Scalar(U256::from_le_hex(le_hex), PhantomData::<Tom256k1>);

        let serialized = sc.try_to_vec().unwrap();
        let deserialized = borsh::BorshDeserialize::try_from_slice(&serialized).unwrap();
        assert_eq!(sc, deserialized);
    }
}
