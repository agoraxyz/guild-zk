use super::modular::{mod_u256, Modular};
use super::Scalar;
use crate::curve::{Curve, Cycle};
use crate::U256;

use bigint::Encoding;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Serialize, Serializer};

use std::marker::PhantomData;

use std::fmt;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct FieldElement<C>(pub(super) U256, pub(super) PhantomData<C>);

impl<C: Curve> FieldElement<C> {
    pub const ONE: Self = Self(U256::ONE, PhantomData);
    pub const ZERO: Self = Self(U256::ZERO, PhantomData);

    pub fn to_cycle_scalar<CC: Cycle<C>>(self) -> Scalar<CC> {
        Scalar::<CC>::new(self.0)
    }
}

impl<C: Curve> Modular for FieldElement<C> {
    const MODULUS: U256 = C::PRIME_MODULUS;

    fn new(number: U256) -> Self {
        Self(mod_u256(&number, &Self::MODULUS), PhantomData)
    }

    fn inner(&self) -> &U256 {
        &self.0
    }
}

impl<C: Curve> Serialize for FieldElement<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_le_bytes(), serializer)
    }
}

impl<C> BorshSerialize for FieldElement<C> {
    #[inline]
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0.to_le_bytes(), writer)?;
        Ok(())
    }
}

impl<C> BorshDeserialize for FieldElement<C> {
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

impl<'a, 'b, C: Curve> std::ops::Add<&'b FieldElement<C>> for &'a FieldElement<C> {
    type Output = FieldElement<C>;
    fn add(self, rhs: &'b FieldElement<C>) -> Self::Output {
        Modular::add(self, rhs)
    }
}

impl<C: Curve> std::ops::Add for FieldElement<C> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Modular::add(&self, &rhs)
    }
}

impl<C: Curve> std::ops::AddAssign for FieldElement<C> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<C: Curve> std::ops::AddAssign<&FieldElement<C>> for FieldElement<C> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = &*self + rhs;
    }
}

impl<C: Curve> std::ops::Sub for FieldElement<C> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Modular::sub(&self, &rhs)
    }
}

impl<'a, 'b, C: Curve> std::ops::Sub<&'b FieldElement<C>> for &'a FieldElement<C> {
    type Output = FieldElement<C>;
    fn sub(self, rhs: &FieldElement<C>) -> Self::Output {
        Modular::sub(self, rhs)
    }
}

impl<C: Curve> std::ops::SubAssign for FieldElement<C> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<C: Curve> std::ops::Neg for FieldElement<C> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Modular::neg(&self)
    }
}

impl<C: Curve> std::ops::Mul for FieldElement<C> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Modular::mul(&self, &rhs)
    }
}

impl<C: Curve> std::ops::Mul<&FieldElement<C>> for FieldElement<C> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        Modular::mul(&self, rhs)
    }
}

impl<'a, 'b, C: Curve> std::ops::Mul<&'b FieldElement<C>> for &'a FieldElement<C> {
    type Output = FieldElement<C>;
    fn mul(self, rhs: &FieldElement<C>) -> Self::Output {
        Modular::mul(self, rhs)
    }
}

impl<C: Curve> std::ops::MulAssign for FieldElement<C> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<C: Curve> std::ops::MulAssign<&FieldElement<C>> for FieldElement<C> {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl<C: Curve> fmt::Display for FieldElement<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::{Secp256k1, Tom256k1};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestCurveSmallMod;

    impl Curve for TestCurveSmallMod {
        const PRIME_MODULUS: U256 = U256::from_u32(17);
        const ORDER: U256 = U256::ONE;
        const GENERATOR_X: U256 = U256::ZERO;
        const GENERATOR_Y: U256 = U256::ZERO;
        const COEFF_A: U256 = U256::ZERO;
        const COEFF_B: U256 = U256::ZERO;
    }

    type FeSmall = FieldElement<TestCurveSmallMod>;
    type FeLarge = FieldElement<Secp256k1>;

    #[test]
    fn operations_with_small_modulus() {
        let a = FeSmall::new(U256::from_u32(15));
        let b = FeSmall::new(U256::from_u32(9));
        assert_eq!(a * b, FeSmall::new(U256::from_u32(16)));
        assert_eq!(a + b, FeSmall::new(U256::from_u32(7)));
        assert_eq!(a - b, FeSmall::new(U256::from_u32(6)));
        assert_eq!(b - a, FeSmall::new(U256::from_u32(11)));
    }

    #[test]
    fn operations_with_large_modulus() {
        let a = FeLarge::new(U256::from_be_hex(
            "000000000000000000000000000000000000000ffffaaaabbbb123456789eeee",
        ));
        let b = FeLarge::new(U256::from_be_hex(
            "000000000000000000000000000012345678901234567890ffffddddeeee7890",
        ));
        let sum = a + b;
        assert_eq!(
            sum,
            FeLarge::new(U256::from_be_hex(
                "00000000000000000000000000001234567890223451233cbbb101235678677e"
            ))
        );
        assert!(sum.0 != U256::ZERO);
        let prod = a * b;
        assert_eq!(
            prod,
            FeLarge::new(U256::from_be_hex(
                "000123450671f20a8b0a93d71f37ba2ec0d166be8a54889e735d97664ad9f5e0"
            ))
        );
        assert!(prod.0 != U256::ZERO);

        let a = FeLarge::new(Secp256k1::GENERATOR_X);
        let b = FeLarge::new(Secp256k1::GENERATOR_Y);
        assert_eq!(
            a + b,
            FeLarge::new(U256::from_be_hex(
                "c1f940f620808011b3455e91dc9813afffb3b123d4537cf2f63a51eb1208ec50"
            ))
        );
        assert_eq!(
            a * b,
            FeLarge::new(U256::from_be_hex(
                "fd3dc529c6eb60fb9d166034cf3c1a5a72324aa9dfd3428a56d7e1ce0179fd9b"
            ))
        );

        let a_min_b = a - b;
        let b_min_a = b - a;
        assert_eq!(a_min_b, -b_min_a);

        assert_eq!(
            a_min_b,
            FeLarge::new(U256::from_be_hex(
                "31838c07d338f746f7fb6699c076025e058448928748d4bfbdaab0cb1be742e0"
            ))
        );
        assert_eq!(
            b_min_a,
            FeLarge::new(U256::from_be_hex(
                "ce7c73f82cc708b9080499663f89fda1fa7bb76d78b72b4042554f33e418b94f"
            ))
        );

        // tom curve generator points summed/multiplied using secp256k1 modulus
        let a = FeLarge::new(Tom256k1::GENERATOR_X);
        let b = FeLarge::new(Tom256k1::GENERATOR_Y);
        assert_eq!(
            a + b,
            FeLarge::new(U256::from_be_hex(
                "17597ac62cc9e6c8f2e81f1999444583995cbc86d7f6ed34487cb74723bfad07"
            ))
        );
        assert_eq!(
            a * b,
            FeLarge::new(U256::from_be_hex(
                "062869f8c96e49475ff3596b7703d46e6183d7f987513f1ede13456a91dbd48e"
            ))
        );

        let a_min_b = a - b;
        let b_min_a = b - a;
        assert_eq!(a_min_b, -b_min_a);
    }

    #[test]
    fn serde_round() {
        let le_hex = "ce7c73f82cc708b9080499663f89fda1fa7bb76d78b72b4042554f33e418b94f";
        let fe = FieldElement(U256::from_le_hex(le_hex), PhantomData::<Tom256k1>);

        let serialized = fe.try_to_vec().unwrap();
        let deserialized = borsh::BorshDeserialize::try_from_slice(&serialized).unwrap();
        assert_eq!(fe, deserialized);
    }
}
