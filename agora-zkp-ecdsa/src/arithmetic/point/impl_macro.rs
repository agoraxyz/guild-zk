use super::super::modular::{mul_mod_u256, Modular};
use super::super::Scalar;
use super::*;
use crate::curve::Curve;
use crate::U256;

use std::collections::HashMap;
use std::fmt;

use std::marker::PhantomData;

const BASE_16_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

macro_rules! impl_point_arithmetic {
    ($this:ty) => {
        impl<C: Curve> std::ops::Neg for $this {
            type Output = Self;
            fn neg(self) -> Self::Output {
                Self::Output {
                    x: self.x,
                    y: -self.y,
                    z: self.z,
                }
            }
        }

        impl<C: Curve> std::ops::Neg for &$this {
            type Output = $this;
            fn neg(self) -> Self::Output {
                Self::Output {
                    x: self.x,
                    y: -self.y,
                    z: self.z,
                }
            }
        }

        impl<C: Curve> std::ops::Add for $this {
            type Output = Point<C>;
            fn add(self, rhs: Self) -> Self::Output {
                self.geometric_add(&rhs)
            }
        }

        impl<'a, 'b, C: Curve> std::ops::Add<&'b $this> for &'a $this {
            type Output = Point<C>;
            fn add(self, rhs: &'b $this) -> Self::Output {
                self.geometric_add(rhs)
            }
        }

        impl<C: Curve> std::ops::AddAssign<&$this> for Point<C> {
            fn add_assign(&mut self, rhs: &$this) {
                *self = &*self + rhs
            }
        }

        impl<C: Curve> std::ops::Sub for $this {
            type Output = Point<C>;
            fn sub(self, rhs: Self) -> Self::Output {
                self + (-rhs)
            }
        }

        impl<'a, 'b, C: Curve> std::ops::Sub<&'b $this> for &'a $this {
            type Output = Point<C>;
            fn sub(self, rhs: &'b $this) -> Self::Output {
                self + &(-rhs)
            }
        }

        impl<C: Curve> std::ops::Mul<Scalar<C>> for &$this {
            type Output = Point<C>;
            fn mul(self, rhs: Scalar<C>) -> Self::Output {
                self.scalar_mul(&rhs)
            }
        }

        impl<'a, 'b, C: Curve> std::ops::Mul<&'b Scalar<C>> for &'a $this {
            type Output = Point<C>;
            fn mul(self, rhs: &'b Scalar<C>) -> Self::Output {
                self.scalar_mul(rhs)
            }
        }

        impl<C: Curve> $this {
            pub const IDENTITY: Self = Self {
                x: FieldElement::ZERO,
                y: FieldElement::ONE,
                z: FieldElement::ZERO,
            };

            pub const GENERATOR: Self = Self {
                x: FieldElement(C::GENERATOR_X, PhantomData),
                y: FieldElement(C::GENERATOR_Y, PhantomData),
                z: FieldElement::ONE,
            };

            #[inline(always)]
            pub fn is_identity(&self) -> bool {
                self.x() == &FieldElement::<C>::ZERO
                    && self.y() != &FieldElement::ZERO
                    && self.z() == &FieldElement::ZERO
            }

            #[inline(always)]
            pub fn x(&self) -> &FieldElement<C> {
                &self.x
            }

            #[inline(always)]
            pub fn y(&self) -> &FieldElement<C> {
                &self.y
            }

            #[inline(always)]
            pub fn z(&self) -> &FieldElement<C> {
                &self.z
            }

            pub fn is_on_curve(&self) -> bool {
                let a = FieldElement::new(C::COEFF_A);
                let b = FieldElement::new(C::COEFF_B);

                let y2 = self.y() * self.y();
                let y2z = y2 * self.z();
                let x3 = self.x() * self.x() * self.x();
                let ax = a * self.x();
                let z2 = self.z() * self.z();
                let axz2 = ax * z2;
                let z3 = z2 * self.z();
                let bz3 = b * z3;
                let t5 = y2z - (x3 + axz2 + bz3);

                t5.inner() == &U256::ZERO
            }

            pub fn double(&self) -> Point<C> {
                self + self
            }

            pub fn geometric_add(&self, rhs: &$this) -> Point<C> {
                let b3 = FieldElement::new(mul_mod_u256(
                    &U256::from_u8(3),
                    &C::COEFF_B,
                    &C::PRIME_MODULUS,
                ));
                let a = FieldElement::new(C::COEFF_A);

                let mut t0 = self.x() * rhs.x();
                let mut t1 = self.y() * rhs.y();
                let mut t2 = self.z() * rhs.z();
                let mut t3 = self.x() + self.y();
                let mut t4 = rhs.x() + rhs.y();

                t3 *= t4;
                t4 = t0 + t1;
                t3 -= t4;
                t4 = self.x() + self.z();
                let mut t5 = rhs.x() + rhs.z();

                t4 *= t5;
                t5 = t0 + t2;
                t4 -= t5;
                t5 = self.y() + self.z();
                let mut sum_x = rhs.y() + rhs.z();

                t5 *= sum_x;
                sum_x = t1 + t2;
                t5 -= sum_x;
                let mut sum_z = a * t4;
                sum_x = b3 * t2;

                sum_z += sum_x;
                sum_x = t1 - sum_z;
                sum_z += t1;
                let mut sum_y = sum_x * sum_z;
                t1 = t0 + t0;

                t1 += t0;
                t2 = a * t2;
                t4 *= b3;
                t1 += t2;
                t2 = t0 - t2;

                t2 *= a;
                t4 += t2;
                t0 = t1 * t4;
                sum_y += t0;
                t0 = t4 * t5;

                sum_x *= t3;
                sum_x -= t0;
                t0 = t1 * t3;
                sum_z *= t5;
                sum_z += t0;

                Point::<C>::new(sum_x, sum_y, sum_z)
            }

            pub fn double_mul(
                &self,
                this_scalar: &Scalar<C>,
                other_point: &Point<C>,
                other_scalar: &Scalar<C>,
            ) -> Point<C> {
                let mut q = Point::<C>::IDENTITY;
                let mut this_current = Point::<C>::IDENTITY;
                let mut other_current = Point::<C>::IDENTITY;
                let mut this_lookup = HashMap::with_capacity(16);
                let mut other_lookup = HashMap::with_capacity(16);
                for digit in &BASE_16_DIGITS {
                    this_lookup.insert(digit, this_current.clone());
                    other_lookup.insert(digit, other_current.clone());
                    this_current += self;
                    other_current += other_point;
                }

                let (this_string, other_string) =
                    this_scalar.pad_to_equal_len_strings(other_scalar);
                for (this_ch, other_ch) in this_string.chars().zip(other_string.chars()) {
                    q = q.double();
                    q = q.double();
                    q = q.double();
                    q = q.double();
                    // NOTE: both unwraps are fine because chars are definitely
                    // one of the keys in the respective maps
                    q += this_lookup.get(&this_ch).unwrap();
                    q += other_lookup.get(&other_ch).unwrap();
                }
                q
            }

            pub fn scalar_mul(&self, scalar: &Scalar<C>) -> Point<C> {
                let mut q = Point::<C>::IDENTITY;
                let mut current = Point::<C>::IDENTITY;
                let mut lookup = HashMap::with_capacity(16);
                for digit in &BASE_16_DIGITS {
                    lookup.insert(digit, current.clone());
                    current += self;
                }
                for ch in scalar.to_unpadded_string().chars() {
                    q = q.double();
                    q = q.double();
                    q = q.double();
                    q = q.double();
                    // NOTE: unwrap is fine because ch is definitely
                    // one of the keys in the map
                    q += lookup.get(&ch).unwrap()
                }
                q
            }
        }

        impl<C: Curve> fmt::Display for $this {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                writeln!(f, "x: {}", self.x())?;
                writeln!(f, "y: {}", self.y())?;
                writeln!(f, "z: {}", self.z())
            }
        }
    };
}

impl_point_arithmetic!(Point<C>);
impl_point_arithmetic!(AffinePoint<C>);
