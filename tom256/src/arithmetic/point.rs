use super::affine_point::AffinePoint;
use super::field::FieldElement;
use super::modular::Modular;
use crate::curve::Curve;

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Point<C: Curve> {
    x: FieldElement<C>,
    y: FieldElement<C>,
    z: FieldElement<C>,
}

impl<C: Curve + PartialEq> PartialEq for Point<C> {
    fn eq(&self, other: &Self) -> bool {
        let x0z1 = self.x * other.z;
        let x1z0 = other.x * self.z;
        let y0z1 = self.y * other.z;
        let y1z0 = other.y * self.z;

        x0z1 == x1z0 && y0z1 == y1z0
    }
}

impl<C: Curve> Point<C> {
    pub const GENERATOR: Self = Self {
        x: FieldElement(C::GENERATOR_X, PhantomData),
        y: FieldElement(C::GENERATOR_Y, PhantomData),
        z: FieldElement::ONE,
    };

    pub const IDENTITY: Point<C> = Point::<C> {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    pub fn new(x: FieldElement<C>, y: FieldElement<C>, z: FieldElement<C>) -> Self {
        Self { x, y, z }
    }

    pub fn into_affine(self) -> AffinePoint<C> {
        if self.is_identity() {
            AffinePoint::<C>::new_identity()
        } else {
            let z_inv = self.z.inverse();
            AffinePoint::<C>::new(self.x * z_inv, self.y * z_inv, FieldElement::<C>::ONE)
        }
    }

    pub fn to_affine(&self) -> AffinePoint<C> {
        if self.is_identity() {
            AffinePoint::<C>::new_identity()
        } else {
            let z_inv = self.z.inverse();
            AffinePoint::<C>::new(self.x * z_inv, self.y * z_inv, FieldElement::<C>::ONE)
        }
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
}

impl<C: Curve> std::ops::Add<AffinePoint<C>> for Point<C> {
    type Output = Self;
    fn add(self, rhs: AffinePoint<C>) -> Self {
        self.geometric_add(&rhs.into_point())
    }
}

impl<'a, 'b, C: Curve> std::ops::Add<&'b AffinePoint<C>> for &'a Point<C> {
    type Output = Point<C>;
    fn add(self, rhs: &'b AffinePoint<C>) -> Self::Output {
        self.geometric_add(&rhs.to_point())
    }
}

impl<'a, 'b, C: Curve> std::ops::Sub<&'b AffinePoint<C>> for &'a Point<C> {
    type Output = Point<C>;
    fn sub(self, rhs: &'b AffinePoint<C>) -> Self::Output {
        self + &(-rhs)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::{Secp256k1, Tom256k1};
    use crate::arithmetic::Scalar;

    use bigint::U256;
    
    type SecPoint = Point<Secp256k1>;
    type TomPoint = Point<Tom256k1>;

    type SecScalar = Scalar<Secp256k1>;
    type TomScalar = Scalar<Tom256k1>;

    #[test]
    fn on_curve_check() {
        assert!(SecPoint::GENERATOR.is_on_curve());
        assert!(TomPoint::GENERATOR.is_on_curve());
        assert!(SecPoint::GENERATOR.double().is_on_curve());
        assert!(TomPoint::GENERATOR.double().is_on_curve());
        let sec_scalar = SecScalar::new(U256::from_u32(123456));
        let sec_point = SecPoint::GENERATOR.scalar_mul(&sec_scalar);
        assert!(sec_point.is_on_curve());

        let tom_scalar = TomScalar::new(U256::from_u32(678910));
        let tom_point = TomPoint::GENERATOR.scalar_mul(&tom_scalar);
        assert!(tom_point.is_on_curve());

        let tom_on_sec = SecPoint {
            x: FieldElement::new(Tom256k1::GENERATOR_X),
            y: FieldElement::new(Tom256k1::GENERATOR_Y),
            z: FieldElement::ONE,
        };

        let sec_on_tom = TomPoint {
            x: FieldElement::new(Secp256k1::GENERATOR_X),
            y: FieldElement::new(Secp256k1::GENERATOR_Y),
            z: FieldElement::ONE,
        };
        assert!(!tom_on_sec.is_on_curve());
        assert!(!sec_on_tom.is_on_curve());
    }

    #[test]
    fn point_addition() {
        let g2 = SecPoint::GENERATOR.double();
        assert_eq!(
            g2.x().inner(),
            &U256::from_be_hex("f40af3b6c6fdf9aa5402b9fdc39ac4b67827eb373c92077452348e044f109fc8")
        );
        assert_eq!(
            g2.y().inner(),
            &U256::from_be_hex("56915849f52cc8f76f5fd7e4bf60db4a43bf633e1b1383f85fe89164bfadcbdb")
        );
        assert_eq!(
            g2.z().inner(),
            &U256::from_be_hex("f8783c53dfb2a307b568a6ad931fc97023dc71cdc3eac498b0c6ba5554759a29")
        );

        println!("{}", g2.to_affine());

        let random_double = SecPoint {
            x: FieldElement::new(U256::from_be_hex(
                "B8F0170E293FCC9291BEE2665E9CA9B25D3B11810ED68D9EA0CB440D7064E4DA",
            )),
            y: FieldElement::new(U256::from_be_hex(
                "0691AA44502212591132AA6F27582B78F9976998DE355C4EE5960DB05AC0A2A3",
            )),
            z: FieldElement::ONE,
        }
        .double()
        .into_affine();
        assert!(random_double.is_on_curve());
        assert_eq!(
            random_double.x().inner(),
            &U256::from_be_hex("d99bdf80fe99540ed7c33669cc43ac72fa2fa2c14b731ae6758c1c17eaf7b26e")
        );
        assert_eq!(
            random_double.y().inner(),
            &U256::from_be_hex("cac2c38a379655150567315c7cf7f596585b577b28e03108b0d2df2b9c83af52")
        );
        assert_eq!(random_double.z().inner(), &U256::ONE);

        let four = SecScalar::new(U256::from_u8(4));
        let g4 = SecPoint::GENERATOR.scalar_mul(&four);
        assert_eq!(g2.double(), g4);
        assert_eq!(&g2 + &g2, g4);
    }

    #[test]
    fn scalar_multiplication() {
        let d = TomScalar::new(U256::from_be_hex(
            "c51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd",
        ));
        let e = TomScalar::new(U256::from_be_hex(
            "d37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7",
        ));
        let f = TomScalar::new(U256::from_be_hex(
            "B8F0170E293FCC9291BEE2665E9CA9B25D3B11810ED68D9EA0CB440D7064E4DA",
        ));

        let t = TomPoint::GENERATOR.scalar_mul(&d).into_affine();
        assert!(t.is_on_curve());
        assert_eq!(
            t.x().inner(),
            &U256::from_be_hex("3758fd961003dc291e21523313f0b4329d732b84e52f0159b2d6627bca8d2db2")
        );
        assert_eq!(
            t.y().inner(),
            &U256::from_be_hex("0c21e4f939a5d91c1473416bb936e61bd688dd91db2778f832a54cdacc207deb")
        );

        let r = TomPoint::GENERATOR
            .double_mul(&e, &t.to_point(), &f)
            .into_affine();
        assert!(r.is_on_curve());
        assert_eq!(
            r.x().inner(),
            &U256::from_be_hex("8fdb6195754109cc23c635f41f799fd6e1f6078eb94fe0d9cde1eb80d36e5e31")
        );
        assert_eq!(
            r.y().inner(),
            &U256::from_be_hex("fddd45b8f6f633074edddcf1394a1c9498e6f7b5847b744adf01833f38553c01")
        );

        let mut g12 = TomPoint::IDENTITY;
        for _ in 0..12 {
            g12 = g12 + TomPoint::GENERATOR;
        }

        assert_eq!(
            TomPoint::GENERATOR.scalar_mul(&TomScalar::new(U256::from_u32(12))),
            g12
        );

        let scalars = &[
            (
                TomScalar::new(U256::from_u8(3)),
                TomScalar::new(U256::from_u8(12)),
            ),
            (
                TomScalar::new(U256::from_u8(36)),
                TomScalar::new(U256::from_u8(220)),
            ),
            (
                TomScalar::new(U256::from_u8(189)),
                TomScalar::new(U256::from_u8(89)),
            ),
            (
                TomScalar::new(U256::from_u8(92)),
                TomScalar::new(U256::from_u8(105)),
            ),
        ];

        let h_gen = TomPoint::GENERATOR.scalar_mul(&TomScalar::new(U256::from_u8(250)));

        for (a, b) in scalars {
            let dbl_mul = h_gen.double_mul(a, &TomPoint::GENERATOR, b);
            let dbl_mul_rev = TomPoint::GENERATOR.double_mul(b, &h_gen, a);
            let expected = &h_gen * *a + &TomPoint::GENERATOR * *b;
            assert_eq!(dbl_mul, expected);
            assert_eq!(dbl_mul_rev, expected);
        }
    }
}
