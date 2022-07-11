use super::{AffinePoint, Point, Scalar};
use crate::curve::Curve;

use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::collections::binary_heap::BinaryHeap;
use std::fmt;

use crate::rng::CryptoCoreRng;

#[derive(Debug, Clone)]
pub struct Pair<C: Curve> {
    scalar: Scalar<C>,
    point: Point<C>,
}

#[derive(Debug, Clone)]
pub struct Known<C: Curve> {
    point: Point<C>,
    index: usize,
}

#[derive(Debug, Clone)]
pub struct MultiMult<C: Curve> {
    pairs: Vec<Pair<C>>,
    known: Vec<Known<C>>,
}

impl<C: Curve> Default for MultiMult<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve> MultiMult<C> {
    pub fn new() -> Self {
        Self {
            pairs: vec![],
            known: vec![],
        }
    }

    pub fn add_known(&mut self, pt: Point<C>) {
        if !self.known.iter().any(|known| known.point == pt) {
            self.pairs.push(Pair {
                point: pt.clone(),
                scalar: Scalar::ZERO,
            });
            self.known.push(Known {
                point: pt,
                index: self.pairs.len() - 1,
            });
        }
    }

    pub fn insert(&mut self, point: Point<C>, scalar: Scalar<C>) {
        if let Some(element) = self.known.iter().find(|known| known.point == point) {
            self.pairs[element.index].scalar += scalar;
        } else {
            self.pairs.push(Pair::<C> { point, scalar });
        }
    }

    // TODO remove this if not needed
    /*
    pub fn insert_pair(&mut self, pair: Pair<C>) {
        self.pairs.push(pair);
    }
    */

    pub fn evaluate(self) -> Point<C> {
        if self.pairs.is_empty() {
            return Point::<C>::IDENTITY;
        }
        if self.pairs.len() == 1 {
            return self.pairs[0].point.scalar_mul(&self.pairs[0].scalar);
        }

        let mut pairs_heap = heapify_vec(self.pairs);
        loop {
            // unwrap is fine here because peeking and pre-loop checks guarantee len is at least 1
            let a = pairs_heap.pop().unwrap();

            let c: Pair<C>;
            // If b_option is None -> the heap only has one element
            if let Some(mut b) = pairs_heap.peek_mut() {
                if b.scalar == Scalar::<C>::ZERO {
                    return a.point.scalar_mul(&a.scalar);
                }

                c = Pair {
                    point: a.point.clone(),
                    scalar: a.scalar - b.scalar,
                };
                let d = Pair {
                    point: &a.point + &b.point,
                    scalar: b.scalar,
                };

                *b = d;
            } else {
                return a.point.scalar_mul(&a.scalar);
            }

            if c.scalar != Scalar::<C>::ZERO {
                pairs_heap.push(c);
            }
        }
    }
}

pub fn heapify_vec<T: Ord>(vec: Vec<T>) -> BinaryHeap<T> {
    vec.into_iter().collect()
}

pub struct Relation<C: Curve> {
    pairs: Vec<Pair<C>>,
}

impl<C: Curve> Default for Relation<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve> Relation<C> {
    pub fn new() -> Self {
        Self { pairs: vec![] }
    }

    pub fn insert(&mut self, point: Point<C>, scalar: Scalar<C>) {
        self.pairs.push(Pair { point, scalar })
    }

    pub fn drain<R: CryptoCoreRng>(self, rng: &mut R, multimult: &mut MultiMult<C>) {
        let randomizer = Scalar::<C>::random(rng);
        for pair in self.pairs {
            multimult.insert(pair.point, pair.scalar * randomizer);
        }
    }
}

// *************************************** TRAITS ***************************************** //
impl<C: Curve> fmt::Display for MultiMult<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for pair in &self.pairs {
            writeln!(f, "scalar: {}", pair.scalar)?;
            let pt_aff: AffinePoint<C> = pair.point.clone().into();
            writeln!(f, "point: {}", pt_aff)?;
        }
        fmt::Result::Ok(())
    }
}

impl<C: Curve> fmt::Display for Relation<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for pair in &self.pairs {
            writeln!(f, "scalar: {}", pair.scalar)?;
            let pt_aff: AffinePoint<C> = pair.point.clone().into();
            writeln!(f, "point: {}", pt_aff)?;
        }
        fmt::Result::Ok(())
    }
}

impl<C: Curve> PartialEq for Pair<C> {
    fn eq(&self, other: &Self) -> bool {
        self.scalar.eq(&other.scalar)
    }
}

impl<C: Curve> Eq for Pair<C> {}

impl<C: Curve> PartialOrd for Pair<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.scalar.partial_cmp(&other.scalar)
    }
}

impl<C: Curve> Ord for Pair<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.scalar.cmp(&other.scalar)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arithmetic::{FieldElement, Modular};
    use crate::curve::{Secp256k1, Tom256k1};

    use bigint::U256;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    use std::time::{Duration, Instant};

    type SecAffine = AffinePoint<Secp256k1>;
    type SecPoint = Point<Secp256k1>;
    type SecScalar = Scalar<Secp256k1>;

    type TomAffine = AffinePoint<Tom256k1>;
    type TomPoint = Point<Tom256k1>;
    type TomScalar = Scalar<Tom256k1>;

    fn get_test_rng() -> StdRng {
        StdRng::from_seed([
            54, 1, 63, 153, 89, 49, 228, 122, 166, 230, 220, 138, 243, 90, 252, 212, 162, 48, 105,
            3, 140, 12, 169, 247, 176, 212, 208, 179, 38, 62, 94, 172,
        ])
    }

    #[test]
    fn multimult_empty() {
        let multimult = MultiMult::<Secp256k1>::new();
        assert_eq!(multimult.evaluate(), SecPoint::IDENTITY);
    }

    #[test]
    fn multimult_single() {
        let pt = SecPoint::GENERATOR;
        let scalar = SecScalar::ONE;

        let expected = pt.scalar_mul(&scalar);

        let mut multimult = MultiMult::<Secp256k1>::new();
        multimult.insert(pt, scalar);

        assert_eq!(multimult.evaluate(), expected);
    }

    #[test]
    fn multimult_multiple() {
        let mut rng = get_test_rng();

        let mut mm_time = Duration::new(0, 0);
        let mut normal_time = Duration::new(0, 0);

        let mut multimult = MultiMult::<Secp256k1>::new();
        let mut expected = SecPoint::IDENTITY;

        let summa_len = 10;
        let mut scalars = Vec::with_capacity(summa_len);
        for _ in 0..summa_len {
            scalars.push(SecScalar::random(&mut rng));
        }

        for (i, scalar) in scalars.iter().enumerate() {
            let mut pt = SecPoint::GENERATOR;
            for _ in 0..i {
                pt = pt.double();
            }

            let now = Instant::now();
            let new_term = pt.scalar_mul(scalar);
            expected = expected + new_term;
            normal_time += now.elapsed();

            multimult.insert(pt, *scalar);
        }

        let now = Instant::now();
        let actual = multimult.evaluate();
        mm_time += now.elapsed();

        println!("Normal time: {:?}", normal_time);
        println!("Multimult time: {:?}", mm_time);

        assert_eq!(actual, expected);
    }

    #[test]
    fn secp_relations() {
        let mut rng = get_test_rng();
        let mut rel = Relation::<Secp256k1>::new();

        let summa_len = 3;
        let mut scalars = Vec::with_capacity(summa_len);
        for _ in 0..summa_len {
            let scalar = SecScalar::random(&mut rng);
            scalars.push(scalar);
        }

        let mut pt: SecAffine = SecPoint::GENERATOR.into();
        for scalar in scalars.iter() {
            pt = pt.double().into();
            rel.insert(pt.clone().into(), *scalar);
        }

        let mut multimult = MultiMult::new();
        rel.drain(&mut rng, &mut multimult);
        let sum = multimult.evaluate();
        let expected = SecPoint::new(
            FieldElement::new(U256::from_be_hex(
                "cf2de7b2e687085c14a39bb01457edfcac2cbadf67906de73d3251c6569d3089",
            )),
            FieldElement::new(U256::from_be_hex(
                "3fb1eb3907871809c1c46ba8d20b01798384cb6f9926d386c0456b7b01e4cbd5",
            )),
            FieldElement::ONE,
        );

        assert_eq!(sum, expected);
    }

    #[test]
    fn tom_relations() {
        let mut rng = get_test_rng();
        let mut rel = Relation::<Tom256k1>::new();

        let summa_len = 3;
        let mut scalars = Vec::with_capacity(summa_len);
        for _ in 0..summa_len {
            let scalar = TomScalar::random(&mut rng);
            scalars.push(scalar);
        }

        let mut pt: TomAffine = TomPoint::GENERATOR.into();
        for scalar in scalars.iter() {
            pt = pt.double().into();
            rel.insert(pt.clone().into(), *scalar);
        }

        let mut multimult = MultiMult::new();
        rel.drain(&mut rng, &mut multimult);
        let sum = multimult.evaluate();
        let expected = TomPoint::new(
            FieldElement::new(U256::from_be_hex(
                "cccb91596829355ee5ab3682180025da88f0f93384149db1a2dca1c8c1011127",
            )),
            FieldElement::new(U256::from_be_hex(
                "f7b4bc3b8ccc4296ac43ce053b9fc375d889dae6b15511253a2431def4edb6d1",
            )),
            FieldElement::ONE,
        );

        assert_eq!(sum, expected);
    }
}
