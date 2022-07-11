use crate::arithmetic::{Modular, Point};
use crate::curve::Curve;
use crate::U256;

use bigint::Encoding;
use sha3::{Digest, Keccak256};

pub struct PointHasher {
    hasher: Keccak256,
}

impl PointHasher {
    pub fn new(hash_id: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(hash_id);

        Self { hasher }
    }

    pub fn insert_point<C: Curve>(&mut self, pt: &Point<C>) {
        self.hasher.update(pt.x().inner().to_be_bytes());
        self.hasher.update(pt.y().inner().to_be_bytes());
        self.hasher.update(pt.z().inner().to_be_bytes());
    }

    pub fn insert_points<C: Curve>(&mut self, points: &[&Point<C>]) {
        for p in points {
            // write input message
            self.hasher.update(p.x().inner().to_be_bytes());
            self.hasher.update(p.y().inner().to_be_bytes());
            self.hasher.update(p.z().inner().to_be_bytes());
        }
    }

    pub fn finalize(self) -> U256 {
        let finalized = self.hasher.finalize();
        U256::from_be_bytes(finalized[0..32].try_into().unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arithmetic::FieldElement;
    use crate::curve::Tom256k1;

    impl PointHasher {
        pub fn new_empty() -> Self {
            let hasher = Keccak256::new();
            Self { hasher }
        }
    }

    #[test]
    fn keccak_test() {
        let test_point = Point::<Tom256k1>::new(
            FieldElement::new(U256::from_be_hex(
                "7849ef496dac1bedd153886aee3eaa4ff31a3966b0f1b48268c0ec47386ff895",
            )),
            FieldElement::new(U256::from_be_hex(
                "c84bf6c971421a75b055899760b864e9e1b1d0213bb905f8ccc2bc1c5a41e6b4",
            )),
            FieldElement::new(U256::from_be_hex(
                "f57a7930cff4c9d8636802e0a2aa2804067c58182dedfb20541a0bfe50752ab4",
            )),
        );
        let expected =
            U256::from_be_hex("a446b4fe7f655042c87c4a669d57dc85abdae2d969c40c0ca497ea709faa1bc0");

        let mut hasher = PointHasher::new_empty();
        hasher.insert_point(&test_point);
        assert_eq!(hasher.finalize(), expected);
    }
}
