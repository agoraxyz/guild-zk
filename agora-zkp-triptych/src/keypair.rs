use k256::elliptic_curve::Field;
use k256::{AffinePoint, Scalar};
use rand_core::OsRng;

pub struct Keypair {
    pub public: AffinePoint,
    pub private: Scalar,
}

impl Keypair {
    pub fn random() -> Self {
        let private = Scalar::random(OsRng);
        Self {
            public: (AffinePoint::GENERATOR * private).to_affine(),
            private,
        }
    }
}

/*
#[test]
fn test_keypairs() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    for i in 0..10 {
        let keypair = Keypair::random();
        let encoded = keypair.public.to_encoded_point(false);
        let mut encoded_string = String::new();
        encoded_string.push_str(&hex::encode(encoded.x().unwrap()));
        encoded_string.push_str(&hex::encode(encoded.y().unwrap()));
        if i == 4 {
            println!("{}", hex::encode(keypair.private.to_bytes()));
        }
        println!("i = {}: {}", i, encoded_string);
    }
    assert!(false);
}
*/
