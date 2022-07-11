use generic_array::GenericArray;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint};

pub type FrontendRing = Vec<String>;
pub type Ring = Vec<AffinePoint>;

pub fn parse_ring(frontend_ring: FrontendRing) -> Result<Ring, String> {
    if frontend_ring.len() >= 2usize.pow(crate::MAX_2_EXPONENT as u32) {
        return Err("ring too long".to_string());
    }
    let mut ring = Ring::with_capacity(frontend_ring.len());
    for pk in frontend_ring.iter() {
        ring.push(parse_pubkey(pk)?)
    }
    Ok(ring)
}

fn parse_pubkey(pk_string: &str) -> Result<AffinePoint, String> {
    let mut bytes = [0u8; 64];
    hex::decode_to_slice(
        &pk_string.trim_start_matches("0x").trim_start_matches("04"),
        &mut bytes,
    )
    .map_err(|e| e.to_string())?;
    let encoded = EncodedPoint::from_affine_coordinates(
        GenericArray::from_slice(&bytes[0..32]),
        GenericArray::from_slice(&bytes[32..64]),
        false,
    );
    let point = AffinePoint::from_encoded_point(&encoded);
    if point.is_some().unwrap_u8() == 0 {
        Err("failed to parse pubkey".to_owned())
    } else {
        Ok(point.unwrap())
    }
}

pub fn pad_ring_to_2n(ring: &mut Ring) -> Result<usize, String> {
    if ring.is_empty() {
        Err("empty ring".to_string())
    } else {
        let log_2_ring_len = ring.len().log2();
        let pow_2_ring_len = 2usize.pow(log_2_ring_len);
        // pow_2_ring_len is always less than or equal to keys.len()
        // because log2 always rounds down
        if ring.len() != pow_2_ring_len {
            for _ in 0..pow_2_ring_len * 2 - ring.len() {
                ring.push(ring[0])
            }
            Ok((log_2_ring_len + 1) as usize)
        } else {
            Ok(log_2_ring_len as usize)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keypair::Keypair;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn pad_ring() {
        let mut ring = Vec::<AffinePoint>::new();
        assert!(pad_ring_to_2n(&mut ring).is_err());
        ring.push(AffinePoint::GENERATOR);
        assert_eq!(pad_ring_to_2n(&mut ring), Ok(0));
        assert_eq!(ring.len(), 1);
        ring.push(AffinePoint::GENERATOR);
        assert_eq!(pad_ring_to_2n(&mut ring), Ok(1));
        assert_eq!(ring.len(), 2);
        ring.push(AffinePoint::GENERATOR);
        assert_eq!(pad_ring_to_2n(&mut ring), Ok(2));
        assert_eq!(ring.len(), 4);
        assert_eq!(ring[3], AffinePoint::GENERATOR);
        for _ in 0..5 {
            ring.push(AffinePoint::GENERATOR);
        }
        assert_eq!(ring.len(), 9);
        assert_eq!(pad_ring_to_2n(&mut ring), Ok(4));
        assert_eq!(ring.len(), 16);
        assert_eq!(ring[15], AffinePoint::GENERATOR);
    }

    #[test]
    fn test_parse_pubkey() {
        let pubkey_str = "0x0454e32170dd5a0b7b641aa77daa1f3f31b8df17e51aaba6cfcb310848d26351180b6ac0399d21460443d10072700b64b454d70bfba5e93601536c740bbd099682";
        let pubkey = parse_pubkey(pubkey_str).unwrap();
        let x_coordinate = &pubkey.to_bytes()[1..33];
        assert_eq!(
            hex::encode(x_coordinate),
            pubkey_str.trim_start_matches("0x04")[0..64]
        );

        for _ in 0..10 {
            let keypair = Keypair::random();
            let encoded = keypair.public.to_encoded_point(false);
            let x_coordinate = hex::encode(encoded.x().unwrap());
            let y_coordinate = hex::encode(encoded.y().unwrap());

            let mut pubkey_string = String::from("04");
            pubkey_string.push_str(&x_coordinate);
            pubkey_string.push_str(&y_coordinate);

            let parsed = parse_pubkey(&pubkey_string).unwrap();
            assert_eq!(parsed, keypair.public);
        }
    }
}
