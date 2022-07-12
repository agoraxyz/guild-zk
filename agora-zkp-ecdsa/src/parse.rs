use crate::arithmetic::{AffinePoint, FieldElement, Modular, Scalar};
use crate::curve::Curve;
use crate::U256;

use serde::{Deserialize, Serialize};

pub type Ring = Vec<String>;
pub type ParsedRing<C> = Vec<Scalar<C>>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofInput {
    pub msg_hash: String,
    pub pubkey: String,
    pub signature: String,
    pub index: usize,
    pub guild_id: String,
}

pub struct ParsedProofInput<C: Curve> {
    pub msg_hash: Scalar<C>,
    pub pubkey: AffinePoint<C>,
    pub signature: Signature<C>,
    pub index: usize,
    pub guild_id: String,
}

impl<C: Curve> TryFrom<ProofInput> for ParsedProofInput<C> {
    type Error = String;
    fn try_from(rhs: ProofInput) -> Result<Self, Self::Error> {
        let hash = rhs.msg_hash.trim_start_matches("0x");
        if hash.len() != 64 {
            return Err("invalid hash length".to_string());
        }
        Ok(Self {
            msg_hash: Scalar::new(U256::from_be_hex(hash)),
            pubkey: parse_pubkey(&rhs.pubkey)?,
            signature: parse_signature(&rhs.signature)?,
            index: rhs.index,
            guild_id: rhs.guild_id,
        })
    }
}

pub struct Signature<C> {
    pub r: Scalar<C>,
    pub s: Scalar<C>,
}

enum Parse {
    Pubkey,
    Signature,
}

pub fn parse_ring<C: Curve>(ring: Ring) -> Result<ParsedRing<C>, String> {
    let mut parsed = ParsedRing::with_capacity(ring.len());
    for pk in ring.iter() {
        parsed.push(extract_x_coordinate(pk)?);
    }
    Ok(parsed)
}

fn extract_x_coordinate<C: Curve>(pubkey: &str) -> Result<Scalar<C>, String> {
    let stripped = pubkey.trim_start_matches("0x").trim_start_matches("04");
    // NOTE this check avoids explicit panics by `from_be_hex`
    if stripped.len() > 128 {
        return Err("invalid pubkey".to_string());
    }
    Ok(Scalar::new(U256::from_be_hex(&stripped[..64])))
}

fn parse_pubkey<C: Curve>(pubkey: &str) -> Result<AffinePoint<C>, String> {
    let (x, y) = parse_str(pubkey, Parse::Pubkey)?;
    Ok(AffinePoint::new(
        FieldElement::<C>::new(x),
        FieldElement::<C>::new(y),
    ))
}

fn parse_signature<C: Curve>(signature: &str) -> Result<Signature<C>, String> {
    let (r, s) = parse_str(signature, Parse::Signature)?;
    Ok(Signature {
        r: Scalar::new(r),
        s: Scalar::new(s),
    })
}

fn parse_str(slice: &str, into: Parse) -> Result<(U256, U256), String> {
    let trimmed = slice.trim_start_matches("0x");
    if trimmed.len() != 130 {
        return Err("invalid bytes".to_string());
    }
    match into {
        Parse::Pubkey => {
            // NOTE pubkeys always start with 0x04
            let x = U256::from_be_hex(&trimmed[2..66]);
            let y = U256::from_be_hex(&trimmed[66..]);
            Ok((x, y))
        }
        Parse::Signature => {
            let r = U256::from_be_hex(&trimmed[0..64]);
            let s = U256::from_be_hex(&trimmed[64..128]);
            // NOTE last 2 bytes represent the recovery `v` parameter
            Ok((r, s))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arithmetic::Modular;
    use crate::curve::{Secp256k1, Tom256k1};
    use crate::U256;

    #[test]
    fn pubkey_extraction() {
        let pubkey = "0x0408c6cd9400645819c8c556a6e83e0a7728f070a813bb9d24d5c24290e21fc5e438396f9333264d3e7c1d3e6ee1bc572b2f00b98db7065e9bf278f2b8dbe02718";
        let x_coord = extract_x_coordinate::<Tom256k1>(pubkey).unwrap();

        assert_eq!(
            x_coord,
            Scalar::<Tom256k1>::new(U256::from_be_hex(
                "08c6cd9400645819c8c556a6e83e0a7728f070a813bb9d24d5c24290e21fc5e4"
            ))
        );
    }

    #[test]
    fn parse_helpers() {
        let signature = "0x45c4039b611c0cc207ff7fb7a6899ea0431aac2cf37515d74a71f2df00e2c3e0096fad5e7eda762898fffd4644f8a7a406bf6bde868814ea03058c882fcd23311c";

        let sig = parse_signature(signature).unwrap();
        assert_eq!(
            sig.r,
            Scalar::<Secp256k1>::new(U256::from_be_hex(
                "45c4039b611c0cc207ff7fb7a6899ea0431aac2cf37515d74a71f2df00e2c3e0"
            ))
        );
        assert_eq!(
            sig.s,
            Scalar::<Secp256k1>::new(U256::from_be_hex(
                "096fad5e7eda762898fffd4644f8a7a406bf6bde868814ea03058c882fcd2331"
            ))
        );

        let pubkey = "0x0408c6cd9400645819c8c556a6e83e0a7728f070a813bb9d24d5c24290e21fc5e438396f9333264d3e7c1d3e6ee1bc572b2f00b98db7065e9bf278f2b8dbe02718";

        let pubkey_point = parse_pubkey(pubkey).unwrap();
        assert_eq!(
            pubkey_point.x(),
            &FieldElement::<Secp256k1>::new(U256::from_be_hex(
                "08c6cd9400645819c8c556a6e83e0a7728f070a813bb9d24d5c24290e21fc5e4"
            ))
        );
        assert_eq!(
            pubkey_point.y(),
            &FieldElement::<Secp256k1>::new(U256::from_be_hex(
                "38396f9333264d3e7c1d3e6ee1bc572b2f00b98db7065e9bf278f2b8dbe02718"
            ))
        );

        assert_eq!(pubkey_point.z(), &FieldElement::ONE);
    }

    #[test]
    fn parse() {
        let input = ProofInput {
            msg_hash: "0x1ab4850e7f0a85a521e87b274e3130efdb45f6a47e74e6dcebf5591c6bc8f16e".to_string(),
            signature:"0x45c4039b611c0cc207ff7fb7a6899ea0431aac2cf37515d74a71f2df00e2c3e0096fad5e7eda762898fffd4644f8a7a406bf6bde868814ea03058c882fcd23311c".to_string(),
            pubkey:"0x0408c6cd9400645819c8c556a6e83e0a7728f070a813bb9d24d5c24290e21fc5e438396f9333264d3e7c1d3e6ee1bc572b2f00b98db7065e9bf278f2b8dbe02718".to_string(),
            index: 1,
            guild_id: "Our-guild#2314".to_string(),
        };
        let ring = vec![
            "0x1679349AeA848f928cE886fbAE10a85660CBFecE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            "0x0679349AeA848f928cE886fbAE10a85660CBFecD0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            "0x7679349AeA848f928cE886fbAE10a85660CBFecF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ];

        let parsed_input: ParsedProofInput<Secp256k1> = input.try_into().unwrap();
        let parsed_ring: ParsedRing<Tom256k1> = parse_ring(ring).unwrap();

        assert_eq!(
            parsed_input.msg_hash,
            Scalar::new(U256::from_be_hex(
                "1ab4850e7f0a85a521e87b274e3130efdb45f6a47e74e6dcebf5591c6bc8f16e"
            ))
        );
        assert_eq!(parsed_input.guild_id, "Our-guild#2314");
        assert_eq!(
            parsed_ring[0],
            Scalar::new(U256::from_be_hex(
                "1679349AeA848f928cE886fbAE10a85660CBFecE000000000000000000000000"
            ))
        );
        assert_eq!(
            parsed_ring[1],
            Scalar::new(U256::from_be_hex(
                "0679349AeA848f928cE886fbAE10a85660CBFecD000000000000000000000000"
            ))
        );
        assert_eq!(
            parsed_ring[2],
            Scalar::new(U256::from_be_hex(
                "7679349AeA848f928cE886fbAE10a85660CBFecF000000000000000000000000"
            ))
        );
    }
}
