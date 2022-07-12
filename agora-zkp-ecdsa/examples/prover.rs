use agora_zkp_ecdsa::curve::{Secp256k1, Tom256k1};
use agora_zkp_ecdsa::parse::*;
use agora_zkp_ecdsa::pedersen::PedersenCycle;
use agora_zkp_ecdsa::proofs::ZkAttestProof;
use rand_core::OsRng;
use structopt::StructOpt;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

#[derive(StructOpt)]
struct Opt {
    #[structopt(long, help = "array of public keys as string")]
    ring: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    let ring_file = File::open(opt.ring)?;
    let ring_reader = BufReader::new(ring_file);
    let ring: Ring = serde_json::from_reader(ring_reader)?;

    // generate pedersen parameters
    let mut rng = OsRng;
    let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

    let msg_hash = "0x9788117298a1450f6002d25f0c21d83bc6001681a2e5e31c748c0f55504b11e9".to_string();
    let pubkey = "0454e32170dd5a0b7b641aa77daa1f3f31b8df17e51aaba6cfcb310848d26351180b6ac0399d21460443d10072700b64b454d70bfba5e93601536c740bbd099682".to_string();
    let signature = "0xd2943d5fa0ba2733bcbbd58853c6c1be65388d9198dcb5228e117f49409612a46394afb97a7610d16e7bea0062e71afc2a3039324c80df8ef38d3668164fad2c1c".to_string();

    let proof_input = ProofInput {
        msg_hash,
        pubkey,
        signature,
        index: 1,
        guild_id: "almafa".to_string(),
    };

    let parsed_input: ParsedProofInput<Secp256k1> = proof_input.try_into()?;
    let parsed_ring = parse_ring(ring)?;

    let zkattest_proof =
        ZkAttestProof::<Secp256k1, Tom256k1>::construct(rng, pedersen, parsed_input, &parsed_ring)
            .await?;

    let mut file = File::create("proof.json")?;
    borsh::BorshSerialize::serialize(&zkattest_proof, &mut file).unwrap();

    println!("Proof generated successfully");
    Ok(())
}
