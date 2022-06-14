use rand_core::OsRng;
use structopt::StructOpt;
use tom256::build_thread_pool;
use tom256::curve::{Secp256k1, Tom256k1};
use tom256::parse::*;
use tom256::pedersen::PedersenCycle;
use tom256::proofs::ZkAttestProof;

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Write};
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
    let thread_pool = build_thread_pool()?;

    // generate pedersen parameters
    let mut rng = OsRng;
    let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

    let msg_hash = "0x2c31a901b06d2727f458c7eb5c15eb7a794d69f841970f95c39ac092274c2a5a".to_string();
    let pubkey =
            "0x041296d6ed4e96bc378b8a460de783cdfbf58afbe04b355f1c225fb3e0b92cdc6e349d7005833c933898e2b88eae1cf40250c16352ace3915de65ec86f5bb9b349".to_string();
    let signature =
            "0xc945f22f92bc9afa7c8929637d3f8694b95a6ae9e276103b2061a0f88d61d8e92aaa9b9eec482d8befd1e1d2a9e2e219f21bd660278aefa9b0641184280cc2d91b".to_string();

    let proof_input = ProofInput {
        msg_hash,
        pubkey,
        signature,
        index: 7,
        guild_id: "almafa".to_string(),
    };

    let parsed_input: ParsedProofInput<Secp256k1> = proof_input.try_into()?;
    let parsed_ring = parse_ring(ring)?;

    let zkattest_proof = ZkAttestProof::<Secp256k1, Tom256k1>::construct(
        rng,
        pedersen,
        parsed_input,
        &parsed_ring,
        &thread_pool,
    )
    .await?;

    let mut file = File::create("proof.json")?;
    let proof = serde_json::to_string(&zkattest_proof)?;
    write!(file, "{}", proof).map_err(|e| e.to_string())?;
    println!("Proof generated successfully");
    Ok(())
}
