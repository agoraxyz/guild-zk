use structopt::StructOpt;
use tom256::build_thread_pool;
use tom256::curve::{Secp256k1, Tom256k1};
use tom256::parse::*;
use tom256::proofs::ZkAttestProof;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

#[derive(StructOpt)]
struct Opt {
    #[structopt(long, help = "zk ecdsa and membership proof")]
    proof: PathBuf,
    #[structopt(long, help = "array of public keys as string")]
    ring: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    let thread_pool = build_thread_pool()?;

    let ring_file = File::open(opt.ring)?;
    let ring_reader = BufReader::new(ring_file);

    let proof_file = File::open(opt.proof)?;
    let proof_reader = BufReader::new(proof_file);

    let ring: Ring = serde_json::from_reader(ring_reader)?;
    let parsed_ring = parse_ring(ring)?;

    let proof: ZkAttestProof<Secp256k1, Tom256k1> = serde_json::from_reader(proof_reader)?;

    proof.verify(rand_core::OsRng, &parsed_ring, &thread_pool)?;
    println!("Proof OK");
    Ok(())
}
