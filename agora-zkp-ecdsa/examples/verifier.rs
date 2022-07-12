use agora_zkp_ecdsa::curve::{Secp256k1, Tom256k1};
use agora_zkp_ecdsa::parse::*;
use agora_zkp_ecdsa::proofs::ZkAttestProof;
use structopt::StructOpt;

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

    let ring_file = File::open(opt.ring)?;
    let ring_reader = BufReader::new(ring_file);

    let ring: Ring = serde_json::from_reader(ring_reader)?;
    let parsed_ring = parse_ring(ring)?;

    let proof_binary = std::fs::read(opt.proof).unwrap();
    let proof: ZkAttestProof<Secp256k1, Tom256k1> =
        borsh::BorshDeserialize::try_from_slice(proof_binary.as_slice()).unwrap();

    proof.verify(rand_core::OsRng, &parsed_ring)?;
    println!("Proof OK");
    Ok(())
}
