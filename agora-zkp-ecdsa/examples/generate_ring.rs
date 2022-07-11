use agora_zkp_ecdsa::arithmetic::{Point, Scalar};
use agora_zkp_ecdsa::curve::Secp256k1;
use rand_core::OsRng;
use structopt::StructOpt;

use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

#[derive(StructOpt)]
struct Opt {
    #[structopt(long, help = "number of desired pubkeys in the ring")]
    size: u64,
    #[structopt(long, help = "file where the ring is written")]
    ring: PathBuf,
}

fn get_random_pubkey(rng: &mut OsRng) -> String {
    let random_scalar = Scalar::<Secp256k1>::random(rng);
    let random_point = Point::<Secp256k1>::GENERATOR
        .scalar_mul(&random_scalar)
        .to_affine();
    let mut string = format!("04{}{}", random_point.x(), random_point.y());
    string.make_ascii_lowercase();
    string
}

fn main() -> Result<(), Box<dyn Error>> {
    let pubkey = "0454e32170dd5a0b7b641aa77daa1f3f31b8df17e51aaba6cfcb310848d26351180b6ac0399d21460443d10072700b64b454d70bfba5e93601536c740bbd099682".to_string();
    let index = 1;

    let opt = Opt::from_args();

    let mut rng = OsRng;

    let mut ring = vec![];
    while (ring.len() as u64) < opt.size {
        let curr_pubkey = get_random_pubkey(&mut rng);
        if curr_pubkey != pubkey {
            ring.push(curr_pubkey);
        }
    }

    ring[index] = pubkey;

    let ring_file = File::create(opt.ring)?;
    serde_json::to_writer(ring_file, &ring)?;
    Ok(())
}
