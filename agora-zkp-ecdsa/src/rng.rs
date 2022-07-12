use rand_core::{CryptoRng, OsRng, RngCore};

pub trait RngDefault {
    fn default() -> Self;
}

pub trait CryptoCoreRng: RngCore + CryptoRng + RngDefault {}

impl RngDefault for OsRng {
    fn default() -> Self {
        OsRng
    }
}

impl CryptoCoreRng for OsRng {}

#[cfg(test)]
use rand::rngs::StdRng;
#[cfg(test)]
use rand_core::SeedableRng;

#[cfg(test)]
impl RngDefault for StdRng {
    fn default() -> Self {
        StdRng::from_entropy()
    }
}
#[cfg(test)]
impl CryptoCoreRng for StdRng {}
