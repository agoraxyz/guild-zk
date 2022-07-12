use crate::ring::*;
use crate::utils::interpolate;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::{Field, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

// NOTE this is a public "private key" that determines the U point which is used
// for tag generation
const U_SCALAR_U256: U256 =
    U256::from_le_hex("7c81a9587b8da43a9519bd50d96191fd8f2c4f66b8f1550e366e3c7f9ed18897");

#[derive(Clone, Serialize, Deserialize)]
pub struct Parameters {
    generators: Vec<VecElem<AffinePoint>>,
    h_point: AffinePoint,
}

impl Parameters {
    pub fn new(n_generators: usize) -> Self {
        let mut generators = Vec::<VecElem<AffinePoint>>::with_capacity(n_generators);
        for _ in 0..n_generators {
            let pt_0 = AffinePoint::GENERATOR * Scalar::random(OsRng);
            let pt_1 = AffinePoint::GENERATOR * Scalar::random(OsRng);
            generators.push(VecElem {
                i_0: pt_0.to_affine(),
                i_1: pt_1.to_affine(),
            });
        }

        Self {
            generators,
            h_point: (AffinePoint::GENERATOR * Scalar::random(OsRng)).to_affine(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct VecElem<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq> {
    i_0: T,
    i_1: T,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    a_commitment: AffinePoint,
    b_commitment: AffinePoint,
    c_commitment: AffinePoint,
    d_commitment: AffinePoint,
    x_points: Vec<AffinePoint>,
    y_points: Vec<AffinePoint>,
    f_scalars: Vec<Scalar>,
    z_a_scalar: Scalar,
    z_c_scalar: Scalar,
    z_scalar: Scalar,
    tag: AffinePoint,
}

// NOTE n = 2, i.e. N = 2^m
// N - number of elements in the ring (should be padded to 2^m)
impl Signature {
    pub fn new(
        index: usize,
        ring: &Ring,
        message_hash: &[u8],
        mut privkey: Scalar, // mutable for zeroize at the end
        parameters: &Parameters,
    ) -> Result<Self, String> {
        // include the msg hash in the challenge
        let mut hasher = Keccak256::new();
        hasher.update(message_hash);
        // pad ring and hash pubkeys
        let mut ring = ring.to_owned();
        let m = pad_ring_to_2n(&mut ring)?;
        for pk in ring.iter() {
            hasher.update(pk.to_bytes());
        }

        // generate signature tag
        let u_point = AffinePoint::GENERATOR * Scalar::from_uint_reduced(U_SCALAR_U256);
        if privkey == Scalar::ZERO {
            return Err("invalid private key".to_owned());
        }
        // NOTE privkey is always invertible due to the above check
        let j_point = u_point * privkey.invert().unwrap();

        let a_vec = (0..m)
            .map(|_| {
                let i_1 = Scalar::random(OsRng);
                VecElem { i_0: -i_1, i_1 }
            })
            .collect::<Vec<VecElem<Scalar>>>();
        let b_vec = deltas(index, m); // sigma vec
        let c_vec = a_vec
            .iter()
            .zip(b_vec.iter())
            .map(|(a, b)| {
                let i_0 = a.i_0 * (Scalar::ONE - (b.i_0 + b.i_0));
                let i_1 = a.i_1 * (Scalar::ONE - (b.i_1 + b.i_1));
                VecElem { i_0, i_1 }
            })
            .collect::<Vec<VecElem<Scalar>>>();
        let d_vec = a_vec
            .iter()
            .map(|a| {
                let i_0 = -(a.i_0 * a.i_0);
                let i_1 = -(a.i_1 * a.i_1);
                VecElem { i_0, i_1 }
            })
            .collect::<Vec<VecElem<Scalar>>>();

        let mut omegas = Vec::<Scalar>::with_capacity(m);
        let mut rho_vec = Vec::<Scalar>::with_capacity(m);
        let mut a_com_gen = ProjectivePoint::IDENTITY;
        let mut b_com_gen = ProjectivePoint::IDENTITY;
        let mut c_com_gen = ProjectivePoint::IDENTITY;
        let mut d_com_gen = ProjectivePoint::IDENTITY;
        for (i, gen) in parameters.generators.iter().take(m).enumerate() {
            a_com_gen += gen.i_0 * a_vec[i].i_0;
            a_com_gen += gen.i_1 * a_vec[i].i_1;
            b_com_gen += gen.i_0 * b_vec[i].i_0;
            b_com_gen += gen.i_1 * b_vec[i].i_1;
            c_com_gen += gen.i_0 * c_vec[i].i_0;
            c_com_gen += gen.i_1 * c_vec[i].i_1;
            d_com_gen += gen.i_0 * d_vec[i].i_0;
            d_com_gen += gen.i_1 * d_vec[i].i_1;
            omegas.push(Scalar::from((i + 2) as u32)); // x points for polynomial interpolation
            rho_vec.push(Scalar::random(OsRng));
        }

        let r_a = Scalar::random(OsRng);
        let r_b = Scalar::random(OsRng);
        let r_c = Scalar::random(OsRng);
        let r_d = Scalar::random(OsRng);

        let a_com = (parameters.h_point * r_a + a_com_gen).to_affine();
        let b_com = (parameters.h_point * r_b + b_com_gen).to_affine();
        let c_com = (parameters.h_point * r_c + c_com_gen).to_affine();
        let d_com = (parameters.h_point * r_d + d_com_gen).to_affine();

        hasher.update(a_com.to_bytes());
        hasher.update(b_com.to_bytes());
        hasher.update(c_com.to_bytes());
        hasher.update(d_com.to_bytes());

        let coeff_vecs = get_coeffs(index, ring.len(), m, &a_vec, &b_vec, &omegas)?;

        let mut x_points = Vec::<AffinePoint>::with_capacity(m);
        let mut y_points = Vec::<AffinePoint>::with_capacity(m);

        for (j, rho) in rho_vec.iter().enumerate() {
            let mut sum = ProjectivePoint::IDENTITY;
            for k in 0..ring.len() {
                sum += ring[k] * coeff_vecs[k][j];
            }
            let x = (sum + ProjectivePoint::GENERATOR * rho).to_affine();
            let y = (j_point * rho).to_affine();
            hasher.update(x.to_bytes());
            hasher.update(y.to_bytes());

            x_points.push(x);
            y_points.push(y);
        }

        // NOTE unwrap is fine here as the hasher will always
        // provide a hash with proper size from which the
        // scalar is generated
        let xi = Scalar::from_repr(hasher.finalize()).unwrap();

        let mut f_vec = Vec::<Scalar>::with_capacity(m);
        for (a, b) in a_vec.iter().zip(b_vec.iter()) {
            f_vec.push(b.i_1 * xi + a.i_1);
        }

        let z_a = r_b * xi + r_a;
        let z_c = r_c * xi + r_d;

        let mut xi_pow = Scalar::ONE;
        let z_sum = rho_vec.iter().fold(Scalar::ZERO, |acc, &rho| {
            let next = rho * xi_pow;
            xi_pow *= xi;
            acc + next
        });

        // note x_pow here should be xi^m due to stuff in fold
        let z_scalar = privkey * xi_pow - z_sum;
        privkey.zeroize();

        Ok(Self {
            a_commitment: a_com,
            b_commitment: b_com,
            c_commitment: c_com,
            d_commitment: d_com,
            x_points,
            y_points,
            f_scalars: f_vec,
            z_a_scalar: z_a,
            z_c_scalar: z_c,
            z_scalar,
            tag: j_point.to_affine(),
        })
    }

    pub fn verify(
        &self,
        ring: &Ring,
        message_hash: &[u8],
        parameters: &Parameters,
    ) -> Result<(), String> {
        let mut hasher = Keccak256::new();
        hasher.update(message_hash);

        let mut ring = ring.to_owned();
        let m = pad_ring_to_2n(&mut ring)?;
        for pk in ring.iter() {
            hasher.update(pk.to_bytes())
        }

        let u_point = AffinePoint::GENERATOR * Scalar::from_uint_reduced(U_SCALAR_U256);

        hasher.update(self.a_commitment.to_bytes());
        hasher.update(self.b_commitment.to_bytes());
        hasher.update(self.c_commitment.to_bytes());
        hasher.update(self.d_commitment.to_bytes());

        for (x, y) in self.x_points.iter().zip(self.y_points.iter()) {
            hasher.update(x.to_bytes());
            hasher.update(y.to_bytes());
        }

        // NOTE unwrap is fine here as the hasher will always
        // provide a hash with proper size from which the
        // scalar is generated
        let xi = Scalar::from_repr(hasher.finalize()).unwrap();

        let f_scalars = self
            .f_scalars
            .iter()
            .map(|&elem| VecElem {
                i_0: xi - elem,
                i_1: elem,
            })
            .collect::<Vec<VecElem<Scalar>>>();

        // check commitments
        let mut gen_0_f = ProjectivePoint::IDENTITY;
        let mut gen_1_f = ProjectivePoint::IDENTITY;
        let mut gen_0_f_xi = ProjectivePoint::IDENTITY;
        let mut gen_1_f_xi = ProjectivePoint::IDENTITY;

        for (g, f) in parameters.generators.iter().take(m).zip(f_scalars.iter()) {
            gen_0_f += g.i_0 * f.i_0;
            gen_1_f += g.i_1 * f.i_1;
            gen_0_f_xi += g.i_0 * (f.i_0 * (xi - f.i_0));
            gen_1_f_xi += g.i_1 * (f.i_1 * (xi - f.i_1));
        }

        let com_f = (gen_0_f + gen_1_f + parameters.h_point * self.z_a_scalar).to_affine();
        let com_f_xi = (gen_0_f_xi + gen_1_f_xi + parameters.h_point * self.z_c_scalar).to_affine();

        if (ProjectivePoint::from(self.a_commitment) + self.b_commitment * xi).to_affine() != com_f
        {
            return Err("ab commitment mismatch".to_owned());
        }

        if (ProjectivePoint::from(self.d_commitment) + self.c_commitment * xi).to_affine()
            != com_f_xi
        {
            return Err("cd commitment mismatch".to_owned());
        }

        let (sum_pk_prod_f, sum_prod_f) = sum_f_scalars(&f_scalars, &ring);

        let (x_sum, y_sum) = self.sum_points_with_challenge(xi);

        let first_zero = sum_pk_prod_f - x_sum - AffinePoint::GENERATOR * self.z_scalar;
        let second_zero = u_point * sum_prod_f - y_sum - self.tag * self.z_scalar;

        if first_zero.to_affine() != AffinePoint::IDENTITY {
            return Err("first constraint is nonzero".to_owned());
        }

        if second_zero.to_affine() != AffinePoint::IDENTITY {
            return Err("second constraint is nonzero".to_owned());
        }

        Ok(())
    }

    fn sum_points_with_challenge(&self, xi: Scalar) -> (ProjectivePoint, ProjectivePoint) {
        let mut xi_pow = Scalar::ONE; // xi^0
        self.x_points.iter().zip(self.y_points.iter()).fold(
            (ProjectivePoint::IDENTITY, ProjectivePoint::IDENTITY),
            |(acc_x, acc_y), (&x, &y)| {
                let next_x = acc_x + x * xi_pow;
                let next_y = acc_y + y * xi_pow;
                xi_pow *= xi;
                (next_x, next_y)
            },
        )
    }
}

fn deltas(num: usize, n: usize) -> Vec<VecElem<Scalar>> {
    (0..n)
        .map(|j| {
            if num & 1 << j == 0 {
                VecElem {
                    i_0: Scalar::ONE,
                    i_1: Scalar::ZERO,
                }
            } else {
                VecElem {
                    i_0: Scalar::ZERO,
                    i_1: Scalar::ONE,
                }
            }
        })
        .collect::<Vec<VecElem<Scalar>>>()
}

fn get_coeffs(
    index: usize,
    n: usize,
    m: usize,
    a_vec: &[VecElem<Scalar>],
    b_vec: &[VecElem<Scalar>],
    omegas: &[Scalar],
) -> Result<Vec<Vec<Scalar>>, String> {
    let mut coeff_vecs = Vec::<Vec<Scalar>>::new();
    for k in 0..n {
        let mut evals = vec![Scalar::ONE; m];
        for (omega, eval) in omegas.iter().zip(evals.iter_mut()) {
            let mut highest_order_omega = Scalar::ONE;
            for j in 0..m {
                if k & (1 << j) == 0 {
                    *eval *= b_vec[j].i_0 * omega + a_vec[j].i_0;
                } else {
                    *eval *= b_vec[j].i_1 * omega + a_vec[j].i_1;
                }
                highest_order_omega *= omega;
            }
            if k == index {
                *eval -= highest_order_omega;
            }
        }

        let coeffs = interpolate(omegas, &evals)?;
        coeff_vecs.push(coeffs);
    }
    Ok(coeff_vecs)
}

fn sum_f_scalars(f_scalars: &[VecElem<Scalar>], ring: &Ring) -> (ProjectivePoint, Scalar) {
    let mut sum_pk_prod_f = ProjectivePoint::IDENTITY;
    let mut sum_prod_f = Scalar::ZERO;
    for (k, &pk) in ring.iter().enumerate() {
        let prod_f = f_scalars
            .iter()
            .enumerate()
            .fold(Scalar::ONE, |acc, (j, f)| {
                if k & (1 << j) == 0 {
                    acc * f.i_0
                } else {
                    acc * f.i_1
                }
            });

        sum_pk_prod_f += pk * prod_f;
        sum_prod_f += prod_f;
    }

    (sum_pk_prod_f, sum_prod_f)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keypair::Keypair;

    fn test_signature() -> Signature {
        Signature {
            a_commitment: AffinePoint::IDENTITY,
            b_commitment: AffinePoint::IDENTITY,
            c_commitment: AffinePoint::IDENTITY,
            d_commitment: AffinePoint::IDENTITY,
            x_points: vec![AffinePoint::GENERATOR; 3],
            y_points: vec![AffinePoint::GENERATOR; 3],
            f_scalars: Vec::new(),
            z_a_scalar: Scalar::ZERO,
            z_c_scalar: Scalar::ZERO,
            z_scalar: Scalar::ZERO,
            tag: AffinePoint::GENERATOR,
        }
    }

    fn test_ring(size: usize) -> Ring {
        let mut ring = Ring::with_capacity(size);
        for _ in 0..size {
            ring.push((AffinePoint::GENERATOR * Scalar::random(OsRng)).to_affine());
        }
        ring
    }

    #[test]
    #[rustfmt::skip]
    fn kronecker_delta() {
        let index = 1234_usize; //0b0000010011010010
        let m = 11; // N = 2^11
        let d = deltas(index, m);

        assert_eq!(d.len(), 11);
        assert_eq!(d[0], VecElem { i_0: Scalar::ONE, i_1: Scalar::ZERO }); // 0
        assert_eq!(d[1], VecElem { i_0: Scalar::ZERO, i_1: Scalar::ONE }); // 1
        assert_eq!(d[2], VecElem { i_0: Scalar::ONE, i_1: Scalar::ZERO }); // 0
        assert_eq!(d[3], VecElem { i_0: Scalar::ONE, i_1: Scalar::ZERO }); // 0
        assert_eq!(d[4], VecElem { i_0: Scalar::ZERO, i_1: Scalar::ONE }); // 1
        assert_eq!(d[5], VecElem { i_0: Scalar::ONE, i_1: Scalar::ZERO }); // 0
        assert_eq!(d[6], VecElem { i_0: Scalar::ZERO, i_1: Scalar::ONE }); // 1
        assert_eq!(d[7], VecElem { i_0: Scalar::ZERO, i_1: Scalar::ONE }); // 1
        assert_eq!(d[8], VecElem { i_0: Scalar::ONE, i_1: Scalar::ZERO }); // 0
        assert_eq!(d[9], VecElem { i_0: Scalar::ONE, i_1: Scalar::ZERO }); // 0
        assert_eq!(d[10], VecElem { i_0: Scalar::ZERO, i_1: Scalar::ONE }); // 1
    }

    #[test]
    #[rustfmt::skip]
    fn coeff_interpolation() {
        let m = 2; // exponent
        let n = 4; // 2^exponent
        let index = 1; // we are second in the ring
        let omegas = vec![Scalar::from(2u32), Scalar::from(3u32)];
        let a_vec = vec![
            VecElem { i_0: Scalar::ONE, i_1: Scalar::from(2u32) },
            VecElem { i_0: Scalar::from(3u32), i_1: Scalar::from(4u32) },
        ];
        let b_vec = vec![
            VecElem { i_0: Scalar::from(5u32), i_1: Scalar::from(6u32) },
            VecElem { i_0: Scalar::from(7u32), i_1: Scalar::from(8u32) },
        ];

        let coeffs = get_coeffs(index, n, m, &a_vec, &b_vec, &omegas).unwrap();
        assert_eq!(-coeffs[0][0], Scalar::from(207u32));
        assert_eq!(-coeffs[1][0], Scalar::from(240u32));
        assert_eq!(-coeffs[2][0], Scalar::from(236u32));
        assert_eq!(-coeffs[3][0], Scalar::from(280u32));
        assert_eq!(coeffs[0][1], Scalar::from(197u32));
        assert_eq!(coeffs[1][1], Scalar::from(237u32));
        assert_eq!(coeffs[2][1], Scalar::from(228u32));
        assert_eq!(coeffs[3][1], Scalar::from(280u32));

        assert_eq!(coeffs[0][0] + omegas[0] * coeffs[0][1], Scalar::from(187u32));
        assert_eq!(coeffs[0][0] + omegas[1] * coeffs[0][1], Scalar::from(384u32));

        assert_eq!(coeffs[1][0] + omegas[0] * coeffs[1][1], Scalar::from(234u32));
        assert_eq!(coeffs[1][0] + omegas[1] * coeffs[1][1], Scalar::from(471u32));

        assert_eq!(coeffs[2][0] + omegas[0] * coeffs[2][1], Scalar::from(220u32));
        assert_eq!(coeffs[2][0] + omegas[1] * coeffs[2][1], Scalar::from(448u32));

        assert_eq!(coeffs[3][0] + omegas[0] * coeffs[3][1], Scalar::from(280u32));
        assert_eq!(coeffs[3][0] + omegas[1] * coeffs[3][1], Scalar::from(560u32));
    }

    #[test]
    fn sum_xy_points() {
        let signature = test_signature();
        let (x_sum, y_sum) = signature.sum_points_with_challenge(Scalar::ONE);
        assert_eq!(x_sum, AffinePoint::GENERATOR * Scalar::from(3u32));
        assert_eq!(y_sum, AffinePoint::GENERATOR * Scalar::from(3u32));
        let (x_sum, y_sum) = signature.sum_points_with_challenge(Scalar::from(3u32));
        assert_eq!(x_sum, AffinePoint::GENERATOR * Scalar::from(13u32));
        assert_eq!(y_sum, AffinePoint::GENERATOR * Scalar::from(13u32));
    }

    #[test]
    #[rustfmt::skip]
    fn f_scalars_summed() {
        let ring = vec![
            AffinePoint::GENERATOR,
            (AffinePoint::GENERATOR * Scalar::from(2u32)).to_affine(),
        ];

        let f_scalars = vec![
            VecElem { i_0: Scalar::ONE, i_1: Scalar::from(2u32) },
            VecElem { i_0: Scalar::from(3u32), i_1: Scalar::from(4u32) },
            VecElem { i_0: Scalar::from(5u32), i_1: Scalar::from(6u32) },
        ];

        let (pk_sum, sum) = sum_f_scalars(&f_scalars, &ring);
        assert_eq!(sum, Scalar::from(45u32));
        assert_eq!(pk_sum, AffinePoint::GENERATOR * Scalar::from(75u32));
    }

    #[test]
    fn valid_signature() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let mut ring = test_ring(5);
        let index = 2_usize;
        ring[index] = keypair.public;

        let msg = b"hello there!";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(signature.verify(&ring, &msg_hash, &parameters).is_ok());
    }

    #[test]
    fn invalid_not_in_ring() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let ring = test_ring(30);
        let index = 2_usize;
        let msg = b"I'm not in the ring!";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(signature.verify(&ring, &msg_hash, &parameters).is_err());
    }

    #[test]
    fn invalid_index() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let mut ring = test_ring(10);
        ring[7] = keypair.public;
        let index = 2_usize;
        let msg = b"My pubkey is at the wrong index!";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(signature.verify(&ring, &msg_hash, &parameters).is_err());
    }

    #[test]
    fn invalid_msg_hash() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let mut ring = test_ring(10);
        let index = 3_usize;
        ring[index] = keypair.public;
        let msg = b"The original message";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();

        let wrong_msg = b"Some other message";
        let mut hasher = Keccak256::new();
        hasher.update(wrong_msg);
        let wrong_msg_hash = hasher.finalize();
        assert!(signature
            .verify(&ring, &wrong_msg_hash, &parameters)
            .is_err());
    }

    #[test]
    fn invalid_different_ring() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let mut ring = test_ring(8);
        let index = 5_usize;
        ring[index] = keypair.public;
        let msg = b"asdf";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        ring.push(AffinePoint::GENERATOR);
        assert!(signature.verify(&ring, &msg_hash, &parameters).is_err());
    }

    #[test]
    fn invalid_parameters() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let mut ring = test_ring(8);
        let index = 5_usize;
        ring[index] = keypair.public;
        let msg = b"asdf";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        let parameters = Parameters::new(10);
        assert!(signature.verify(&ring, &msg_hash, &parameters).is_err());
    }

    #[test]
    fn linkability() {
        let parameters = Parameters::new(10);
        let keypair = Keypair::random();
        let mut ring = test_ring(8);
        let index = 5_usize;
        ring[index] = keypair.public;
        let msg = b"asdf";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        // sign exactly the same ring with same message
        let signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(signature.verify(&ring, &msg_hash, &parameters).is_ok());

        let same_signature =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(same_signature.verify(&ring, &msg_hash, &parameters).is_ok());
        assert_eq!(same_signature.tag, signature.tag);

        // change message
        let msg = b"asdf";
        let mut hasher = Keccak256::new();
        hasher.update(msg);
        let msg_hash = hasher.finalize();

        let diff_msg_sig =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(diff_msg_sig.verify(&ring, &msg_hash, &parameters).is_ok());
        assert_eq!(diff_msg_sig.tag, signature.tag);
        // change ring and even the parameters
        let parameters = Parameters::new(10);
        ring.push(AffinePoint::GENERATOR);
        let different_sig =
            Signature::new(index, &ring, &msg_hash, keypair.private, &parameters).unwrap();
        assert!(different_sig.verify(&ring, &msg_hash, &parameters).is_ok());
        assert_eq!(different_sig.tag, signature.tag);
    }
}
