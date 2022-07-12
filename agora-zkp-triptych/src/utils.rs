use k256::Scalar;

pub fn interpolate(x: &[Scalar], y: &[Scalar]) -> Result<Vec<Scalar>, String> {
    if x.len() != y.len() {
        return Err("input lengths not equal".to_string());
    }

    let n = x.len();

    let mut s = vec![Scalar::ZERO; n];
    let mut coeffs = vec![Scalar::ZERO; n];

    s.push(Scalar::ONE);
    s[n - 1] = -x[0];

    for (i, x_elem) in x.iter().enumerate().skip(1) {
        #[allow(clippy::assign_op_pattern)]
        for j in n - 1 - i..n - 1 {
            s[j] = s[j] - *x_elem * s[j + 1];
        }
        s[n - 1] -= *x_elem;
    }

    for i in 0..n {
        let mut phi = Scalar::ZERO;
        for j in (1..=n).rev() {
            phi = Scalar::from(j as u64) * s[j] + x[i] * phi;
        }
        let ff_option = phi.invert();
        if ff_option.is_some().unwrap_u8() == 0 {
            return Err("tried to invert a zero scalar".to_owned());
        }
        // NOTE unwrap is fine due to the above check
        let ff = ff_option.unwrap();
        let mut b = Scalar::ONE;
        for j in (0..n).rev() {
            coeffs[j] += b * ff * y[i];
            b = s[j] + x[i] * b;
        }
    }

    Ok(coeffs)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ops::Neg;
    #[test]
    fn interpolate_polynomial() {
        // not equal length inputs
        let x = vec![Scalar::from(3u32); 3];
        let y = vec![Scalar::from(5u32); 4];
        assert!(interpolate(&x, &y).is_err());

        // constant polynomial (y = 53)
        let x = vec![Scalar::from(3u32); 1];
        let y = vec![Scalar::from(53u32); 1];
        let coeffs = interpolate(&x, &y).unwrap();
        assert_eq!(coeffs[0], Scalar::from(53u32));

        // simple first order polynomial (y = x)
        let x = vec![Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];

        let y = x.clone();
        let coeffs = interpolate(&x, &y).unwrap();
        assert_eq!(coeffs[0], Scalar::ZERO); // c_0
        assert_eq!(coeffs[1], Scalar::ONE); // c_1
        assert_eq!(coeffs[2], Scalar::ZERO); // c_2

        // first order polynomial (y = 22 * x + 7)
        let x = vec![Scalar::from(2u32), Scalar::from(3u32)];
        let y = vec![Scalar::from(51u32), Scalar::from(83u32)];
        let coeffs = interpolate(&x, &y).unwrap();
        // values taken from zkp js interpolate
        assert_eq!(coeffs[0], Scalar::from(13u32).neg());
        assert_eq!(coeffs[1], Scalar::from(0x20u32));

        // fourth order polynomial
        // y = x^4 + 0 * x^3 + 3 * x^2 + 2 * x + 14
        let x = vec![
            Scalar::from(1u32),
            Scalar::from(2u32),
            Scalar::from(3u32),
            Scalar::from(4u32),
            Scalar::from(5u32),
            Scalar::from(6u32),
        ];
        let y = vec![
            Scalar::from(20u32),
            Scalar::from(46u32),
            Scalar::from(128u32),
            Scalar::from(326u32),
            Scalar::from(724u32),
            Scalar::from(1430u32),
        ];
        let coeffs = interpolate(&x, &y).unwrap();
        assert_eq!(coeffs[0], Scalar::from(14u32)); // c0 (x^0)
        assert_eq!(coeffs[1], Scalar::from(2u32)); // c1 (x^1)
        assert_eq!(coeffs[2], Scalar::from(3u32)); // c2 (x^2)
        assert_eq!(coeffs[3], Scalar::from(0u32)); // c3 (x^3)
        assert_eq!(coeffs[4], Scalar::from(1u32)); // c4 (x^4)
        assert_eq!(coeffs[5], Scalar::from(0u32)); // c5 (x^5)
    }
}
