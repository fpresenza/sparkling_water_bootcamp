use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub fn power_mod<const NUM_LIMBS: usize>(
        mut base: UnsignedInteger<NUM_LIMBS>,
        mut exp: UnsignedInteger<NUM_LIMBS>,
        modulus: &UnsignedInteger<NUM_LIMBS>,
    ) -> UnsignedInteger<NUM_LIMBS> {
    //
    // Fast modular powering algorithm.
    // Actually div_rem is not to efficient, so Montgomery Arithmetics are preferred.
    //
    let zero = UnsignedInteger::<NUM_LIMBS>::from_u64(0);
    let one = UnsignedInteger::<NUM_LIMBS>::from_u64(1);

    if exp == zero {
        one
    } else if exp == one {
        base
    } else {
        let mut result = one;
        while exp > one {
            if exp & one == one {
                (_, result) = (result * base).div_rem(modulus);
                exp = exp - one;
            }
            (_, base) = (base * base).div_rem(modulus);
            exp >>= 1;
        }
        (_, result) = (base * result).div_rem(modulus);
        result
    }
}

pub fn extended_euclidean_algorithm<const NUM_LIMBS: usize>(
        a: UnsignedInteger<NUM_LIMBS>, b: UnsignedInteger<NUM_LIMBS>,
    ) -> (UnsignedInteger<NUM_LIMBS>, UnsignedInteger<NUM_LIMBS>, UnsignedInteger<NUM_LIMBS>) {
    let zero = UnsignedInteger::<NUM_LIMBS>::from_u64(0);
    let one = UnsignedInteger::<NUM_LIMBS>::from_u64(1);

    let (mut r0, mut r1) = (a, b);
    let (mut s0, mut s1) = (one, zero);
    let (mut t0, mut t1) = (zero, one);

    let mut n: u64 = 0;

    while r1 != zero {
        let (q, _) = r0.div_rem(&r1);

        r0 = if r0 > q * r1 {
            r0 - q * r1
        } else {
            q * r1 - r0
        };

        (r0, r1) = (r1, r0);

        s0 = s0 + q * s1;
        (s0, s1) = (s1, s0);

        t0 = t0 + q * t1;
        (t0, t1) = (t1, t0);

        n += 1;
    }

    if n & 1 == 1 {
        s0 = b - s0;
    } else {
        t0 = a - t0;
    }

    (r0, s0, t0)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_mod_works_2_limbs() {
        let b = UnsignedInteger::<2>::from_u128(18446744069414584321);
        let exp = UnsignedInteger::<2>::from_u128(125);
        let modulus = UnsignedInteger::<2>::from_u128(2147483648);
        let expected = UnsignedInteger::<2>::from_u128(1);
        let obtained = power_mod(b, exp, &modulus);
        assert_eq!(obtained, expected);
    }
}