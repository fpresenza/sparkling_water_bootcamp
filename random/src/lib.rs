use num_primes::Generator;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub fn random_unsigned_integer<const NUM_LIMBS: usize>(bit_size: usize) -> UnsignedInteger<NUM_LIMBS> {
    UnsignedInteger::<NUM_LIMBS>::from_hex(
        &Generator::new_prime(bit_size).to_str_radix(16)
    ).unwrap()
}