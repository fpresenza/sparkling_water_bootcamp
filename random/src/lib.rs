use num_primes::Generator;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::prelude::*;

const LIMB_SIZE_BIT: usize = 64;
const LIMB_MAX: u64 = u64::MAX;

pub fn random_integer<const NUM_LIMBS: usize>() -> UnsignedInteger<NUM_LIMBS> {
    let mut limbs: [u64; NUM_LIMBS] = [0; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        limbs[i] = rand::thread_rng().gen_range(0..LIMB_MAX);
    }
    UnsignedInteger::<NUM_LIMBS>::from_limbs(limbs)
}

pub fn random_integer_in_range<const NUM_LIMBS: usize>(
        low: UnsignedInteger<NUM_LIMBS>, high: UnsignedInteger<NUM_LIMBS>
    ) -> UnsignedInteger<NUM_LIMBS> {

    loop {
        let num = random_integer::<NUM_LIMBS>();
        if (num >= low) & (num < high) {
            break num
        }
    }
}

pub fn random_prime_from_bitsize<const NUM_LIMBS: usize>(
        bit_size: usize
    ) -> UnsignedInteger<NUM_LIMBS> {
    UnsignedInteger::<NUM_LIMBS>::from_hex(
        &Generator::new_prime(bit_size).to_str_radix(16)
    ).unwrap()
}

// Generate a random number with given number of limbs and in a certain range.NUM_LIMBS
// TODO: test random numbers only with floor(log2(high)) + 1 bits. 
pub fn random_prime_in_range<const NUM_LIMBS: usize>(
        low: UnsignedInteger<NUM_LIMBS>, high: UnsignedInteger<NUM_LIMBS>
    ) -> UnsignedInteger<NUM_LIMBS> {

    loop {
        let num = random_prime_from_bitsize::<NUM_LIMBS>(NUM_LIMBS * LIMB_SIZE_BIT);
        if (num >= low) & (num < high) {
            break num
        }
    }
}
    
