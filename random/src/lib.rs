use num_primes::Generator;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

const LIMB_SIZE_BIT: usize = 64;

pub fn random_unsigned_integer<const NUM_LIMBS: usize>(bit_size: usize) -> UnsignedInteger<NUM_LIMBS> {
    UnsignedInteger::<NUM_LIMBS>::from_hex(
        &Generator::new_prime(bit_size).to_str_radix(16)
    ).unwrap()
}

// Generate a random number with given number of limbs and in a certain range.NUM_LIMBS
// TODO: test random numbers only with floor(log2(high)) + 1 bits. 
pub fn random_unsigned_integer_in_range<const NUM_LIMBS: usize>(
        low: UnsignedInteger<NUM_LIMBS>, high: UnsignedInteger<NUM_LIMBS>
    ) -> UnsignedInteger<NUM_LIMBS> {

    loop {
        let num = random_unsigned_integer::<NUM_LIMBS>(NUM_LIMBS * LIMB_SIZE_BIT);
        if (num >= low) & (num < high) {
            break num
        }
    }
}
    
