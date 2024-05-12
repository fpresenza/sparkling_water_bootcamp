use gcd::Gcd;
use lambdaworks_math::field::fields::u64_prime_field::U64FieldElement;

fn main() {
    // Take two prime numbers in the range 2..2^32. 
    // This primes are taken from SageMath, since I don't know
    // which library use to generate random primes in Rust.
    // Also, it is checked that (p-1) * (q-1) is relatively prime 
    // to the encryption key.
    // let p = 598991051_u64;
    // let q = 2840026297_u64;
    // MOD equals p * q
    const MOD: u64 = 1701150336507668147;
    type FEMOD = U64FieldElement<MOD>;
    const PHI_MOD: u64 = 1701150333068650800;
    type FEPHI = U64FieldElement<PHI_MOD>;
    let phi_phi_mod = 388215687235276800_u64;

    // TODO: using carmichael's is suppossedly more eficient.

    // Generate keys
    // It was checked using SageMath that 65537 is coprime to PHI_MOD
    let encryption_key = 65537_u64;
    assert_eq!(Gcd::gcd(encryption_key, PHI_MOD), 1);
    println!("Encryption key is: ({}, {})", encryption_key, MOD);

    // Here I use the .pow() method instead of the .inv() method since only
    // the former is correct: 
    // since PHI_MOD is not prime, given a number e, its inverse, d, equals:
    //      d = e^{phi(PHI_MOD) - 1} % PHI_MOD
    // but
    //      d != e^{PHI_MOD - 2} % PHI_MOD 
    // as is implemented in the .inv() method.
    let decryption_key = *FEPHI::new(encryption_key).pow(phi_phi_mod - 1).value();
    println!("Decryption key is: ({}, {})", decryption_key, MOD);

    // encrypt messages
    let plain_msg = 68353567629759241_u64;
    println!("Plain message is: {}", plain_msg);
    
    let cypher_msg = *FEMOD::new(plain_msg).pow(encryption_key).value();
    println!("Encrypted message is: {}", cypher_msg);
    
    let recov_msg = *FEMOD::new(cypher_msg).pow(decryption_key).value();
    println!("Recovered message is {}", recov_msg);
}
