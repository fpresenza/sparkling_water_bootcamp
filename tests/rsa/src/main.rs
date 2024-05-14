use num_primes::Generator;
use lambdaworks_math::{traits::ByteConversion, unsigned_integer::element::UnsignedInteger};
use number_theory::{power_mod, extended_euclidean_algorithm};

const LIMB_SIZE_BIT: usize = 64;
const LIMB_SIZE_BYTE: usize = 8;

fn random_unsigned_integer<const NUM_LIMBS: usize>(bit_size: usize) -> UnsignedInteger<NUM_LIMBS> {
    UnsignedInteger::<NUM_LIMBS>::from_hex(
        &Generator::new_prime(bit_size).to_str_radix(16)
    ).unwrap()
}

#[derive(Debug)]
struct RSA<const NUM_LIMBS: usize> {
    encryption_exp: UnsignedInteger<NUM_LIMBS>,
    decryption_exp: UnsignedInteger<NUM_LIMBS>,
    modulus: UnsignedInteger<NUM_LIMBS>
}

impl<const NUM_LIMBS: usize> RSA<NUM_LIMBS> {
    fn new() -> Self {
        let zero = UnsignedInteger::<NUM_LIMBS>::from_u64(0);
        let one = UnsignedInteger::<NUM_LIMBS>::from_u64(1);
        let bit_size = NUM_LIMBS * LIMB_SIZE_BIT / 4;

        // generate two random primes of bitsize
        //      NUM_LIMBS * LIMB_SIZE_BIT / 4 
        // to prevent UnsignedInteger overflow.
        let p = random_unsigned_integer::<NUM_LIMBS>(bit_size);
        let q = random_unsigned_integer::<NUM_LIMBS>(bit_size);

        let modulus = &p * &q;
        let euler_phi = (&p - &one) * (&q - &one);

        // check 65537 < euler_phi and the they have no common factors.
        // Since 65537 is prime, it is sufficient to check that is not a
        // multiple of 65537.
        let encryption_exp = UnsignedInteger::<NUM_LIMBS>::from_u64(65537);
        assert!(encryption_exp < euler_phi);
        let (_, rem) = euler_phi.div_rem(&encryption_exp);
        assert!(rem != zero);
        
        let (_, decryption_exp, _) = extended_euclidean_algorithm(
            encryption_exp.clone(),
            euler_phi.clone()
        );

        Self { 
            encryption_exp,
            decryption_exp,
            modulus
        }
    }

    fn encrypt(
            &self,
            plaintext_as_integer: UnsignedInteger<NUM_LIMBS>, 
            encryption_exp: UnsignedInteger<NUM_LIMBS>,
            modulus: &UnsignedInteger<NUM_LIMBS>
        ) -> UnsignedInteger<NUM_LIMBS> {
        assert!(plaintext_as_integer < *modulus);
        power_mod(plaintext_as_integer, encryption_exp, modulus)
    }

    fn decrypt(
            &self, 
            cyphertext_as_integer: UnsignedInteger<NUM_LIMBS>, 
        ) -> UnsignedInteger<NUM_LIMBS> {
        power_mod(cyphertext_as_integer, self.decryption_exp, &self.modulus)
    }
}

fn main() {
    const NUM_LIMBS: usize = 8;
    type RSA512 = RSA<NUM_LIMBS>;

    println!("----------");
    println!("Generating Alice's key.");
    let alica_rsa = RSA512::new();
    println!("Alice's key: {:?}", alica_rsa);
    println!("----------");
    println!("Generating Bob's key.");
    let bob_rsa = RSA512::new();
    println!("Bob's key: {:?}", alica_rsa);

    // encrypt messages
    println!("----------");
    // let message = 
    let message = "Hi! This is a Secret Message.";
    let max_bytes = LIMB_SIZE_BYTE * NUM_LIMBS;
    assert!(message.len() <= max_bytes);
    println!("Plain message from Alice to Bob: {:?}", message);
    let mut padded_message = (0..max_bytes-message.len()).map(|_| "\x00").collect::<String>();
    padded_message.push_str(message);
    // println!("padded_message {:?}", padded_message);

    let plaintext_as_bytes = padded_message.as_bytes();
    // println!("Plaintext as bytes: {:?}", plaintext_as_bytes);

    let plaintext_as_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
        &plaintext_as_bytes
    ).unwrap();
    // println!("Message as UnsigedInteger: {:?}", plaintext_as_integer);

    let cyphertext_as_integer = alica_rsa.encrypt(
        plaintext_as_integer,
        bob_rsa.encryption_exp.clone(),
        &bob_rsa.modulus
    );
    // println!("Encrypted message as UnsigedInteger: {:?}", cyphertext_as_integer);
    
    let cyphertext_as_bytes = cyphertext_as_integer.to_bytes_be();
    // println!("Encrypted message as bytes from Alice to Bob: {:?}", cyphertext_as_bytes);

    println!(
        "
        ---------------------------->
        Sending over insecure channel
        ---------------------------->
        "
    );

    let recovered_cyphertext_as_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
        &cyphertext_as_bytes  
    ).unwrap();
    // println!("Recovered Encrypted message as UnsigedInteger: {:?}", recovered_cyphertext_as_integer);

    let recovered_plaintext_as_integer = bob_rsa.decrypt(recovered_cyphertext_as_integer);
    // println!("Recovered message is {:?}", recovered_plaintext_as_integer);

    let recovered_plaintext_as_bytes = recovered_plaintext_as_integer.to_bytes_be();
    // println!("Recovered plaintext as bytes is {:?}", recovered_plaintext_as_bytes);

    let recoverd_message = String::from_utf8(recovered_plaintext_as_bytes);
    println!("Recovered message {:?}", recoverd_message.unwrap());

}
