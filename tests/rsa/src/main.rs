use num_primes::Generator;
use blake2::{Blake2s256, Digest};
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

        // generate two random primes of bitsize
        //      NUM_LIMBS * LIMB_SIZE_BIT / 4 
        // to prevent UnsignedInteger overflow.
        let bit_size = NUM_LIMBS * LIMB_SIZE_BIT / 4;
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
    const NUM_LIMBS: usize = 16;
    type RSA512 = RSA<NUM_LIMBS>;

    println!("RSA {} bits", NUM_LIMBS * LIMB_SIZE_BIT);

    //
    // Generate Keys //
    //   
    println!("----------");
    println!("Generating Alice's keys.");
    let alice_rsa = RSA512::new();
    // println!("Alice's keys: {:?}", alice_rsa);
    println!("----------");
    println!("Generating Bob's keys.");
    let bob_rsa = RSA512::new();
    // println!("Bob's keys: {:?}", bob_rsa);
    println!("----------");


    //
    // Encrypt plaintext //
    //
    let plaintext = "Secret message.";
    println!("Plaintext from Alice to Bob: {:?}", plaintext);

    // check message has proper size
    let extra_bytes = NUM_LIMBS * LIMB_SIZE_BYTE - plaintext.len();
    assert!(extra_bytes > 0);

    let mut plaintext_as_bytes = plaintext.as_bytes().to_vec();
    // println!("Plaintext as bytes: {:?}", plaintext_as_bytes);

    let mut padded_plaintext_as_bytes = vec![0; extra_bytes];
    padded_plaintext_as_bytes.append(&mut plaintext_as_bytes);
    // println!("Padded plaintext as bytes: {:?}", padded_plaintext_as_bytes);

    let plaintext_as_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
        &padded_plaintext_as_bytes
    ).unwrap();
    // println!("Plaintext as integer: {:?}", plaintext_as_integer);

    let cyphertext_as_integer = alice_rsa.encrypt(
        plaintext_as_integer,
        bob_rsa.encryption_exp.clone(),
        &bob_rsa.modulus
    );
    // println!("Cyphertex as integer: {:?}", cyphertext_as_integer);
    
    let cyphertext_as_bytes = cyphertext_as_integer.to_bytes_be();
    // println!("Cyphertex as bytes from Alice to Bob: {:?}", cyphertext_as_bytes);

    //
    // Signature scheme //
    // Uses Blake2s256 hash function with digest of 32 bytes
    //
    const DIGEST_SIZE_BYTE: usize = 32;
    let extra_bytes = NUM_LIMBS * LIMB_SIZE_BYTE - DIGEST_SIZE_BYTE;
    let mut hasher = Blake2s256::new();
    hasher.update(padded_plaintext_as_bytes);
    let mut hashtext_as_bytes = vec![0; extra_bytes];
    hashtext_as_bytes.append(&mut hasher.finalize().to_vec());
    // println!("Hashed text as bytes: {:?}", hashtext_as_bytes);
    
    let hashtext_as_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
        &hashtext_as_bytes
    ).unwrap();
    // println!("Hashed text as integer: {:?}", hashtext_as_integer);
    assert!(hashtext_as_integer < bob_rsa.modulus);

    let signedtext_as_integer = alice_rsa.decrypt(hashtext_as_integer);
    let signedtext_as_bytes = signedtext_as_integer.to_bytes_be();

    println!(
        "
        ---------------------------->
        Sending over insecure channel:

        message: {:?}

        signature: {:?}
        ---------------------------->
        ",
        cyphertext_as_bytes,
        signedtext_as_bytes
    );

    let recovered_cyphertext_as_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
        &cyphertext_as_bytes  
    ).unwrap();
    // println!("Recovered cyphertex as integer: {:?}", recovered_cyphertext_as_integer);

    let recovered_plaintext_as_integer = bob_rsa.decrypt(recovered_cyphertext_as_integer);
    // println!("Recovered plaintext: {:?}", recovered_plaintext_as_integer);

    let recovered_plaintext_as_bytes = recovered_plaintext_as_integer.to_bytes_be();
    // println!("Recovered plaintext as bytes: {:?}", recovered_plaintext_as_bytes);

    let recovered_plaintext = String::from_utf8(recovered_plaintext_as_bytes).unwrap();
    println!("Recovered plaintext: {:?}", recovered_plaintext);

    // check signature validity
    let recovered_signedtext_as_integer =  UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
        &signedtext_as_bytes  
    ).unwrap();

    let recovered_hashtext_as_integer = bob_rsa.encrypt(
        recovered_signedtext_as_integer,
        alice_rsa.encryption_exp.clone(),
        &alice_rsa.modulus
    );
    let mut recovered_hashtext_as_bytes = recovered_hashtext_as_integer.to_bytes_be();
    recovered_hashtext_as_bytes.drain(0..extra_bytes);
    // println!("Recovered hashtext as bytes{:?}", recovered_hashtext_as_bytes);

    let mut hasher = Blake2s256::new();
    hasher.update(recovered_plaintext.as_bytes());
    let hashed_recovered_plaintext_as_bytes = hasher.finalize().to_vec();
    // println!("Hashed recovered plaintext as bytes: {:?}", hashed_recovered_plaintext_as_bytes);

    if recovered_hashtext_as_bytes == hashed_recovered_plaintext_as_bytes {
        println!("Signature has been successfully validated.");
    } else {
        println!("Signature is invalid.");
    }
}
