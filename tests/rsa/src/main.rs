use num_primes::Generator;
use blake2::{Blake2s256, Digest};
use lambdaworks_math::{traits::ByteConversion, unsigned_integer::element::UnsignedInteger};
use number_theory::{power_mod, extended_euclidean_algorithm};

const LIMB_SIZE_BIT: usize = 64;
const LIMB_SIZE_BYTE: usize = 8;
const DIGEST_SIZE_BYTE: usize = 32;

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

    fn public_key(&self) -> (UnsignedInteger<NUM_LIMBS>, UnsignedInteger<NUM_LIMBS>) {
        (self.encryption_exp.clone(), self.modulus.clone())
    }

    fn plaintext_as_bytes(plaintext: &str) -> Vec<u8> {
        // add zeros to fill the proper size
        let extra_bytes = NUM_LIMBS * LIMB_SIZE_BYTE - plaintext.len();
        assert!(extra_bytes > 0);
    
        let mut plaintext_as_bytes = plaintext.as_bytes().to_vec();
        let mut padded_plaintext_as_bytes = vec![0; extra_bytes];
        padded_plaintext_as_bytes.append(&mut plaintext_as_bytes);
        padded_plaintext_as_bytes
    }


    fn encrypt(
            &self,
            plaintext_as_bytes: Vec<u8>,
            public_key: (UnsignedInteger<NUM_LIMBS>, UnsignedInteger<NUM_LIMBS>)
        ) -> Vec<u8> {
        let (exponent, modulus) = public_key;
        let plaintext_as_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
            &plaintext_as_bytes
        ).unwrap();
        assert!(plaintext_as_integer < modulus);

        power_mod(plaintext_as_integer, exponent, &modulus).to_bytes_be()
    }

    fn decrypt(&self, encrypted_bytes: Vec<u8>) -> Vec<u8> {
        let encripted_integer = UnsignedInteger::<NUM_LIMBS>::from_bytes_be(
            &encrypted_bytes  
        ).unwrap();

        let decrypted_integer = power_mod(
            encripted_integer,
            self.decryption_exp.clone(),
            &self.modulus
        );
        let decrypted_bytes = decrypted_integer.to_bytes_be();
        decrypted_bytes
    }

    // Signature scheme: uses Blake2s256 hash function with digest of 32 bytes
    fn sign(&self, plaintext_as_bytes: Vec<u8>) -> Vec<u8> {
        let extra_bytes = NUM_LIMBS * LIMB_SIZE_BYTE - DIGEST_SIZE_BYTE;

        let mut hasher = Blake2s256::new();
        hasher.update(plaintext_as_bytes);
        let mut hashtext_as_bytes = vec![0; extra_bytes];
        hashtext_as_bytes.append(&mut hasher.finalize().to_vec());

        self.decrypt(hashtext_as_bytes)
    }

    fn validate_signature(
            &self,
            signedtext_as_bytes: Vec<u8>, 
            plaintext_as_bytes: Vec<u8>,
            public_key: (UnsignedInteger<NUM_LIMBS>, UnsignedInteger<NUM_LIMBS>)
        ) -> bool {

        let mut hashtext_as_bytes = self.encrypt(
            signedtext_as_bytes,
            public_key
        );
    
        let mut hasher = Blake2s256::new();
        let extra_bytes = NUM_LIMBS * LIMB_SIZE_BYTE - DIGEST_SIZE_BYTE;
        hashtext_as_bytes.drain(0..extra_bytes);
        hasher.update(plaintext_as_bytes);
        let hashed_plaintext_as_bytes = hasher.finalize().to_vec();
        hashtext_as_bytes == hashed_plaintext_as_bytes
    }
}

fn main() {
    // Hash function used has a digest of 32 bytes,
    // therefore RSA modulus should be at least 32 bytes.
    // In this implementation, the modulus is approximately
    // half of the size of the RSA, which therefore should be 
    // of at least 64 bytes = 512 bits = 8 limbs.
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
    let plaintext_as_bytes = RSA512::plaintext_as_bytes(plaintext);

    let cyphertext_as_bytes = alice_rsa.encrypt(
        plaintext_as_bytes.clone(),
        bob_rsa.public_key()
    );

    let signedtext_as_bytes = alice_rsa.sign(plaintext_as_bytes);

    println!(
        "
        ---------------------------->
        Sending over insecure channel:

        message: {:X?}

        signature: {:X?}
        ---------------------------->
        ",
        cyphertext_as_bytes,
        signedtext_as_bytes
    );

    let recovered_plaintext_as_bytes = bob_rsa.decrypt(cyphertext_as_bytes);
    let recovered_plaintext = String::from_utf8(recovered_plaintext_as_bytes.clone()).unwrap();
    println!("Recovered plaintext: {:?}", recovered_plaintext);

    let valid_signature = bob_rsa.validate_signature(
        signedtext_as_bytes,
        recovered_plaintext_as_bytes,
        alice_rsa.public_key()
    );
    if valid_signature {
        println!("Signature has been successfully validated.");
    } else {
        println!("Signature is invalid.");
    }
}
