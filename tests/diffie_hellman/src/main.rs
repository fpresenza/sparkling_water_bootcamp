use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::{
        traits::IsEllipticCurve,
        short_weierstrass::curves::{
            bls12_381::curve::BLS12381Curve,
            bn_254::curve::BN254Curve
        }
};
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use random::random_integer_in_range;

const BLS12381_LIMBS: usize = 4;
const BLS12381_SUBGROUP_ORDER: UnsignedInteger<BLS12381_LIMBS> = UnsignedInteger::<BLS12381_LIMBS>::from_hex_unchecked(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
);

const BN254_LIMBS: usize = 4;
const BN254_SUBGROUP_ORDER: UnsignedInteger<BN254_LIMBS> = UnsignedInteger::<BN254_LIMBS>::from_hex_unchecked(
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
);



struct DiffieHellman<T: IsEllipticCurve, const NUM_LIMBS: usize> {
    private_number: UnsignedInteger<NUM_LIMBS>,
    public_number: T::PointRepresentation,
    shared_key: Option<T::PointRepresentation>
}

impl<T: IsEllipticCurve, const NUM_LIMBS: usize> DiffieHellman<T, NUM_LIMBS> {
    fn new(order: UnsignedInteger<NUM_LIMBS>) -> Self {
        let zero = UnsignedInteger::<NUM_LIMBS>::from_u64(0);
        
        // generate private number
        let private_number = random_integer_in_range::<NUM_LIMBS>(zero, order);
        // println!("Private Number: {:?}", private_number);
        let generator = T::generator();
    
        // generate public number
        let public_number = generator.operate_with_self(private_number);
    
        Self {
            private_number,
            public_number,
            shared_key: None
        }
    }

    fn get_shared_key(&mut self, other_public_number: &T::PointRepresentation) {
        self.shared_key = Some(other_public_number.operate_with_self(self.private_number))
    }
}


fn main() {
    // Diffie-Hellman with BLS12_384 curve
    let mut alice = DiffieHellman::<BLS12381Curve, BLS12381_LIMBS>::new(BLS12381_SUBGROUP_ORDER);
    let mut bob = DiffieHellman::<BLS12381Curve, BLS12381_LIMBS>::new(BLS12381_SUBGROUP_ORDER);

    // Diffie-Hellman with BN_254 curve
    let mut charly = DiffieHellman::<BN254Curve, BN254_LIMBS>::new(BN254_SUBGROUP_ORDER);
    let mut donald = DiffieHellman::<BN254Curve, BN254_LIMBS>::new(BN254_SUBGROUP_ORDER);


    println!(
        "
        ---------------------------->
        Sending over insecure channel:

        Alice's public number: {:?}

        Bob's public number: {:?}
        ---------------------------->
        ",
        alice.public_number,
        bob.public_number
    );

    println!(
        "
        ---------------------------->
        Sending over insecure channel:

        Charly's public number: {:?}

        Donald's public number: {:?}
        ---------------------------->
        ",
        charly.public_number,
        donald.public_number
    );

    alice.get_shared_key(&bob.public_number);
    bob.get_shared_key(&alice.public_number);
    // println!("Alice's Shared Key: {:?}", alice.shared_key.as_ref().unwrap().to_affine());
    // println!("Bob's Shared Key: {:?}", bob.shared_key.as_ref().unwrap().to_affine());
    if alice.shared_key == bob.shared_key {
        println!("Key Exchange between Alice and Bob was successful.");
    } else {
        println!("Key Exchange between Alice and Bob invalid.");
    }


    charly.get_shared_key(&donald.public_number);
    donald.get_shared_key(&charly.public_number);
    // println!("Charly's Shared Key: {:?}", charly.shared_key.as_ref().unwrap().to_affine());
    // println!("Donald's Shared Key: {:?}", donald.shared_key.as_ref().unwrap().to_affine());
    if charly.shared_key == donald.shared_key {
        println!("Key Exchange between Charly and Donald was successful.");
    } else {
        println!("Key Exchange between Charly and Donald invalid.");
    }
}
