use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::{
        traits::IsEllipticCurve,
        short_weierstrass::curves::bls12_381::curve::{BLS12381Curve, SUBGROUP_ORDER}
};
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use random::random_unsigned_integer_in_range;

const SUBGROUP_ORDER_LIMBS: usize = 4;

fn main() {
    let zero = UnsignedInteger::<SUBGROUP_ORDER_LIMBS>::from_u64(0);

    let generator = BLS12381Curve::generator();
    // println!("{:?}", generator);

    // generate alice's secret number
    let alice_secret_number = random_unsigned_integer_in_range::<SUBGROUP_ORDER_LIMBS>(zero, SUBGROUP_ORDER);
    assert!(alice_secret_number < SUBGROUP_ORDER);
    println!("Alice's Secret Number: {:?}", alice_secret_number);
    let alice_public_number = generator.operate_with_self(alice_secret_number);

    // generate bob's secret number
    let bob_secret_number = random_unsigned_integer_in_range::<SUBGROUP_ORDER_LIMBS>(zero, SUBGROUP_ORDER);
    assert!(bob_secret_number < SUBGROUP_ORDER);
    println!("Bob's Secret Number: {:?}", bob_secret_number);
    let bob_public_number = generator.operate_with_self(bob_secret_number);

    println!(
        "
        ---------------------------->
        Sending over insecure channel:

        Alice's public number: {:?}

        Bob's public number: {:?}
        ---------------------------->
        ",
        alice_public_number,
        bob_public_number
    );

    let alice_shared_key = bob_public_number.operate_with_self(alice_secret_number);
    println!("Alice's Shared Key: {:?}", alice_shared_key.to_affine());
    let bob_shared_key = alice_public_number.operate_with_self(bob_secret_number);
    println!("Bob's Shared Key: {:?}", bob_shared_key.to_affine());
    assert_eq!(alice_shared_key, bob_shared_key);
}
