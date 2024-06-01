use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_crypto::commitments::{
    kzg::{KateZaveruchaGoldberg, StructuredReferenceString},
    traits::IsCommitmentScheme,
};
use lambdaworks_math::{
    elliptic_curve::{
        short_weierstrass::{
            curves::bls12_381::{
                curve::BLS12381Curve,
                default_types::{FrConfig, FrElement},
                field_extension::BLS12381PrimeField,
                pairing::BLS12381AtePairing,
                twist::BLS12381TwistCurve,
            },
            point::ShortWeierstrassProjectivePoint,
        },
    },
    field::{
        element::FieldElement, fields::montgomery_backed_prime_fields::MontgomeryBackendPrimeField,
    },
    polynomial::Polynomial,
    unsigned_integer::element::UnsignedInteger,
};
use number_theory::power_mod;

type G1Point = ShortWeierstrassProjectivePoint<BLS12381Curve>;
type G2Point = ShortWeierstrassProjectivePoint<BLS12381TwistCurve>;

type KZG = KateZaveruchaGoldberg<MontgomeryBackendPrimeField<FrConfig, 4>, BLS12381AtePairing>;
pub type Fq = FieldElement<BLS12381PrimeField>;

fn challenge_polynomial() -> Polynomial<FrElement> {
    Polynomial::<FrElement>::new(&[
        FieldElement::from(69),
        FieldElement::from(78),
        FieldElement::from(32),
        FieldElement::from(65),
        FieldElement::from(82),
        FieldElement::from(71),
        FieldElement::from(69),
        FieldElement::from(78),
        FieldElement::from(84),
        FieldElement::from(73),
        FieldElement::from(78),
        FieldElement::from(65),
        FieldElement::from(32),
        FieldElement::from(78),
        FieldElement::from(65),
        FieldElement::from(67),
        FieldElement::from(73),
        FieldElement::from(32),
        FieldElement::from(84),
        FieldElement::from(73),
        FieldElement::from(69),
        FieldElement::from(82),
        FieldElement::from(65),
    ])
}

fn main() {
    let base_dir = env!("CARGO_MANIFEST_DIR");
    let srs_path = base_dir.to_owned() + "/srs.bin";
    let srs = StructuredReferenceString::<G1Point, G2Point>::from_file(&srs_path).unwrap();

    let kzg = KZG::new(srs.clone());

    let p = challenge_polynomial();

    let p_commitment: G1Point = kzg.commit(&p);

    // If you need to write a bigger number, you can use
    // If you are writing the solution in rust you shouldn't need this
    // let big_number = UnsignedInteger::<6>::from_limbs([0, 0, 0, 0, 0, 2]);
    // let y = Fq::new(big_number);

    // TO DO: Make your own fake proof
    let g1 = &srs.powers_main_group[0];
    let alpha_g1 = &srs.powers_main_group[1];

    let g2 = &srs.powers_secondary_group[0];
    let alpha_g2 = &srs.powers_secondary_group[1];

    // try obtaining the secret number alpha via brute force.to_hex
    println!("Trying by brute force up to 1000 tries...");
    let mut alpha = 1_u64;
    while alpha < 1000 {
        let point1 = &g1.operate_with_self(alpha);
        if point1 == alpha_g1 {
            break
        }
        let point2 = &g2.operate_with_self(alpha);
        if point2 == alpha_g2 {
            break
        }
        alpha += 1;
    }
    println!("Brute force is not the way...");

    // check if a power of the secret number alpha times g1 equals g1.

    let mut k = 1_usize;
    loop {
        let alpha_k_g1 = &srs.powers_main_group[k];
        if g1 == alpha_k_g1 {
            break
        }
        k += 1;
    }
    //     alpha^64 * g1 = g1 =>  alpha^64 = 1 (mod r)
    //  this means that alpha is a 64-th root of one modulo r
    println!(
        "Eureka: alpha to the {:?}-th power is a root of unity modulo BLS12381Curve's r", k
    );    // k equals 64

    // find a 64-th primitive root of one modulo r
    println!("Finding a 64-th primitive root of unity modulo r...");
    let r = UnsignedInteger::<8>::from_hex_unchecked("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let one = UnsignedInteger::<8>::from(1_u64);
    let sixtyfour = UnsignedInteger::<8>::from(64_u64);
    let (cofactor, _) = (r - one).div_rem(&sixtyfour);
    let random_number =  UnsignedInteger::<8>::from(5_u64);    // check with sage that it is appropriate
    let primitive_root = power_mod(random_number, cofactor, &r);    // check with sage that it has order 64
    println!("Primitive root found! : {:?}", primitive_root.to_hex());

    println!("Trying to find alpha as one of the 64 roots of unity...");
    // let mut point: ShortWeierstrassProjectivePoint::<BLS12381Curve>;
    // let mut candidate = UnsignedInteger::<8>::from(0_u64);
    let mut k = 1;
    let alpha = loop {
        let pow = UnsignedInteger::<8>::from(k as u64);
        let candidate = power_mod(primitive_root, pow, &r);
        let point = &g1.operate_with_self(candidate);
        if point == alpha_g1 {
            break candidate
        }
        k += 1;
        if k > 64 {
            panic!("Secret number not found.");
        }
    };
    println!("Alpha found! The secret number is {:?}", alpha);
    // candidate = 0xe4840ac57f86f5e293b1d67bc8de5d9a12a70a615d0b8e4d2fc5e69ac5db47f
    // Now we can fake proofs

    // Create fake evaluation point
    println!("Creating fake evaluation proof...");
    let alpha = UnsignedInteger::<4>::from_hex_unchecked(&alpha.to_hex());  // ugly way of reducing from 8 to 4 limbs
    let fake_p_eval_at_alpha = p.evaluate(&FrElement::from(&alpha));
    let num = fake_p_eval_at_alpha - FrElement::from(3);
    let den = FrElement::from(&alpha) - FrElement::from(1);
    let fake_q_eval_at_alpha = num * den.inv().unwrap();
    println!("{:?}", fake_q_eval_at_alpha);

    // interpolate fake polynomial
    let q = Polynomial::<FrElement>::new(&[fake_q_eval_at_alpha]);

    // create fake proof
    let fake_proof: G1Point = kzg.commit(&q);

    println!("Fake proof for submission:");
    println!("{:?}", &fake_proof.to_affine().x().to_string());
    println!("{:?}", &fake_proof.to_affine().y().to_string());

    assert!(kzg.verify(
        &FrElement::from(1),
        &FrElement::from(3),
        &p_commitment,
        &fake_proof
    ));
}
