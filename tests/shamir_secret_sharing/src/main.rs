use rand::prelude::*;
use lambdaworks_math::{
    field::fields::u64_prime_field::U64FieldElement,
    polynomial::Polynomial
};

const MODULUS: u64 = 173;
const N_SHARES: u64 = 5;
const N_SUFFICIENT: usize = 3;
type FE = U64FieldElement<MODULUS>;

fn main() {

    let mut rng = rand::thread_rng();
    
    // Define secret
    let secret = FE::new(150);
    println!("Secret is: {}", secret.value());
    
    // Create coefficient vector. First coeff is the secret.
    let mut coeffs = vec![secret];

    // Append the random coefficients in the range 1..N_SUFFICIENT-1
    coeffs.append(
        &mut
        (1..=N_SUFFICIENT-1)
        .map(|_| FE::new(rng.gen_range(0..MODULUS)))
        .collect()
    );

    // Construct polynomial
    let poly = Polynomial::new(&coeffs);

    let shares: Vec<FE> = (1..=N_SHARES)
        .map(|i| poly.evaluate(&FE::new(i)))
        .collect();
    println!("The shares to distribute are:");
    for i in 1..=N_SHARES {
        println!("({}, {})", i, shares[(i as usize) - 1].value());
    }

    let mut parties = [0_u64; N_SUFFICIENT];
    // let parties: [u64; 3] = [1, 4, 3];
    let mut i = 0;
    while i < N_SUFFICIENT {
        let rand_party = rand::thread_rng().gen_range(1..=N_SHARES);
        if !parties.contains(&rand_party) {
            parties[i] = rand_party;
            i += 1;
        }
    }
    println!("If parties {:?} gather togheter, they can reveal the secret.", parties);

    let inter = Polynomial::interpolate(
        &parties.map(FE::new),
        &parties.map(|i| shares[(i as usize) - 1])
    ).unwrap();

    let revealed_secret = inter.coefficients[0].value();

    println!("Revealed secret is: {:?}", revealed_secret);
}
