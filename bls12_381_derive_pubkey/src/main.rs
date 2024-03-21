use lambdaworks_math::{
    elliptic_curve::{
        traits::IsEllipticCurve,
        short_weierstrass::curves::bls12_381::curve::BLS12381Curve
    },
    cyclic_group::IsGroup};

fn main() {
    // parse secret key into an integer
    let seckey = u64::from_str_radix("6C616D6264617370", 16).unwrap();

    let g = BLS12381Curve::generator();
    let pubkey = g.operate_with_self(seckey);
    println!("{:?}", pubkey);
}
