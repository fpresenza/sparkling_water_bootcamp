use lambdaworks_math::{
    elliptic_curve::{
        traits::IsEllipticCurve,
        short_weierstrass::curves::bls12_381::curve::BLS12381Curve
    },
    cyclic_group::IsGroup
};

fn main() {
    // parse secret key into an unsigned integer
    let seckey = u64::from_str_radix("6C616D6264617370", 16).unwrap();

    // group generator
    let g = BLS12381Curve::generator();

    // compose 'g' with itself 'seckey' times
    let pubkey = g.operate_with_self(seckey);

    // get affine (uncompressed) coordinates as a hexstring
    println!("public key x-affine coordinate: {:?}", pubkey.to_affine().x().value().to_hex());
    println!("public key y-affine coordinate: {:?}", pubkey.to_affine().y().value().to_hex());
}
