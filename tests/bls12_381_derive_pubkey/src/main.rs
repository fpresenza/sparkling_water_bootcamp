use lambdaworks_math::{
    elliptic_curve::{
        traits::IsEllipticCurve,
        short_weierstrass::curves::bls12_381::curve::BLS12381Curve
    },
    cyclic_group::IsGroup
};

fn main() {
    // secret key
    let seckey: u64 = 0x6C616D6264617370;

    // group generator
    let g = BLS12381Curve::generator();

    // compose 'g' with itself 'seckey' times
    let pubkey_affine = g.operate_with_self(seckey).to_affine();

    // get affine (uncompressed) coordinates as a hexstring
    println!("public key x-affine coordinate: {:?}", pubkey_affine.x().value().to_hex());
    // prints: public key x-affine coordinate: "773B526CAB2D1FEC900E6AD51E75BBE8EF6395D02F2FBFC84A1B09118FA4121A6EA675532E89A7B43AF5B9FFF9FE7F8"
    println!("public key y-affine coordinate: {:?}", pubkey_affine.y().value().to_hex());
    // prints: public key y-affine coordinate: "117B6D42F9AB470E2719A696C954502FA963DFC9F0085ED1B419AFD0F205B039A66E824073D68B07F23707C3547FE979"
}
