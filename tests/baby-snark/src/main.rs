use baby_snark::{
    utils::{i64_vec_to_field, i64_matrix_to_field},
    setup,
    ssp::SquareSpanProgram,
    scs::SquareConstraintSystem,
    Prover,
    verify
};

fn main() {
    // Cirtcuit: two fan-in 2 xor gates in cascade <-> one fan-in 3 xor gate
    // Define Constraint Matrix 
    let u = i64_matrix_to_field(&[
        &[-1, 2, 0, 0, 0, 0],
        &[-1, 0, 2, 0, 0, 0],
        &[-1, 0, 0, 2, 0, 0],
        &[-1, 0, 0, 0, 2, 0],
        &[-1, 0, 0, 0, 0, 2],
        &[-1, 1, 1, 0, 1, 0],
        &[-1, 0, 0, 1, 1, 1]
    ]);
    let public = i64_vec_to_field(&[1, 1, 0, 1]);
    let witness = i64_vec_to_field(&[1, 0]);
    let mut input = public.clone();
    input.extend(witness.clone());

    // Construct Span Program (ssp):
    let ssp = SquareSpanProgram::from_scs(SquareConstraintSystem::from_matrix(u, public.len()));

    let (pk, vk) = setup(&ssp);

    let proof = match Prover::prove(&input, &ssp, &pk) {
        Ok(p) => p,
        Err(e) => panic!("{:?}", e)
    };

    let verified = verify(&vk, &proof, &public);
    assert!(verified);
}
