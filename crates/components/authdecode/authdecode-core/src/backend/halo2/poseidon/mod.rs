pub(crate) mod circuit_config;
mod rate15_params;
mod rate1_params;
mod rate2_params;
pub(crate) mod spec;

use halo2_poseidon::poseidon::primitives::{ConstantLength, Hash};
use halo2_proofs::halo2curves::bn256::Fr as F;

use spec::{Spec1, Spec15, Spec2};

use super::Bn256F;

/// Hashes inputs with rate-15 Poseidon and returns the digest.
pub fn poseidon_15(field_elements: &[Bn256F; 15]) -> Bn256F {
    let msg = field_elements.iter().map(|f| f.inner).collect::<Vec<_>>();
    let out = Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(msg.try_into().unwrap());
    Bn256F::new(out)
}

/// Hashes inputs with rate-2 Poseidon and returns the digest.
pub fn poseidon_2(field_elements: &[Bn256F; 2]) -> Bn256F {
    let msg = field_elements.iter().map(|f| f.inner).collect::<Vec<_>>();
    let out = Hash::<F, Spec2, ConstantLength<2>, 3, 2>::init().hash(msg.try_into().unwrap());
    Bn256F::new(out)
}

/// Hashes inputs with rate-1 Poseidon and returns the digest.
pub fn poseidon_1(field_elements: &[Bn256F; 1]) -> Bn256F {
    let msg = field_elements.iter().map(|f| f.inner).collect::<Vec<_>>();
    let out = Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash(msg.try_into().unwrap());
    Bn256F::new(out)
}
