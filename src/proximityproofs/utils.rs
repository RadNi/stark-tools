use ark_crypto_primitives::merkle_tree::Path;
use ark_ff::{AdditiveGroup, BigInt, FftField, Field as Field, Fp, MontBackend, MontConfig, PrimeField, UniformRand};
use stark_tools::{commitable::Commited, merkletree::MerkleConfig, polynomial::PolynomialPoints};


type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

pub fn prove_leaf_index <T: MontConfig<N>, const N: usize> 
    (commited_poly: &Commited<PolynomialPoints<T, N>>, index: u64) -> Option<(F<T, N>, Path<MerkleConfig>)> {
    let roots = commited_poly.data.roots_preimage.as_ref();
    let queried_x = roots.and_then(|x| x.get_by_right(&index));
    let leaf_value = queried_x.and_then(|x| commited_poly.data.points.get(x).and_then(|y| Some(y.get_y())));
    let path = commited_poly.ptree.generate_proof(index as usize);
    leaf_value.zip(path.ok())
}