use pedersen::Parameters;
use ark_crypto_primitives::crh::injective_map::PedersenTwoToOneCRHCompressor;
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen,
};
use ark_ec::twisted_edwards::Projective;
use ark_ed_on_bls12_381::{EdwardsProjective, JubjubConfig};

use ark_crypto_primitives::crh::{
    CRHScheme, TwoToOneCRHScheme,
};
use ark_crypto_primitives::merkle_tree::{ByteDigestConverter, Config, MerkleTree, Path};
use ark_std::rand::Rng;
use ark_ff::{BigInteger, Fp, MontBackend, MontConfig, PrimeField};
type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;


pub type TwoToOneHash = 
    PedersenTwoToOneCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 128;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

// use ark_r1cs_std::uint8::UInt8;

// mod constraints_test;

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes: one to hash leaves, and one to hash pairs
    // of internal nodes.
    type Leaf = [u8];
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
    type LeafDigest = <LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <TwoToOneHash as TwoToOneCRHScheme>::Output;
}

// type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

/// A Merkle tree containing account information.
/// 
#[derive(Clone)]
pub struct PedersenTreeConfig {
    pub leaf_crh_params: Parameters<Projective<JubjubConfig>>,
    pub two_to_one_crh_params: Parameters<Projective<JubjubConfig>>
}


impl PedersenTreeConfig {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(rng).unwrap();
        PedersenTreeConfig {
            leaf_crh_params: leaf_crh_params,
            two_to_one_crh_params: two_to_one_crh_params,
        }
    }
    pub fn verify_path<T: MontConfig<N>, const N: usize>(&self, path: MerklePath, root: Root, leaf: F<T, N>) -> Result<bool, ark_crypto_primitives::Error> {
        let leaf_bytes = leaf.into_bigint().to_bytes_be();
        path.verify(&self.leaf_crh_params, &self.two_to_one_crh_params, &root, leaf_bytes)
    }
}


/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRHScheme>::Output;
/// A membership proof for a given account.
pub type MerklePath = Path<MerkleConfig>;
pub type PedersenMerkleTree = MerkleTree<MerkleConfig>;


pub fn new_pedersen_merkletree<T: MontConfig<N>, const N: usize>(pedersen_config: &PedersenTreeConfig, leaves: Vec<F<T, N>>) -> PedersenMerkleTree {
    let mut leaves_bytes: Vec<Vec<u8>> = vec![];
    leaves
        .iter()
        .map(|l| l.into_bigint().to_bytes_be()).for_each(|l| leaves_bytes.push(l));
    
    MerkleTree::new(
        &pedersen_config.leaf_crh_params,
        &pedersen_config.two_to_one_crh_params,
        leaves_bytes, // the i-th entry is the i-th leaf.
    )
    .unwrap()
}
