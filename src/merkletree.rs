use ark_crypto_primitives::crh::injective_map::PedersenTwoToOneCRHCompressor;
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen,
};
use ark_ed_on_bls12_381::{EdwardsProjective};

use ark_crypto_primitives::crh::{
    CRHScheme, TwoToOneCRHScheme,
};
use ark_crypto_primitives::merkle_tree::{ByteDigestConverter, Config, MerkleTree, Path};
use ark_std::rand::Rng;



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
pub type PedersenMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRHScheme>::Output;
/// A membership proof for a given account.
pub type MerklePath = Path<MerkleConfig>;
use ark_ff::{AdditiveGroup, BigInt, BigInteger, FftField, Field as Field, Fp, MontBackend, MontConfig, PrimeField, UniformRand};
type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;


pub fn new_pedersen_merkle_tree<R: Rng, T: MontConfig<N>, const N: usize>(rng: &mut R, leaves: Vec<F<T, N>>) -> PedersenMerkleTree {
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(rng).unwrap();

    let mut leaves_bytes: Vec<Vec<u8>> = vec![];
    leaves
        .iter()
        .map(|l| l.into_bigint().to_bytes_le()).for_each(|l| leaves_bytes.push(l));

    PedersenMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            leaves_bytes, // the i-th entry is the i-th leaf.
        )
        .unwrap()
}
