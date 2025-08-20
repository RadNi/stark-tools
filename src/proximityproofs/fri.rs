use ark_crypto_primitives::{sponge::Absorb};
use ark_ec::{CurveGroup};
use ark_ff::{BigInt, BigInteger, Fp, MontConfig, PrimeField, MontBackend};
use spongefish::{codecs::arkworks_algebra::{FieldDomainSeparator, FieldToUnitDeserialize, GroupDomainSeparator, GroupToUnitDeserialize, GroupToUnitSerialize, UnitToField}, ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DomainSeparator, DuplexSpongeInterface, ProofError, ProofResult, ProverState, UnitToBytes, VerifierState};
use stark_tools::{commitable::{Commitable, Commited}, merkletree::{PedersenTreeConfig, Root}, polynomial::{Foldable2, Polynomial, PolynomialCoefficient}};
use crate::proximityproofs::{narg_proximityproof::{ProximityProofDomainSeparator, ProximityProofProver, ProximityProofVerifier}, utils::{bytes_to_bls, bytes_to_path, path_to_bytes, prove_leaf_index}};
use ark_starkcurve::{FqConfig as Config};
use std::{marker::PhantomData};
use crate::proximityproofs::utils::bytes_to_bigints;
type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

// #[derive(Clone)]
pub struct FRIProtocol<G, H, const D: usize> where 
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField> {
    // polynomial degree = 2^D
    pub queries: [u32; D],
    pub rate: u64,
    pub pedersen_config: PedersenTreeConfig,
    marker_type1: PhantomData<H>,
    marker_type2: PhantomData<G>
}

impl<G, H, const D: usize> FRIProtocol<G, H, D> where 
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField> {
    
    pub fn new(queries: [u32; D], rate: u64, pedersen_config: PedersenTreeConfig) -> Self {
        Self {
            queries,
            pedersen_config,
            rate,
            marker_type1: PhantomData,
            marker_type2: PhantomData
        }
    }
}


impl<H, G: CurveGroup, const D: usize> ProximityProofDomainSeparator<G, H> for FRIProtocol<G, H, D> where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField>
{
    fn new_pp_proof(&self) -> DomainSeparator<H> {
        let ds = DomainSeparator::new("FRI proximity proof");
        let ds = self.add_pp_statement(ds);
        self.add_pp_domsep(ds)
    }

    fn add_pp_statement(&self, ds: DomainSeparator<H>) -> DomainSeparator<H> {
        ds.add_bytes(32, "public commitment (C)")
            // .add_points(1, "public key (X)")
            .ratchet()
    }

    fn add_pp_domsep(&self, ds: DomainSeparator<H>) -> DomainSeparator<H> {
        // self.add_bytes(32, "fake commitment (K)")
        let mut ds = ds;
        for i in 0..D {
            ds = ds.challenge_bytes(32, "folding randomness");
            ds = ds.add_bytes(32, "fold commitment");
            let path_length = (D - i) + (self.rate as f64).log2().ceil() as usize;
            println!("path_length: {path_length}");
            for j in 0..self.queries[i] as usize {
                ds = ds.challenge_bytes(2, "round query index");
                ds = ds.add_bytes(32, "query value");
                for _ in 0..path_length { // it must be 3*path_length - 1
                    ds = ds.add_bytes(32, "query proof");
                }
            }
        }
        ds
        // path: [
        // [61, 76, 213, 126, 240, 130, 0, 149, 92, 20, 12, 31, 156, 23, 222, 81, 171, 66, 115, 79, 234, 73, 15, 174, 183, 118, 255, 150, 111, 79, 49, 100], 
        // [11, 126, 127, 167, 194, 22, 20, 167, 143, 20, 232, 136, 148, 99, 16, 91, 152, 185, 81, 150, 32, 26, 220, 206, 176, 66, 149, 245, 139, 21, 172, 120], 
        // [2, 78, 226, 92, 123, 55, 139, 51, 200, 84, 10, 44, 183, 84, 38, 139, 238, 162, 22, 218, 124, 65, 77, 144, 216, 11, 24, 101, 173, 27, 186, 154], 
        // [62, 91, 66, 109, 185, 37, 42, 77, 92, 207, 41, 146, 90, 24, 183, 155, 102, 235, 167, 207, 19, 148, 115, 1, 220, 46, 198, 146, 90, 52, 252, 197]]
            // .challenge_scalars(2, "challenge (c)")
            // .challenge_scalars(1, "challenge (c1)")
            // .add_scalars(1, "response (r)")
    }
}

impl<'b, H, G, P, const N: usize, T, T1, const D: usize> ProximityProofProver<'b, H, G, P, N, T, T1> for FRIProtocol<G, H, D> where 
    T: MontConfig<N>,
    G: CurveGroup,
    H: DuplexSpongeInterface,
    P: Polynomial<N, T, T1>,
    // Commitment: Absorb + std::fmt::Display,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField>,
    Self: ProximityProofDomainSeparator<G, H> {
    fn prove(
        &self,
        // the hash function `H` works over bytes.
        // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `spongefish::Unit`.
        prover_state: &'b mut spongefish::ProverState<H>,
        // the secret polynomial
        polynomial: &Commited<P>,
        // commitment: &Commitment,
    ) -> spongefish::ProofResult<&'b [u8]> {
        let commitment: Root = polynomial.ptree.root();
        println!("real commitment: {commitment}");

        let mut polynomial = Commited::new(polynomial.ptree.clone(), polynomial.data.clone().fft(4));
        // polynomial.data = polynomial.data.fft(1);
        let fold_num = (polynomial.data.degree as f32 + 1.).log2().ceil() as i32;
        println!("number of folds: {fold_num}, D: {D}");

        // assert!(fold_num == D as i32);
        for i in 0..D {
            let folding_bytes = prover_state.challenge_bytes::<32>().unwrap();
            let folding: BigInt<N> = bytes_to_bigints(folding_bytes);
            // println!("before {:?} after {:?}", folding_bytes, folding);
            let fold = polynomial.data.fold_bigint(4, folding).commit(&self.pedersen_config);
            let commitment: Root = fold.ptree.root();
            // println!("commitment {} {:?}", i, &commitment);
            prover_state.add_bytes(&(commitment.to_sponge_bytes_as_vec())).unwrap();


            let query_bytes = prover_state.challenge_bytes::<2>().unwrap();
            let max_index = (1 << ((D - i) as u64)) * self.rate;
            let query_index: u64 = (query_bytes[0] as u64 * 256 + query_bytes[1] as u64) % max_index;
            let (leaf_value, path): (Fp<MontBackend<T, N>, N>, ark_crypto_primitives::merkle_tree::Path<stark_tools::merkletree::MerkleConfig>) = prove_leaf_index(&polynomial, query_index).unwrap();
            self.pedersen_config.verify_path(path.clone(), polynomial.ptree.root(), leaf_value).map_err(|_| ProofError::SerializationError)?;
            let leaf_arr: [u8; 32] = leaf_value.into_bigint().to_bytes_be().try_into().map_err(|v: Vec<u8>| {
                ProofError::SerializationError
            })?;

            prover_state.add_bytes(&leaf_arr).unwrap();

            let mut proof = path_to_bytes(path.clone()).unwrap();
            
            println!("query index: {query_index}");


            // println!("path: {:?}\nprocessed: {:?}, len: {}", path, proof, proof.len());

            proof.iter().for_each(|p|  {
                prover_state.add_bytes(p).unwrap()
            });
            polynomial = fold;
        }
        Ok(prover_state.narg_string())
    }
}

impl<'b, H, G, const D: usize> ProximityProofVerifier<'b, H, G, Root> for FRIProtocol<G, H, D> where 
    // T: MontConfig<N>,
    H: DuplexSpongeInterface,
    G: CurveGroup,
    // Commitment: Absorb + std::fmt::Display,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField>,
    Self: ProximityProofDomainSeparator<G, H>,
    for<'a> VerifierState<'a, H>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField> {

    fn verify(
        &self,
        verifier_state: &mut spongefish::VerifierState<H>,
        // the commitment to the polynomial
        commitment: &'b Root,
    ) -> spongefish::ProofResult<()> {
        let mut commitment: Root = commitment.clone();
        for i in 0..D {
            let fold_r = verifier_state.challenge_bytes::<32>().map_err(|_| ProofError::SerializationError)?;
            let mut fold_commitment = verifier_state.next_bytes::<32>().map_err(|_| ProofError::SerializationError)?;
            fold_commitment.reverse();
            let query_bytes = verifier_state.challenge_bytes::<2>().map_err(|_| ProofError::SerializationError)?;
            let value_bytes = verifier_state.next_bytes::<32>().map_err(|_| ProofError::SerializationError)?;
            let max_index = (1 << ((D - i) as u64)) * self.rate;
            let query_index: u64 = (query_bytes[0] as u64 * 256 + query_bytes[1] as u64) % max_index;

            let mut proof: Vec<[u8; 32]> = vec![];
            for _ in 0..D - i + (self.rate as f64).log2().ceil() as usize {
                proof.push(verifier_state.next_bytes::<32>().map_err(|_| ProofError::SerializationError)?);
            }
            let path = bytes_to_path(proof.clone(), query_index as usize).map_err(|_| ProofError::InvalidProof).unwrap();

            let leaf_value2: Fp<MontBackend<Config, 4>, 4> = F::new(bytes_to_bigints::<32, 4>(value_bytes));
            let verification_result = self.pedersen_config.verify_path(path.clone(), commitment, leaf_value2).map_err(|x| ProofError::InvalidProof)?;
            if !verification_result {
                return Err(ProofError::InvalidProof);
            }
            commitment = bytes_to_bls(fold_commitment);
        }
        Ok(())
    }
}




pub fn fri_test(pedersen_config: &PedersenTreeConfig) {
    // Instantiate the group and the random oracle:
    // Set the group:
    type G = ark_ed_on_bls12_381::EdwardsProjective;
    // println!("This new modulus {x}");
    // type G = Projective;
    // Set the hash function (commented out other valid choices):
    // type H = spongefish::hash::Keccak;
    type H = spongefish::duplex_sponge::legacy::DigestBridge<sha3::Keccak224>;
    // type H = spongefish::hash::legacy::DigestBridge<sha2::Sha256>;
    let rate = 4;
    let polynomial_degree = 7;
    let queries = [1; 3];
    
    let fri = FRIProtocol::<G, H, 3>::new(
        queries,
        rate,
        pedersen_config.clone()
    );
    // Set up the IO for the protocol transcript with domain separator "spongefish::examples::schnorr"
    let io: DomainSeparator<H> = fri.new_pp_proof();
    // Set up the elements to prove
    // let P = G::generator();

    let mut rnd = ark_std::test_rng();
    // let (x, X) = keygen(&mut rnd);

    // // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut prover_state = io.to_prover_state();
    // prover_state.public_points(&[P, P * x]).unwrap();
    let commited_poly = 
        PolynomialCoefficient::<Config, 4>::random_poly(&mut rnd, polynomial_degree).fft(rate)
        .commit(pedersen_config);

    println!("commitment: {}", commited_poly.ptree.root());
    // println!("Main poly: {}", commited_poly.data);
    // let x: Vec<Fq> = commited_poly.ptree.root().to_sponge_field_elements_as_vec();
    // let mut y = commited_poly.ptree.root().to_sponge_bytes_as_vec();
    // y.reverse();
    // dbg!(x);
    // dbg!(y);
    // let mut commitment_bytes: Vec<u8> = 
    let proof = prove_leaf_index(&commited_poly, 4);
    let (value, path) = proof.unwrap();
    // println!("{:?}", proof);
    println!("verification: {:?}", pedersen_config.verify_path(path, commited_poly.ptree.root(), value));


    prover_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    prover_state.ratchet().unwrap();

    let proof = fri.prove(
        &mut prover_state, 
        &commited_poly,
    ).expect("FRI proof generation faild!");

    // Print out the hex-encoded schnorr proof.
    println!("FRI Proof:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut verifier_state = io.to_verifier_state(proof);
    verifier_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    verifier_state.ratchet().unwrap();

    fri.verify(&mut verifier_state, &commited_poly.ptree.root()).and_then(|_| {println!("FRI proof successfully verified!"); Ok(())}).expect("Invalid proof");
}