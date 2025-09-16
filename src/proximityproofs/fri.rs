use ark_crypto_primitives::{sponge::Absorb};
use ark_ec::{CurveGroup};
use ark_ff::{BigInt, BigInteger, PrimeField};
use spongefish::{codecs::arkworks_algebra::{FieldDomainSeparator, FieldToUnitDeserialize, GroupDomainSeparator, GroupToUnitDeserialize, GroupToUnitSerialize, UnitToField}, ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DomainSeparator, DuplexSpongeInterface, ProofError, ProofResult, ProverState, UnitToBytes, VerifierState};
use stark_tools::{commitable::{Commitable, Commited}, fields::{Field192, Goldilocks}, merkletree::{PedersenTreeConfig, Root}, polynomial::{Foldable2, Polynomial, PolynomialCoefficient, PolynomialPoints}};
use crate::proximityproofs::{narg_proximityproof::{ProximityProofDomainSeparator, ProximityProofProver, ProximityProofVerifier}, utils::{bytes_to_bls, bytes_to_path, path_to_bytes, prove_leaf_index}};
use std::{collections::HashMap, marker::PhantomData};
use crate::proximityproofs::utils::bytes_to_bigints;

type Field = Field192;

pub struct FRIProtocol<G, H, const D: usize, const S: usize, const SBIGINT: usize> where 
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField> {
    pub queries: [u32; D],
    pub rate: u64,
    pub pedersen_config: PedersenTreeConfig,
    marker_type1: PhantomData<H>,
    marker_type2: PhantomData<G>
}

impl<G, H, const D: usize, const S: usize, const SBIGINT: usize> FRIProtocol<G, H, D, S, SBIGINT> where 
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


impl<H, G: CurveGroup, const D: usize, const S: usize, const SBIGINT: usize> ProximityProofDomainSeparator<G, H> for FRIProtocol<G, H, D, S, SBIGINT> where
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
            ds = ds.challenge_bytes(S, "folding randomness");
            ds = ds.add_bytes(32, "fold commitment");
            let path_length = (D - i) + (self.rate as f64).log2().ceil() as usize;
            println!("path_length: {path_length}");
            for _ in 0..self.queries[i] as usize {
                ds = ds.challenge_bytes(2, "round query index");
                ds = ds.add_bytes(S, "leaf0 value");
                for _ in 0..path_length { // it must be 3*path_length - 1
                    ds = ds.add_bytes(32, "leaf0 proof");
                }
                ds = ds.add_bytes(S, "leaf1 value");
                for _ in 0..path_length { // it must be 3*path_length - 1
                    ds = ds.add_bytes(32, "leaf1 proof");
                }
                ds = ds.add_bytes(S, "fold leaf value");
                for _ in 0..path_length-1 { // it must be 3*path_length - 1
                    ds = ds.add_bytes(32, "fold leaf proof");
                }
            }
        }
        ds
    }
}

impl<'b, H, G, P, F, Raw, const D: usize, const S: usize, const SBIGINT: usize> 
ProximityProofProver<'b, H, G, P, F, Raw> for FRIProtocol<G, H, D, S, SBIGINT> where 
    F: PrimeField,
    G: CurveGroup,
    H: DuplexSpongeInterface,
    P: Polynomial<F, Raw>,
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
        let mut polynomial = Commited::new(polynomial.ptree.clone(), polynomial.data.clone().fft(4));
        // polynomial.data = polynomial.data.fft(1);
        let fold_num = (polynomial.data.degree as f32 + 1.).log2().ceil() as i32;
        println!("Number of folds: {fold_num}, D: {D}");
        // assert!(fold_num == D as i32);
        for i in 0..D {
            let folding_bytes = prover_state.challenge_bytes::<S>().unwrap();
            let folding_randomness: BigInt<SBIGINT> = bytes_to_bigints(folding_bytes.into());
            // println!("before {:?} after {:?}", folding_bytes, folding);
            let fold = polynomial.data.fold_bigint(self.rate, folding_randomness).commit(&self.pedersen_config);
            let commitment: Root = fold.ptree.root();
            prover_state.add_bytes(&(commitment.to_sponge_bytes_as_vec())).unwrap();
            
            println!("Making {} queries", self.queries[i]);
            for _ in 0..self.queries[i] {
                let query_bytes = prover_state.challenge_bytes::<2>().unwrap();
                let max_index = (1 << ((D - i) as u64)) * self.rate;

                let leaf0_index: u64 = (query_bytes[0] as u64 * 256 + query_bytes[1] as u64) % max_index;
                let leaf1_index = (leaf0_index + (polynomial.data.degree + 1) * self.rate / 2) % ((polynomial.data.degree + 1) * self.rate);
                let fold_leaf_index = ((leaf0_index * 2 ) % max_index) / 2;
                write_merkleproofs(&polynomial, leaf0_index, prover_state)?;
                write_merkleproofs(&polynomial, leaf1_index, prover_state)?;
                write_merkleproofs(&fold, fold_leaf_index, prover_state)?;
            }
            polynomial = fold;
        }
        Ok(prover_state.narg_string())
    }
}

fn write_merkleproofs<H: DuplexSpongeInterface, F: PrimeField>(
    polynomial: &Commited<PolynomialPoints<F>>,
    leaf_index: u64,
    prover_state: &mut spongefish::ProverState<H>,
) -> Result<(), ProofError> {

    let (leaf_val, path) = prove_leaf_index(polynomial, leaf_index).unwrap();
    let leaf_arr: Vec<u8> = leaf_val.into_bigint().to_bytes_be().try_into().map_err(|_| {
        ProofError::SerializationError
    })?;
    prover_state.add_bytes(&leaf_arr).unwrap();
    let proof = path_to_bytes(path.clone()).unwrap();
    proof.iter().for_each(|p|  {
        prover_state.add_bytes(p).unwrap()
    });
    Ok(())
}

impl<'b, H, G, const D: usize, const S: usize, const SBIGINT: usize> 
ProximityProofVerifier<'b, H, G, Root> for FRIProtocol<G, H, D, S, SBIGINT> where 
    // T: MontConfig<N>,
    H: DuplexSpongeInterface,
    G: CurveGroup,
    // Commitment: Absorb + std::fmt::Display,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField>,
    Self: ProximityProofDomainSeparator<G, H>,
    for<'a> VerifierState<'a, H>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField> {

    fn verify<F: PrimeField>(
        &self,
        verifier_state: &mut spongefish::VerifierState<H>,
        // the commitment to the polynomial
        commitment: &'b Root,
    ) -> spongefish::ProofResult<()> {

        let roots_length = (1 << (D as u64)) * self.rate;
        let mut roots = HashMap::<u64, F>::new();
        let omega = F::get_root_of_unity(roots_length).unwrap();
        let mut root = F::ONE;
        for i in 0..roots_length {
            roots.insert(i, root);
            root *= omega;
        }

        let mut fold_leaf_value = F::ZERO;
        let mut fold_commitment = [0; 32];

        let mut commitment: Root = commitment.clone();
        for i in 0..D {
            let max_index = (1 << ((D - i) as u64)) * self.rate;
            let fold_r_bytes = verifier_state.challenge_bytes::<S>()?;
            let fold_randomness = F::from_be_bytes_mod_order(&fold_r_bytes);
            fold_commitment = verifier_state.next_bytes::<32>()?;
            fold_commitment.reverse();

            for _ in 0..self.queries[i] {
                let query_bytes = verifier_state.challenge_bytes::<2>()?;
                let leaf0_index: u64 = (query_bytes[0] as u64 * 256 + query_bytes[1] as u64) % max_index;
                let leaf1_index = (leaf0_index + max_index / 2) % max_index;
                let fold_leaf_index = ((leaf0_index * 2 ) % max_index) / 2;

                let leaf0_value_bytes = verifier_state.next_bytes::<S>()?;
                let leaf0_value = F::from_be_bytes_mod_order(&leaf0_value_bytes);
                read_and_verify_merkle(
                    leaf0_value, 
                    D - i + (self.rate as f64).log2().ceil() as usize, 
                    leaf0_index as usize, 
                    commitment, 
                    &self.pedersen_config, 
                    verifier_state
                )?;


                let leaf1_value_bytes = verifier_state.next_bytes::<S>().map_err(|_| ProofError::SerializationError)?;
                let leaf1_value = F::from_be_bytes_mod_order(&leaf1_value_bytes);
                read_and_verify_merkle(
                    leaf1_value, 
                    D - i + (self.rate as f64).log2().ceil() as usize, 
                    leaf1_index as usize, 
                    commitment, 
                    &self.pedersen_config, 
                    verifier_state
                )?;


                let fold_leaf_value_bytes = verifier_state.next_bytes::<S>().map_err(|_| ProofError::SerializationError)?;
                fold_leaf_value= F::from_be_bytes_mod_order(&fold_leaf_value_bytes);
                read_and_verify_merkle(
                    fold_leaf_value, 
                    D - i - 1 + (self.rate as f64).log2().ceil() as usize, 
                    fold_leaf_index as usize, 
                    bytes_to_bls(fold_commitment), 
                    &self.pedersen_config, 
                    verifier_state
                )?;

                let leaf0_x_value = roots.get_key_value(&((leaf0_index * (1 << i)) % roots_length)).unwrap().1;
                if fold_leaf_value != ((leaf0_value * (*leaf0_x_value + fold_randomness) + leaf1_value * (*leaf0_x_value - fold_randomness)) / leaf0_x_value.double()) {
                    return Err(ProofError::InvalidProof);
                }
            }
            commitment = bytes_to_bls(fold_commitment);
        }
        let mut final_polynomial_commitment = PolynomialCoefficient::<F>::new(
            0, vec![fold_leaf_value])
            .fft(self.rate)
            .commit(&self.pedersen_config)
            .ptree
            .root()
            .to_sponge_bytes_as_vec();
        final_polynomial_commitment.reverse();
        if final_polynomial_commitment != fold_commitment {
            return Err(ProofError::InvalidProof);
        }
        Ok(())
    }
}



fn read_and_verify_merkle<H: DuplexSpongeInterface, F: PrimeField>(
    leaf_value: F,
    path_length: usize,
    leaf_index: usize,
    commitment: Root,
    pedersen_config: &PedersenTreeConfig, 
    verifier_state: &mut spongefish::VerifierState<H>
) -> Result<(), ProofError> {

    let mut proof: Vec<[u8; 32]> = vec![];
    for _ in 0..path_length {
        proof.push(verifier_state.next_bytes::<32>().map_err(|_| ProofError::SerializationError)?);
    }
    let path = bytes_to_path(proof.clone(), leaf_index as usize).map_err(|_| ProofError::InvalidProof).unwrap();
    let verification_result = pedersen_config.verify_path(path.clone(), commitment, leaf_value).map_err(|x| ProofError::InvalidProof)?;
    if !verification_result {
        return Err(ProofError::InvalidProof);
    }
    return Ok(());
}



pub fn fri_test(pedersen_config: &PedersenTreeConfig) {
    // Instantiate the group and the random oracle:
    // Set the group:
    type G = ark_ed_on_bls12_381::EdwardsProjective;
    // type G = Projective;
    // Set the hash function (commented out other valid choices):
    // type H = spongefish::hash::Keccak;
    type H = spongefish::duplex_sponge::legacy::DigestBridge<sha3::Keccak224>;
    // type H = spongefish::hash::legacy::DigestBridge<sha2::Sha256>;

    /*
        Couldn't find any better way to encode the following :(
    */
    const RATE: u64 = 8;
    const POLYNOMIAL_DEGREE: u64 = 7;
    const POLYNOMIAL_DEGREE_LOG: usize = 3;
    const QUERIES: [u32; POLYNOMIAL_DEGREE_LOG] = [3; POLYNOMIAL_DEGREE_LOG];
    const S: usize = (Field::MODULUS_BIT_SIZE/8) as usize;
    const SBIGINT: usize = S/8;


    let fri = FRIProtocol::<G, H, POLYNOMIAL_DEGREE_LOG, S, SBIGINT>::new(
        QUERIES,
        RATE,
        pedersen_config.clone()
    );
    let io: DomainSeparator<H> = fri.new_pp_proof();

    let mut rnd = ark_std::test_rng();

    let mut prover_state = io.to_prover_state();
    let commited_poly = 
        PolynomialCoefficient::<Field>::random_poly(&mut rnd, POLYNOMIAL_DEGREE).fft(RATE)
        .commit(pedersen_config);


    prover_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    prover_state.ratchet().unwrap();

    let proof = fri.prove(
        &mut prover_state, 
        &commited_poly,
    ).expect("FRI proof generation faild!");

    // Print out the hex-encoded FRI proof.
    println!("FRI Proof:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut verifier_state = io.to_verifier_state(proof);
    verifier_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    verifier_state.ratchet().unwrap();

    fri.verify::<Field>(&mut verifier_state, &commited_poly.ptree.root()).and_then(|_| {println!("FRI proof successfully verified!"); Ok(())}).expect("Invalid proof");
}