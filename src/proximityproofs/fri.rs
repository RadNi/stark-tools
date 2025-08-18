use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup};
use ark_ff::MontConfig;
use spongefish::{codecs::arkworks_algebra::{FieldDomainSeparator, FieldToUnitDeserialize, GroupDomainSeparator, GroupToUnitDeserialize, GroupToUnitSerialize, UnitToField}, ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DomainSeparator, DuplexSpongeInterface, ProverState, UnitToBytes, VerifierState};
use stark_tools::{commitable::{Commitable, Commited}, merkletree::{PedersenTreeConfig, Root}, polynomial::{Foldable2, Polynomial, PolynomialCoefficient, PolynomialPoints}};
use crate::proximityproofs::{narg_proximityproof::{ProximityProofDomainSeparator, ProximityProofProver, ProximityProofVerifier}, utils::prove_leaf_index};
use ark_starkcurve::{FqConfig as Config};
use ark_ed_on_bls12_381::Fq as Fq;
use std::marker::PhantomData;
use crate::proximityproofs::utils::bytes_to_bigints;

// #[derive(Clone)]
pub struct FRIProtocol<G, H, const D: usize> where 
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField> {
    pub queries: [u32; D],
    pub pedersen_config: PedersenTreeConfig,
    marker_type1: PhantomData<H>,
    marker_type2: PhantomData<G>
}

impl<G, H, const D: usize> FRIProtocol<G, H, D> where 
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField> {
    
    pub fn new(queries: [u32; D], pedersen_config: PedersenTreeConfig) -> Self {
        Self {
            queries,
            pedersen_config,
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
            ds = ds.add_bytes(32, "fold commitment")
        }
        ds
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
        let commitment = polynomial.ptree.root();
        println!("real commitment: {commitment}");

        let mut polynomial = Commited::new(polynomial.ptree.clone(), polynomial.data.clone().fft(1));
        // polynomial.data = polynomial.data.fft(1);
        let fold_num = (polynomial.data.degree as f32).log2().ceil() as i32;
        println!("number of folds: {fold_num}, D: {D}");

        // assert!(fold_num == D as i32);
        for i in 0..D {
            let folding_bytes = prover_state.challenge_bytes::<32>().unwrap();
            let folding = bytes_to_bigints(folding_bytes);
            // println!("before {:?} after {:?}", folding_bytes, folding);
            polynomial = polynomial.data.fold_bigint(folding).commit(&self.pedersen_config);
            let commitment = polynomial.ptree.root().to_sponge_bytes_as_vec();
            println!("commitment {} {:?}", i, &commitment);
            // polynomial.data.degree
            prover_state.add_bytes(&commitment).unwrap();
        }
        Ok(prover_state.narg_string())
    }
}

impl<'b, H, G, Commitment, const D: usize> ProximityProofVerifier<'b, H, G, Commitment> for FRIProtocol<G, H, D> where 
    H: DuplexSpongeInterface,
    G: CurveGroup,
    Commitment: Absorb + std::fmt::Display,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField>,
    Self: ProximityProofDomainSeparator<G, H>,
    for<'a> VerifierState<'a, H>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField> {

    fn verify(
        &self,
        verifier_state: &mut spongefish::VerifierState<H>,
        // the commitment to the polynomial
        commitment: &'b Commitment,
    ) -> spongefish::ProofResult<()> {
        println!("Verifieerrrrr:");
        for i in 0..D {
            let x = verifier_state.challenge_bytes::<32>().unwrap();
            let y = verifier_state.next_bytes::<32>().unwrap();
            println!("Challenge: {:?}\nCommitment: {:?}", x, y);
        }
        Ok(())
    }
}




#[allow(non_snake_case)]
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
    
    let fri = FRIProtocol::<G, H, 2>::new(
        [1, 2],
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
        PolynomialCoefficient::<Config, 4>::random_poly(&mut rnd, 7).fft(1)
        .commit(pedersen_config);

    println!("commitment: {}", commited_poly.ptree.root());
    let x: Vec<Fq> = commited_poly.ptree.root().to_sponge_field_elements_as_vec();
    let mut y = commited_poly.ptree.root().to_sponge_bytes_as_vec();
    y.reverse();
    dbg!(x);
    dbg!(y);
    // let mut commitment_bytes: Vec<u8> = 
    let proof = prove_leaf_index(&commited_poly, 4);
    let (value, path) = proof.unwrap();
    // println!("{:?}", proof);
    println!("verification: {:?}", pedersen_config.verify_path(path, commited_poly.ptree.root(), value));


    // println!("leaf verification: {:?}", pedersen_config.verify_path(path, commited_poly.ptree.root(), leaf_value.unwrap()));
    // println!("len: {}", commitment_bytes.len());
    prover_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    prover_state.ratchet().unwrap();

    let proof = fri.prove(
        &mut prover_state, 
        &commited_poly,
        // &commited_poly.ptree.root()
    ).expect("Invalid proof");
    // let proof = prove(&mut prover_state, P, x).expect("Invalid proof");

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut verifier_state = io.to_verifier_state(proof);
    verifier_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    verifier_state.ratchet().unwrap();

    fri.verify(&mut verifier_state, &commited_poly.ptree.root()).expect("Invalid proof");
}