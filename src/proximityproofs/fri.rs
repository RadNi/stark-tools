use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup};
use ark_ff::MontConfig;
use spongefish::{codecs::arkworks_algebra::{FieldDomainSeparator, FieldToUnitDeserialize, GroupDomainSeparator, GroupToUnitDeserialize, GroupToUnitSerialize, UnitToField}, ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, CommonUnitToBytes, DomainSeparator, DuplexSpongeInterface, ProverState, UnitToBytes, VerifierState};
use stark_tools::{commitable::Commitable, merkletree::{PedersenTreeConfig, Root}, polynomial::{Foldable2, Polynomial, PolynomialCoefficient, PolynomialPoints}};
use crate::proximityproofs::{narg_proximityproof::{ProximityProofDomainSeparator, ProximityProofProtocol}, utils::prove_leaf_index};
use ark_starkcurve::{FqConfig as Config};
use ark_ed_on_bls12_381::Fq as Fq;

#[derive(Clone)]
pub struct FRIProtocol {
    pub queries: Vec<u32>,
    pub pedersen_config: PedersenTreeConfig
}


impl<H, G:CurveGroup> ProximityProofDomainSeparator<G, H, FRIProtocol> for DomainSeparator<H>
where
    H: DuplexSpongeInterface,
    Self: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField>,
{
    fn new_pp_proof(domsep: &str, config: &FRIProtocol) -> Self {
        Self::new(domsep)
            .add_pp_statement()
            .add_pp_domsep(config)
    }

    fn add_pp_statement(self) -> Self {
        self.add_bytes(32, "public commitment (C)")
            // .add_points(1, "public key (X)")
            .ratchet()
    }

    fn add_pp_domsep(self, config: &FRIProtocol) -> Self {
        // self.add_bytes(32, "fake commitment (K)")
        self.challenge_bytes(32, "folding randomness")
            // .challenge_scalars(2, "challenge (c)")
            // .challenge_scalars(1, "challenge (c1)")
            // .add_scalars(1, "response (r)")
    }
}

impl<'b, H, G, P, const N: usize, T, T1, DS, Commitment, FRIProtocol> ProximityProofProtocol<'b, H, G, P, N, T, T1, DS, Commitment, FRIProtocol> for FRIProtocol where 
    T: MontConfig<N>,
    H: DuplexSpongeInterface,
    G: CurveGroup,
    P: Polynomial<N, T, T1>,
    Commitment: Absorb + std::fmt::Display,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField>,
    DS: ProximityProofDomainSeparator<G, H, FRIProtocol>,
    for<'a> VerifierState<'a, H>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField> {
    fn prove(
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `spongefish::Unit`.
    prover_state: &'b mut spongefish::ProverState<H>,
    // the secret polynomial
    polynomial: P,
    commitment: &Commitment,
    config: FRIProtocol
    ) -> spongefish::ProofResult<&'b [u8]> {
        let mut rng = ark_std::test_rng();
        println!("real commitment: {commitment}");
        let folding_bytes = prover_state.challenge_bytes::<32>().unwrap();
        let mut folding: [u64; N] = [0; N];
        for i in 0..N {
            let mut sum: u64 = 0;
            for j in 0..8 {
                sum += folding_bytes[i * 8 + j] as u64;
            }
            folding[i] = sum;
        }
        println!("before {:?} after {:?}", folding_bytes, folding);
        let folded = polynomial.fft(1).fold_bytes( folding);
        // folded.commit(&mut rng, config.pedersen_config);
        // let mut commitment_bytes: Vec<u8> = [].to_vec();
        // commitment.to_sponge_bytes(&mut commitment_bytes);
        // println!("bytes: {:?}", commitment_bytes);
        // prover_state.add_bytes(&commitment_bytes).unwrap();
        Ok(prover_state.narg_string())
    }




    fn verify(
    verifier_state: &mut spongefish::VerifierState<H>,
    // the commitment to the polynomial
    commitment: &'b Commitment,
    config: FRIProtocol
    ) -> spongefish::ProofResult<()> {
        let x = verifier_state.challenge_bytes::<32>().unwrap();
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
    
    let config = FRIProtocol {
        queries: vec![1, 2, 3],
        pedersen_config: pedersen_config.clone()
    };
    // Set up the IO for the protocol transcript with domain separator "spongefish::examples::schnorr"
    let io: DomainSeparator<H> = ProximityProofDomainSeparator::<G, H, FRIProtocol>::new_pp_proof("FRI proximity proof", &config);

    // Set up the elements to prove
    // let P = G::generator();

    let mut rnd = ark_std::test_rng();
    // let (x, X) = keygen(&mut rnd);

    // // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut prover_state = io.to_prover_state();
    // prover_state.public_points(&[P, P * x]).unwrap();
    let commited_poly = PolynomialCoefficient::<Config, 4>::random_poly(&mut rnd, 7).fft(1).commit(&mut rnd, pedersen_config);
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


    let proof = <FRIProtocol as ProximityProofProtocol<
        H, G, PolynomialPoints::<Config, 4>, 4, Config, _, DomainSeparator<H>, Root, _
        >>::prove(
        &mut prover_state, 
        commited_poly.data,
        &commited_poly.ptree.root(),
        config.clone()
    ).expect("Invalid proof");
    // let proof = prove(&mut prover_state, P, x).expect("Invalid proof");

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut verifier_state = io.to_verifier_state(proof);
    verifier_state.public_bytes(&commited_poly.ptree.root().to_sponge_bytes_as_vec()).unwrap();
    verifier_state.ratchet().unwrap();

    <FRIProtocol as ProximityProofProtocol<
        H, G, PolynomialPoints::<Config, 4>, 4, Config, _, DomainSeparator<H>, Root, _
        >>::verify(&mut verifier_state, &commited_poly.ptree.root(), config.clone()).expect("Invalid proof");
}