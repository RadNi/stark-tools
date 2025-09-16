use ark_ff::PrimeField;
use ark_ec::{CurveGroup};
use stark_tools::commitable::Commited;
use crate::Polynomial;

use spongefish::codecs::arkworks_algebra::{
    DomainSeparator, DuplexSpongeInterface,
    FieldToUnitDeserialize, GroupToUnitDeserialize,
    GroupToUnitSerialize, ProofResult, ProverState, UnitToField, VerifierState
};

pub trait ProximityProofProver<'b, H, G, P, F, Raw> where
    F: PrimeField,
    H: DuplexSpongeInterface,
    G: CurveGroup,
    P: Polynomial<F, Raw>,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField> {
    fn prove(
        &self,
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `spongefish::Unit`.
        prover_state: &'b mut ProverState<H>,
        // the secret polynomial
        polynomial: &Commited<P>,
        // commitment: &Commitment
    ) -> ProofResult<&'b [u8]>;
}
pub trait ProximityProofVerifier<'b, H, G, Commitment> where
    // T: MontConfig<N>,
    H: DuplexSpongeInterface,
    G: CurveGroup,
    for<'a> VerifierState<'a, H>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField> {

    fn verify<F: PrimeField>(
        &self,
        verifier_state: &mut VerifierState<H>,
        // the commitment to the polynomial
        commitment: &'b Commitment
    ) -> ProofResult<()>;
}


/// Extend the domain separator with the proximity proof protocol.
pub trait ProximityProofDomainSeparator<G: CurveGroup, H: DuplexSpongeInterface> {
    /// Shortcut: create a new proximity proof with statement + proof.
    fn new_pp_proof(&self) -> DomainSeparator<H>;
    /// Add the statement of the proximity proof
    fn add_pp_statement(&self, ds: DomainSeparator<H>) -> DomainSeparator<H>;
    /// Add the proximity proof protocol to the domain separator.
    fn add_pp_domsep(&self, ds: DomainSeparator<H>) -> DomainSeparator<H>;
}
