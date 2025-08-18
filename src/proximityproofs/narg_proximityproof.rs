use ark_ff::{MontConfig};
use ark_ec::{CurveGroup};
use crate::Polynomial;

use spongefish::codecs::arkworks_algebra::{
    DomainSeparator, DuplexSpongeInterface, FieldDomainSeparator,
    FieldToUnitDeserialize, GroupDomainSeparator, GroupToUnitDeserialize,
    GroupToUnitSerialize, ProofResult, ProverState, UnitToField, VerifierState
};

pub trait ProximityProofProtocol<'b, H, G, P, const N: usize, T, T1, DS, Commitment, Protocol> where
    T: MontConfig<N>,
    H: DuplexSpongeInterface,
    G: CurveGroup,
    P: Polynomial<N, T, T1>,
    ProverState<H>: GroupToUnitSerialize<G> + UnitToField<G::ScalarField>,
    DS: ProximityProofDomainSeparator<G, H, Protocol>,
    for<'a> VerifierState<'a, H>: GroupToUnitDeserialize<G>
        + FieldToUnitDeserialize<G::ScalarField>
        + UnitToField<G::ScalarField> {
    fn prove(
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `spongefish::Unit`.
    prover_state: &'b mut ProverState<H>,
    // the secret polynomial
    polynomial: P,
    commitment: &Commitment,
    config: Protocol
    ) -> ProofResult<&'b [u8]>;

    fn verify(
    verifier_state: &mut VerifierState<H>,
    // the commitment to the polynomial
    commitment: &'b Commitment,
    config: Protocol
    ) -> ProofResult<()>;
}

pub trait DSMarker {}
impl<H: DuplexSpongeInterface> DSMarker for DomainSeparator<H> {}

/// Extend the domain separator with the proximity proof protocol.
pub trait ProximityProofDomainSeparator<G: CurveGroup, H: DuplexSpongeInterface, Protocol> where Self: DSMarker {
    /// Shortcut: create a new proximity proof with statement + proof.
    fn new_pp_proof(domsep: &str, config: &Protocol) -> Self;
    /// Add the statement of the proximity proof
    fn add_pp_statement(self) -> Self;
    /// Add the proximity proof protocol to the domain separator.
    fn add_pp_domsep(self, config: &Protocol) -> Self;
}
