//! Traits for the prover backend and the verifier backend.

use crate::{
    prover::{error::ProverError, prover::ProverInput},
    verifier::error::VerifierError,
    Proof, PublicInput,
};

#[cfg(any(test, feature = "fixtures"))]
use std::any::Any;

/// A trait for zk proof generation backend.
pub trait ProverBackend<F>
where
    F: Field,
{
    /// Creates a commitment to the plaintext, padding the plaintext if necessary.
    ///
    /// Returns the commitment and the salt used to create the commitment.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to be committed to.
    fn commit_plaintext(&self, plaintext: Vec<u8>) -> (F, F);

    /// Creates a commitment to the encoding sum.
    ///
    /// Returns the commitment and the salt used to create the commitment.
    ///
    /// # Arguments
    ///
    /// * `encoding_sum` - The sum of the encodings be committed to.
    fn commit_encoding_sum(&self, encoding_sum: F) -> (F, F);

    /// Given the `inputs` to the AuthDecode zk circuit, generates and returns `Proof`(s)
    ///
    /// # Arguments
    ///
    /// * `inputs` - A collection of circuit inputs. Each input proves a single chunk
    ///              of plaintext.
    fn prove(&self, inputs: Vec<ProverInput<F>>) -> Result<Vec<Proof>, ProverError>;

    /// The bytesize of a single chunk of plaintext. Does not include the salt.
    fn chunk_size(&self) -> usize;

    // Testing only. Used to downcast to a concrete type.
    #[cfg(any(test, feature = "fixtures"))]
    fn as_any(&self) -> &dyn Any;
}

/// A trait for zk proof verification backend.
pub trait VerifierBackend<F>
where
    F: Field,
{
    /// Verifies multiple inputs against multiple proofs.
    ///
    /// The backend internally determines which inputs correspond to which proofs.
    fn verify(&self, inputs: Vec<PublicInput<F>>, proofs: Vec<Proof>) -> Result<(), VerifierError>;

    /// The bytesize of a single chunk of plaintext. Does not include the salt.
    fn chunk_size(&self) -> usize;
}

/// Methods for working with a field element.
pub trait Field {
    /// Creates a new field element from bytes in big-endian byte order.
    fn from_bytes_be(bytes: Vec<u8>) -> Self;

    /// Returns zero, the additive identity.
    fn zero() -> Self;
}
