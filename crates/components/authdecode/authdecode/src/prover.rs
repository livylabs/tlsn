use futures_util::SinkExt;
use std::ops::Add;
use utils_aio::sink::IoSink;

use authdecode_core::{
    backend::traits::{Field, ProverBackend as Backend},
    encodings::EncodingProvider,
    id::IdCollection,
    msgs::Message,
    prover::{commitment::CommitmentData, error::ProverError, state},
    Prover as CoreProver,
};

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

/// Prover in the AuthDecode protocol.
pub struct Prover<I, S, F>
where
    I: IdCollection,
    F: Field + Add<Output = F>,
    S: state::ProverState,
{
    /// The wrapped prover in the AuthDecode protocol.
    prover: CoreProver<I, S, F>,
}

impl<I, F> Prover<I, state::Initialized, F>
where
    I: IdCollection,
    F: Field + Add<Output = F>,
{
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `backend` - The zk backend.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Self {
            prover: CoreProver::new(backend),
        }
    }
}

impl<I, F> Prover<I, state::Initialized, F>
where
    I: IdCollection,
    F: Field + Add<Output = F>,
{
    /// Creates a commitment to each element in the `data_set`.
    ///
    /// # Arguments
    ///
    /// * `sink` - The sink for sending messages to the verifier.
    /// * `data_set` - The set of commitment data to be committed to.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    pub async fn commit<Si: IoSink<Message<I, F>> + Send + Unpin>(
        self,
        sink: &mut Si,
        data_set: Vec<CommitmentData<I>>,
    ) -> Result<Prover<I, state::Committed<I, F>, F>, ProverError>
    where
        I: IdCollection,
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        let (core_prover, msg) = self.prover.commit(data_set)?;

        sink.send(Message::Commit(msg)).await?;

        Ok(Prover {
            prover: core_prover,
        })
    }
}

impl<I, F> Prover<I, state::Committed<I, F>, F>
where
    I: IdCollection,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    /// Generates zk proofs.
    ///
    /// # Arguments
    ///
    /// * `sink` - The sink for sending messages to the verifier.
    /// * `encoding_provider` - The provider of full encodings for the plaintext committed to
    ///                         earlier.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    pub async fn prove<Si: IoSink<Message<I, F>> + Send + Unpin>(
        self,
        sink: &mut Si,
        encoding_provider: impl EncodingProvider<I>,
    ) -> Result<Prover<I, state::ProofGenerated<I, F>, F>, ProverError> {
        let (prover, msg) = self.prover.prove(encoding_provider)?;

        sink.send(Message::Proofs(msg)).await?;

        Ok(Prover { prover })
    }
}
