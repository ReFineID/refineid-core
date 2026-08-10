// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Card-side signing for FINEID.
//!
//! The card holds the private key and performs the private-key
//! operation; the host computes the digest and drives the three-command
//! choreography (MANAGE SECURITY ENVIRONMENT, PERFORM SECURITY
//! OPERATION: HASH, PERFORM SECURITY OPERATION: COMPUTE DIGITAL
//! SIGNATURE). The PIN that gates the key must already be verified in
//! the card session; these commands carry no credential material and use
//! the plain transport path.
//!
//! This slice admits the pre-hashed chains that fit the short-form
//! command: RSASSA-PKCS1-v1_5 over SHA-256 for the RSA keys, and ECDSA
//! over P-384 for the newer keys. Host-side-encoded RSA (for PSS, which
//! needs command chaining) and PSO:DECIPHER follow in a later slice.

pub mod commands;
pub mod container;

use refineid_apdu::{CardTransport, CommandDataError, ResponseApdu, StatusWord, TransportOutcome};

use commands::{
    ExternalHashValue, MseSet, MseSetTemplate, PsoComputeDigitalSignature, PsoHashExternal,
    SHA256_LEN, SHA384_LEN, SignatureAlgRef,
};
pub use container::{EcdsaP256, EcdsaP384, RsaPkcs1, RsaPkcs1Sha256, Signature};

/// PKCS#15 key reference for the authentication key (PIN1-gated).
pub const KEY_REF_AUTH: u8 = 0x01;
/// PKCS#15 key reference for the qualified-signature key (PIN2-gated).
pub const KEY_REF_SIGN: u8 = 0x02;

/// Expected RSA-3072 signature length in bytes.
pub const RSA_3072_SIG_BYTES: usize = 384;
/// Expected ECDSA P-384 raw signature length in bytes.
pub const ECDSA_P384_SIG_BYTES: usize = 96;
/// Expected ECDSA P-256 raw signature length in bytes.
pub const ECDSA_P256_SIG_BYTES: usize = 64;

/// The FINEID private-key reference, typed at the sign-API boundary so
/// the chain refuses an arbitrary byte. The card publishes exactly two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRef {
    /// The authentication key, PIN1-gated.
    Auth,
    /// The qualified-signature key, PIN2-gated.
    Sign,
}

impl KeyRef {
    /// The card-side reference byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Auth => KEY_REF_AUTH,
            Self::Sign => KEY_REF_SIGN,
        }
    }

    /// The template FINEID gates this key's signing primitive behind:
    /// the authentication key uses the authentication template, the
    /// qualified-signature key the digital-signature template.
    const fn template(self) -> MseSetTemplate {
        match self {
            Self::Auth => MseSetTemplate::Authentication,
            Self::Sign => MseSetTemplate::DigitalSignature,
        }
    }
}

/// A signing-path failure.
#[derive(Debug)]
pub enum SignError<E> {
    /// An adapter-level transport failure.
    Transport(E),
    /// A transport-level state transition instead of a response.
    Outcome(TransportOutcome),
    /// The card returned a non-success status word at a named stage.
    Status(&'static str, StatusWord),
    /// A command could not be assembled; unreachable for the fixed
    /// signing bodies, kept fail-closed.
    Command(CommandDataError),
    /// The card returned a signature of an unexpected length for the
    /// selected algorithm.
    UnexpectedSignatureLength {
        /// The length the card returned.
        got: usize,
        /// The length the algorithm requires.
        expected: usize,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for SignError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "sign transport: {e}"),
            Self::Outcome(outcome) => write!(f, "sign transport state: {outcome}"),
            Self::Status(stage, sw) => write!(f, "sign {stage}: card returned {sw}"),
            Self::Command(e) => write!(f, "sign command: {e}"),
            Self::UnexpectedSignatureLength { got, expected } => {
                write!(
                    f,
                    "sign: card returned a {got}-byte signature, expected {expected}"
                )
            }
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for SignError<E> {}

/// Card-side signing operations, layered as default methods on every
/// [`CardTransport`].
///
/// Bring the trait into scope to use the methods; the blanket
/// implementation applies to every transport, so a plain contact
/// transport and a PACE secure-messaging transport both gain the same
/// signing operations.
pub trait SignOps: CardTransport {
    /// Set the security environment for a signing key.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn mse_set(
        &mut self,
        alg_ref: SignatureAlgRef,
        key: KeyRef,
    ) -> Result<(), SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = MseSet {
            template: key.template(),
            alg_ref,
            key_ref: key,
        }
        .into_apdu()
        .map_err(SignError::Command)?;
        self.exchange(&command, "MSE:Set").map(drop)
    }

    /// Ship a host-computed digest to the card.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn pso_hash(&mut self, hash: ExternalHashValue) -> Result<(), SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = PsoHashExternal { hash }
            .into_apdu()
            .map_err(SignError::Command)?;
        self.exchange(&command, "PSO:HASH").map(drop)
    }

    /// Have the card sign the previously stored hash and return the raw
    /// signature bytes.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn pso_compute_signature(&mut self) -> Result<Vec<u8>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = PsoComputeDigitalSignature.into_apdu();
        Ok(self.exchange(&command, "PSO:CDS")?.body)
    }

    /// Sign a SHA-256 digest with an RSA key, returning the RSA-3072
    /// signature.
    ///
    /// The key's PIN must already be verified in the card session.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha256_rsa(
        &mut self,
        key: KeyRef,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        self.mse_set(SignatureAlgRef::SHA256_RSA_PKCS1, key)?;
        self.pso_hash(ExternalHashValue::Sha256(digest))?;
        let bytes = self.pso_compute_signature()?;
        if bytes.len() != RSA_3072_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength {
                got: bytes.len(),
                expected: RSA_3072_SIG_BYTES,
            });
        }
        Ok(Signature::new(bytes))
    }

    /// Sign a SHA-384 digest with a P-384 key, returning the raw ECDSA
    /// `r || s` signature.
    ///
    /// The key's PIN must already be verified in the card session.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    fn sign_prehashed_sha384_ecdsa(
        &mut self,
        key: KeyRef,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<EcdsaP384>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        self.mse_set(SignatureAlgRef::SHA384_ECDSA, key)?;
        self.pso_hash(ExternalHashValue::Sha384(digest))?;
        let bytes = self.pso_compute_signature()?;
        if bytes.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength {
                got: bytes.len(),
                expected: ECDSA_P384_SIG_BYTES,
            });
        }
        Ok(Signature::new(bytes))
    }

    /// Transmit one signing command and demand a success response.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn exchange(
        &mut self,
        command: &refineid_apdu::CommandApdu,
        stage: &'static str,
    ) -> Result<ResponseApdu, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let response = self
            .transmit(command)
            .map_err(SignError::Transport)?
            .into_response()
            .map_err(SignError::Outcome)?;
        if !response.is_ok() {
            return Err(SignError::Status(stage, response.status_word()));
        }
        Ok(response)
    }
}

impl<T: CardTransport + ?Sized> SignOps for T {}
