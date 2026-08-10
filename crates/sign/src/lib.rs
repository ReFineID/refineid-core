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
//! operation; the host computes the digest and drives the MANAGE
//! SECURITY ENVIRONMENT / PERFORM SECURITY OPERATION choreography. The
//! shape follows the card family the session resolved (see
//! [`SignScheme`]): the citizen card loads the digest with PSO:HASH and
//! signs an empty PSO:CDS, while the organizational card carries the
//! digest inline in a single PSO:CDS and issues no PSO:HASH. Both
//! families set the digital-signature template for either key. The PIN
//! that gates the key must already be verified in the card session;
//! these commands carry no credential material and use the plain
//! transport path.
//!
//! The pre-hashed chains all fit the short-form command: RSASSA-PKCS1-v1_5
//! and RSASSA-PSS over SHA-256 for the RSA keys, and ECDSA over P-384 for
//! the newer keys. PSS is a card-native scheme -- the card applies the
//! padding from the digest, so the choreography is the pre-hashed chain
//! with a different algorithm reference, not a host-encoded block.
//! PSO:DECIPHER, whose modulus-wide ciphertext needs command chaining,
//! follows in a later slice.

pub mod commands;
pub mod container;

use refineid_apdu::{CardTransport, CommandDataError, ResponseApdu, StatusWord, TransportOutcome};

use commands::{
    ExternalHashValue, MseSet, PsoComputeDigitalSignature, PsoHashExternal, SHA256_LEN, SHA384_LEN,
    SignatureAlgRef,
};
pub use container::{EcdsaP256, EcdsaP384, RsaPkcs1, RsaPkcs1Sha256, RsaPssSha256, Signature};

/// PKCS#15 key reference for the authentication key (PIN1-gated).
pub const KEY_REF_AUTH: u8 = 0x01;
/// PKCS#15 key reference for the qualified-signature key (PIN2-gated).
pub const KEY_REF_SIGN: u8 = 0x02;
/// Organizational card's qualified-signature key reference. That key is
/// local to DF.ESIGN, and a local security-data-object reference sets
/// bit 8 over the object number (IAS-ECC v1.0.1 section 4.4); the global
/// form names no key and the signature answers `6A88`.
pub const ORG_QUALIFIED_KEY_REF: u8 = 0x82;

/// Which card family's signing chain and key numbering to drive.
///
/// The citizen card loads the host digest with PSO:HASH and signs an
/// empty PSO:CDS; the organizational card carries the digest inline in
/// PSO:CDS and names its qualified key by the local reference. The family
/// is resolved once - the auth crate's counter-safe probe settles it when
/// a PIN is verified - and passed to the signing entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignScheme {
    /// FINEID S1 numbering and chain: the citizen cards.
    Citizen,
    /// FINEID S4 numbering and chain: the organizational cards.
    Organizational,
}

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
    /// The card-side reference byte under the citizen numbering.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Auth => KEY_REF_AUTH,
            Self::Sign => KEY_REF_SIGN,
        }
    }

    /// The card-side reference byte under `scheme`. The organizational
    /// qualified-signature key is local to DF.ESIGN and named by
    /// [`ORG_QUALIFIED_KEY_REF`]; every other key keeps its own
    /// reference.
    #[must_use]
    pub const fn reference(self, scheme: SignScheme) -> u8 {
        match (scheme, self) {
            (SignScheme::Organizational, Self::Sign) => ORG_QUALIFIED_KEY_REF,
            _ => self.as_byte(),
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
        scheme: SignScheme,
        alg_ref: SignatureAlgRef,
        key: KeyRef,
    ) -> Result<(), SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = MseSet {
            alg_ref,
            key_ref: key.reference(scheme),
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

    /// Ship the host digest inline and have the card sign it in one
    /// PSO:CDS, the organizational chain's single signing command.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn pso_compute_signature_over_digest(
        &mut self,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = PsoComputeDigitalSignature
            .into_apdu_with_digest(digest)
            .map_err(SignError::Command)?;
        Ok(self.exchange(&command, "PSO:CDS")?.body)
    }

    /// Sign a SHA-256 digest with an RSA key, returning the RSA-3072
    /// signature.
    ///
    /// The key's PIN must already be verified in the card session, and
    /// `scheme` must be the family the session resolved. On an
    /// organizational card the qualified key is local to DF.ESIGN, so
    /// that directory must be the selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha256_rsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA256_RSA_PKCS1,
            key,
            ExternalHashValue::Sha256(digest),
        )?;
        if bytes.len() != RSA_3072_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength {
                got: bytes.len(),
                expected: RSA_3072_SIG_BYTES,
            });
        }
        Ok(Signature::new(bytes))
    }

    /// Sign a SHA-256 digest with an RSA key under RSASSA-PSS, returning
    /// the RSA-3072 signature.
    ///
    /// The card applies the PSS padding itself, so the chain matches the
    /// pre-hashed PKCS#1 path -- only the algorithm reference differs.
    /// PSS uses a card-generated salt, so signing the same digest twice
    /// yields different bytes. The key's PIN must already be verified in
    /// the card session, and `scheme` must be the family the session
    /// resolved.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha256_rsa_pss(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPssSha256>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA256_RSA_PSS,
            key,
            ExternalHashValue::Sha256(digest),
        )?;
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
    /// The key's PIN must already be verified in the card session, and
    /// `scheme` must be the family the session resolved. On an
    /// organizational card the qualified key is local to DF.ESIGN, so
    /// that directory must be the selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    fn sign_prehashed_sha384_ecdsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<EcdsaP384>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA384_ECDSA,
            key,
            ExternalHashValue::Sha384(digest),
        )?;
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

/// Drive the resolved signing chain end to end and return the raw
/// signature bytes: MSE:Set, then either PSO:HASH plus an empty PSO:CDS
/// (citizen) or a single inline-digest PSO:CDS (organizational).
fn drive_chain<T: SignOps>(
    transport: &mut T,
    scheme: SignScheme,
    alg_ref: SignatureAlgRef,
    key: KeyRef,
    hash: ExternalHashValue,
) -> Result<Vec<u8>, SignError<T::Error>> {
    transport.mse_set(scheme, alg_ref, key)?;
    match scheme {
        SignScheme::Citizen => {
            transport.pso_hash(hash)?;
            transport.pso_compute_signature()
        }
        SignScheme::Organizational => transport.pso_compute_signature_over_digest(hash.as_bytes()),
    }
}
