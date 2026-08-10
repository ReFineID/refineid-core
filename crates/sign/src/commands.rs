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

//! Typed commands for the FINEID signing chain.
//!
//! Signing is a three-command choreography (FINEID S1 v4.2 sections 3.6
//! through 3.8): MANAGE SECURITY ENVIRONMENT selects the key and
//! algorithm, PERFORM SECURITY OPERATION: HASH ships the host-computed
//! digest, and PERFORM SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE
//! returns the signature. The card holds the private key and never
//! reveals it; these commands carry no credential material.

use refineid_apdu::{ApduClass, CommandApdu, CommandDataError, CommandHeader};

use crate::KeyRef;

/// MANAGE SECURITY ENVIRONMENT instruction.
const MSE_INS: u8 = 0x22;
/// MSE P1 selecting SET for computation and deciphering.
const MSE_P1_SET: u8 = 0x41;
/// MSE P2 for the digital-signature template.
const MSE_P2_DST: u8 = 0xB6;
/// MSE P2 for the authentication template.
const MSE_P2_AT: u8 = 0xA4;

/// Control-reference-object tag for the algorithm reference.
const CRDO_ALG_REF: u8 = 0x80;
/// Control-reference-object tag for the key reference.
const CRDO_KEY_REF: u8 = 0x84;
/// Control-reference-object value length: the references are one byte.
const CRDO_VALUE_LEN: u8 = 0x01;

/// PERFORM SECURITY OPERATION instruction, shared by HASH and COMPUTE
/// DIGITAL SIGNATURE.
const PSO_INS: u8 = 0x2A;
/// PSO:HASH P1.
const PSO_HASH_P1: u8 = 0x90;
/// PSO:HASH P2 for the external / final hash form.
const PSO_HASH_P2_EXTERNAL: u8 = 0xA0;
/// The hash-value object tag inside PSO:HASH.
const PSO_HASH_TAG_VALUE: u8 = 0x90;
/// Bytes preceding the digest in the hash-value object: the tag and the
/// length byte.
const HASH_VALUE_HEADER_LEN: usize = 2;

/// PSO:COMPUTE DIGITAL SIGNATURE P1.
const PSO_CDS_P1: u8 = 0x9E;
/// PSO:COMPUTE DIGITAL SIGNATURE P2.
const PSO_CDS_P2: u8 = 0x9A;
/// Expected-length byte requesting every available byte of the
/// signature; the adapter chains any 61xx response.
const PSO_CDS_LE_ANY: u8 = 0x00;

/// SHA-1 digest length in bytes.
pub const SHA1_LEN: usize = 20;
/// SHA-224 digest length in bytes.
pub const SHA224_LEN: usize = 28;
/// SHA-256 digest length in bytes.
pub const SHA256_LEN: usize = 32;
/// SHA-384 digest length in bytes.
pub const SHA384_LEN: usize = 48;
/// SHA-512 digest length in bytes.
pub const SHA512_LEN: usize = 64;

/// Algorithm-reference byte for the digital-signature template, per
/// FINEID S1 v4.2 section 3.6.3 Table 6. The byte packs the hash
/// function in its high nibble and the signature scheme in its low
/// nibble; the named values are the ones FINEID cards accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureAlgRef {
    byte: u8,
}

impl SignatureAlgRef {
    /// SHA-256 (high nibble 4) with RSASSA-PKCS1-v1_5 (low nibble 2):
    /// the RSA FINEID signing key's reference.
    pub const SHA256_RSA_PKCS1: Self = Self { byte: 0x42 };
    /// SHA-384 (high nibble 5) with ECDSA (low nibble 4): the newer
    /// P-384 key's reference (FINEID S4-1 v4.2 section 4.2).
    pub const SHA384_ECDSA: Self = Self { byte: 0x54 };
    /// SHA-256 (high nibble 4) with ECDSA (low nibble 4): the P-384 key
    /// signing a SHA-256 digest, required by some relying parties.
    pub const SHA256_ECDSA: Self = Self { byte: 0x44 };

    /// The wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.byte
    }
}

/// Which security-environment template MSE:SET targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MseSetTemplate {
    /// Digital-signature template: the qualified-signature key signs a
    /// hashed message.
    DigitalSignature,
    /// Authentication template: FINEID cards gate the auth key's signing
    /// primitive behind this template.
    Authentication,
}

impl MseSetTemplate {
    /// The MSE P2 byte for this template.
    #[must_use]
    pub const fn p2(self) -> u8 {
        match self {
            Self::DigitalSignature => MSE_P2_DST,
            Self::Authentication => MSE_P2_AT,
        }
    }
}

/// MANAGE SECURITY ENVIRONMENT: SET for a signing key.
#[derive(Debug, Clone, Copy)]
pub struct MseSet {
    /// Which template to set.
    pub template: MseSetTemplate,
    /// Algorithm reference.
    pub alg_ref: SignatureAlgRef,
    /// Private-key reference.
    pub key_ref: KeyRef,
}

impl MseSet {
    /// Serialise into a case-3 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers here: the fixed six-byte
    /// control-reference body is always within the short form. The
    /// result is fallible so the caller stays fail-closed.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        let data = [
            CRDO_ALG_REF,
            CRDO_VALUE_LEN,
            self.alg_ref.as_byte(),
            CRDO_KEY_REF,
            CRDO_VALUE_LEN,
            self.key_ref.as_byte(),
        ];
        CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: MSE_INS,
                p1: MSE_P1_SET,
                p2: self.template.p2(),
            },
            &data,
        )
    }
}

/// A host-computed digest shipped to the card for signing. Each variant
/// pins its wire length (FINEID S1 v4.2 section 3.7.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalHashValue {
    /// A SHA-1 digest.
    Sha1([u8; SHA1_LEN]),
    /// A SHA-224 digest.
    Sha224([u8; SHA224_LEN]),
    /// A SHA-256 digest.
    Sha256([u8; SHA256_LEN]),
    /// A SHA-384 digest.
    Sha384([u8; SHA384_LEN]),
    /// A SHA-512 digest.
    Sha512([u8; SHA512_LEN]),
}

impl ExternalHashValue {
    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha224(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
            Self::Sha384(bytes) => bytes,
            Self::Sha512(bytes) => bytes,
        }
    }

    /// The length byte for the hash-value object; within `u8` by
    /// construction.
    #[must_use]
    pub const fn len_byte(&self) -> u8 {
        match self {
            Self::Sha1(_) => SHA1_LEN as u8,
            Self::Sha224(_) => SHA224_LEN as u8,
            Self::Sha256(_) => SHA256_LEN as u8,
            Self::Sha384(_) => SHA384_LEN as u8,
            Self::Sha512(_) => SHA512_LEN as u8,
        }
    }
}

/// PSO:HASH shipping a host-computed digest in the external-hash form.
#[derive(Debug, Clone, Copy)]
pub struct PsoHashExternal {
    /// The host-computed digest.
    pub hash: ExternalHashValue,
}

impl PsoHashExternal {
    /// Serialise into a case-3 command APDU carrying the hash-value
    /// object.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers: the largest digest object is
    /// well within the short form. Fallible so the caller stays
    /// fail-closed.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        let bytes = self.hash.as_bytes();
        let mut data = Vec::with_capacity(HASH_VALUE_HEADER_LEN.saturating_add(bytes.len()));
        data.push(PSO_HASH_TAG_VALUE);
        data.push(self.hash.len_byte());
        data.extend_from_slice(bytes);
        CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: PSO_INS,
                p1: PSO_HASH_P1,
                p2: PSO_HASH_P2_EXTERNAL,
            },
            &data,
        )
    }
}

/// PSO:COMPUTE DIGITAL SIGNATURE over the previously stored hash.
#[derive(Debug, Clone, Copy)]
pub struct PsoComputeDigitalSignature;

impl PsoComputeDigitalSignature {
    /// Serialise into a case-2 command APDU. The card signs the stored
    /// hash and returns the signature; the adapter chains any 61xx
    /// response.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        CommandApdu::case_2(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: PSO_INS,
                p1: PSO_CDS_P1,
                p2: PSO_CDS_P2,
            },
            PSO_CDS_LE_ANY,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExternalHashValue, MseSet, MseSetTemplate, PsoComputeDigitalSignature, PsoHashExternal,
        SHA256_LEN, SHA384_LEN, SignatureAlgRef,
    };
    use crate::KeyRef;

    /// Expected MSE:Set AT wire for the RSA auth key: header, Lc, then
    /// the algorithm and key control-reference objects.
    const EXPECTED_MSE_AT_RSA: &[u8] = &[
        0x00, 0x22, 0x41, 0xA4, 0x06, 0x80, 0x01, 0x42, 0x84, 0x01, 0x01,
    ];
    /// Expected PSO:HASH wire for a SHA-256 digest: header, Lc, tag,
    /// length, then the digest.
    const EXPECTED_PSO_HASH_SHA256_PREFIX: &[u8] = &[0x00, 0x2A, 0x90, 0xA0, 0x22, 0x90, 0x20];
    /// Expected PSO:CDS wire: header and expected-length byte.
    const EXPECTED_PSO_CDS: &[u8] = &[0x00, 0x2A, 0x9E, 0x9A, 0x00];
    /// A digest filler byte.
    const FILL: u8 = 0xAB;
    /// The documented SHA-256 + RSA-PKCS1 algorithm-reference byte.
    const ALG_SHA256_RSA: u8 = 0x42;
    /// The documented SHA-384 + ECDSA algorithm-reference byte.
    const ALG_SHA384_ECDSA: u8 = 0x54;
    /// The documented SHA-256 + ECDSA algorithm-reference byte.
    const ALG_SHA256_ECDSA: u8 = 0x44;

    #[test]
    fn algorithm_references_pack_the_documented_bytes() {
        assert_eq!(SignatureAlgRef::SHA256_RSA_PKCS1.as_byte(), ALG_SHA256_RSA);
        assert_eq!(SignatureAlgRef::SHA384_ECDSA.as_byte(), ALG_SHA384_ECDSA);
        assert_eq!(SignatureAlgRef::SHA256_ECDSA.as_byte(), ALG_SHA256_ECDSA);
    }

    #[test]
    fn mse_set_at_matches_the_specified_wire() {
        let apdu = MseSet {
            template: MseSetTemplate::Authentication,
            alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1,
            key_ref: KeyRef::Auth,
        }
        .into_apdu()
        .expect("fixed body encodes");
        assert_eq!(apdu.as_bytes(), EXPECTED_MSE_AT_RSA);
    }

    #[test]
    fn pso_hash_sha256_matches_the_specified_wire() {
        let apdu = PsoHashExternal {
            hash: ExternalHashValue::Sha256([FILL; SHA256_LEN]),
        }
        .into_apdu()
        .expect("digest object encodes");
        let wire = apdu.as_bytes();
        assert_eq!(
            &wire[..EXPECTED_PSO_HASH_SHA256_PREFIX.len()],
            EXPECTED_PSO_HASH_SHA256_PREFIX
        );
        assert_eq!(
            wire.len(),
            EXPECTED_PSO_HASH_SHA256_PREFIX.len() + SHA256_LEN
        );
    }

    #[test]
    fn pso_hash_length_byte_tracks_the_digest() {
        assert_eq!(
            ExternalHashValue::Sha256([FILL; SHA256_LEN]).len_byte(),
            SHA256_LEN as u8
        );
        assert_eq!(
            ExternalHashValue::Sha384([FILL; SHA384_LEN]).len_byte(),
            SHA384_LEN as u8
        );
    }

    #[test]
    fn pso_cds_matches_the_specified_wire() {
        assert_eq!(
            PsoComputeDigitalSignature.into_apdu().as_bytes(),
            EXPECTED_PSO_CDS
        );
    }
}
