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

//! SubjectPublicKeyInfo extraction from an X.509 certificate.
//!
//! This layer reads the public key out of a certificate the read path
//! returns: it navigates the DER to the SubjectPublicKeyInfo, classifies
//! the key (RSA with its modulus size, or an elliptic curve), and exposes
//! the SPKI bytes so a host verifier can check a signature the card
//! produced. It pairs a certificate with the right signing chain.
//!
//! It does **not** validate the certificate. Chain building, validity
//! windows, name constraints, key usage, and revocation are a consumer or
//! platform concern and stay out of this crate, as does the rest of the
//! X.509 structure; only the SubjectPublicKeyInfo is parsed. The DER walk
//! is built on [`refineid_ber`] rather than a general X.509 parser.

use refineid_ber::{BerError, BerTlvAny};

/// ASN.1 universal tag for SEQUENCE (constructed).
const TAG_SEQUENCE: u16 = 0x30;
/// ASN.1 universal tag for INTEGER.
const TAG_INTEGER: u16 = 0x02;
/// ASN.1 universal tag for BIT STRING.
const TAG_BIT_STRING: u16 = 0x03;
/// ASN.1 universal tag for OBJECT IDENTIFIER.
const TAG_OID: u16 = 0x06;
/// ASN.1 context-specific `[0]` constructed tag: the explicit TBS version.
const TAG_VERSION: u16 = 0xA0;

/// Object identifier `rsaEncryption` (1.2.840.113549.1.1.1), DER value.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// Object identifier `id-RSASSA-PSS` (1.2.840.113549.1.1.10), DER value.
const OID_RSASSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
/// Object identifier `id-ecPublicKey` (1.2.840.10045.2.1), DER value.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// Object identifier `secp384r1` (1.3.132.0.34), DER value.
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
/// Object identifier `prime256v1` / `secp256r1` (1.2.840.10045.3.1.7),
/// DER value.
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// SubjectPublicKeyInfo index among the TBSCertificate fields when the
/// explicit version is present: version, serial, signature, issuer,
/// validity, subject, then the key.
const SPKI_INDEX_WITH_VERSION: usize = 6;
/// The same index when the optional version field is absent.
const SPKI_INDEX_NO_VERSION: usize = 5;

/// A NIST elliptic curve a FINEID key may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
}

/// The classified public key of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA (PKCS#1 or PSS), with the modulus bit length: 3072 for an
    /// RSA-3072 key.
    Rsa {
        /// Modulus size in bits.
        modulus_bits: usize,
    },
    /// An elliptic-curve key over `curve`.
    Ecdsa {
        /// The named curve.
        curve: EcCurve,
    },
}

/// The SubjectPublicKeyInfo of a certificate: its DER bytes and the
/// classified key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spki<'a> {
    der: &'a [u8],
    key: PublicKey,
}

impl<'a> Spki<'a> {
    /// Parse the SubjectPublicKeyInfo out of one complete X.509
    /// certificate.
    ///
    /// # Errors
    ///
    /// [`X509Error`] when the DER is malformed, the structure is not a
    /// certificate reaching a SubjectPublicKeyInfo, or the key algorithm
    /// or curve is not one this crate recognizes.
    pub fn from_certificate(certificate_der: &'a [u8]) -> Result<Self, X509Error> {
        let certificate = sequence(certificate_der)?;
        let tbs = sequence(first_child_bytes(certificate.value())?)?;

        let (first, _) = child_with_bytes(tbs.value(), 0)?;
        let spki_index = if first.tag() == TAG_VERSION {
            SPKI_INDEX_WITH_VERSION
        } else {
            SPKI_INDEX_NO_VERSION
        };
        let (spki, der) = child_with_bytes(tbs.value(), spki_index)?;
        expect_tag(spki, TAG_SEQUENCE)?;

        let key = classify(spki.value())?;
        Ok(Self { der, key })
    }

    /// The SubjectPublicKeyInfo DER, ready to hand a host verifier.
    #[must_use]
    pub const fn der(&self) -> &[u8] {
        self.der
    }

    /// The classified public key.
    #[must_use]
    pub const fn key(&self) -> PublicKey {
        self.key
    }
}

/// Classify the key from a SubjectPublicKeyInfo value: an AlgorithmIdentifier
/// SEQUENCE followed by the subjectPublicKey BIT STRING.
fn classify(spki_value: &[u8]) -> Result<PublicKey, X509Error> {
    let algorithm = child(spki_value, 0)?;
    expect_tag(algorithm, TAG_SEQUENCE)?;
    let subject_public_key = child(spki_value, 1)?;
    expect_tag(subject_public_key, TAG_BIT_STRING)?;

    let algorithm_oid = child(algorithm.value(), 0)?;
    expect_tag(algorithm_oid, TAG_OID)?;
    let oid = algorithm_oid.value();

    if oid == OID_RSA_ENCRYPTION || oid == OID_RSASSA_PSS {
        let modulus_bits = rsa_modulus_bits(subject_public_key.value())?;
        return Ok(PublicKey::Rsa { modulus_bits });
    }
    if oid == OID_EC_PUBLIC_KEY {
        let parameters = child(algorithm.value(), 1)?;
        expect_tag(parameters, TAG_OID)?;
        let curve = match parameters.value() {
            value if value == OID_SECP384R1 => EcCurve::P384,
            value if value == OID_PRIME256V1 => EcCurve::P256,
            _ => return Err(X509Error::UnsupportedCurve),
        };
        return Ok(PublicKey::Ecdsa { curve });
    }
    Err(X509Error::UnsupportedAlgorithm)
}

/// Read the modulus bit length from a subjectPublicKey BIT STRING that
/// wraps a PKCS#1 RSAPublicKey.
fn rsa_modulus_bits(bit_string_value: &[u8]) -> Result<usize, X509Error> {
    // The BIT STRING opens with an unused-bits count, then the DER.
    let (_unused_bits, rsa_public_key_der) = bit_string_value
        .split_first()
        .ok_or(X509Error::Malformed("empty RSA public key bit string"))?;
    let rsa_public_key = sequence(rsa_public_key_der)?;
    let modulus = child(rsa_public_key.value(), 0)?;
    expect_tag(modulus, TAG_INTEGER)?;

    // A DER INTEGER carries a leading zero byte when the high bit would
    // otherwise read as a sign; strip it to get the magnitude.
    let magnitude = match modulus.value().split_first() {
        Some((&0, rest)) if !rest.is_empty() => rest,
        _ => modulus.value(),
    };
    match magnitude.first() {
        None => Ok(0),
        Some(&top) => {
            let full = magnitude.len().saturating_mul(u8::BITS as usize);
            Ok(full - top.leading_zeros() as usize)
        }
    }
}

/// Parse `bytes` as a TLV and require it be a SEQUENCE.
fn sequence(bytes: &[u8]) -> Result<BerTlvAny<'_>, X509Error> {
    let tlv = BerTlvAny::parse(bytes).map_err(X509Error::Ber)?;
    expect_tag(tlv, TAG_SEQUENCE)?;
    Ok(tlv)
}

/// The full byte span of the first child of a constructed value.
fn first_child_bytes(value: &[u8]) -> Result<&[u8], X509Error> {
    let (_, bytes) = child_with_bytes(value, 0)?;
    Ok(bytes)
}

/// The `index`-th child TLV of a constructed value.
fn child(value: &[u8], index: usize) -> Result<BerTlvAny<'_>, X509Error> {
    let (tlv, _) = child_with_bytes(value, index)?;
    Ok(tlv)
}

/// The `index`-th child TLV of a constructed value, together with the
/// exact bytes it occupies, walking the definite-length encodings.
fn child_with_bytes(value: &[u8], index: usize) -> Result<(BerTlvAny<'_>, &[u8]), X509Error> {
    let mut cursor = 0;
    for _ in 0..index {
        let rest = value
            .get(cursor..)
            .ok_or(X509Error::Malformed("child index past end"))?;
        let field = BerTlvAny::parse(rest).map_err(X509Error::Ber)?;
        cursor = cursor
            .checked_add(field.size())
            .ok_or(X509Error::Malformed("length overflow"))?;
    }
    let rest = value
        .get(cursor..)
        .ok_or(X509Error::Malformed("child index past end"))?;
    let field = BerTlvAny::parse(rest).map_err(X509Error::Ber)?;
    let bytes = rest
        .get(..field.size())
        .ok_or(X509Error::Malformed("child length past end"))?;
    Ok((field, bytes))
}

/// Require a parsed TLV to carry `tag`.
fn expect_tag(tlv: BerTlvAny<'_>, tag: u16) -> Result<(), X509Error> {
    if tlv.tag() == tag {
        Ok(())
    } else {
        Err(X509Error::Malformed("unexpected tag"))
    }
}

/// A certificate-parsing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X509Error {
    /// The underlying DER parse failed.
    Ber(BerError),
    /// The DER parsed but its structure was not a certificate reaching a
    /// SubjectPublicKeyInfo; the note says where.
    Malformed(&'static str),
    /// The key algorithm is not one this crate recognizes.
    UnsupportedAlgorithm,
    /// The key is elliptic-curve, but over a curve this crate does not
    /// recognize.
    UnsupportedCurve,
}

impl core::fmt::Display for X509Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ber(error) => write!(f, "x509 DER: {error}"),
            Self::Malformed(note) => write!(f, "x509: malformed certificate: {note}"),
            Self::UnsupportedAlgorithm => f.write_str("x509: unsupported key algorithm"),
            Self::UnsupportedCurve => f.write_str("x509: unsupported elliptic curve"),
        }
    }
}

impl core::error::Error for X509Error {}

#[cfg(test)]
mod tests {
    use super::{
        EcCurve, OID_EC_PUBLIC_KEY, OID_PRIME256V1, OID_RSA_ENCRYPTION, OID_SECP384R1, PublicKey,
        Spki, TAG_BIT_STRING, TAG_INTEGER, TAG_OID, TAG_SEQUENCE, TAG_VERSION, X509Error,
    };
    use refineid_ber::tlv;

    /// RSA-3072 modulus width in bytes.
    const RSA_3072_BYTES: usize = 384;
    /// Expected RSA-3072 modulus bit length.
    const RSA_3072_BITS: usize = 3072;
    /// A leading byte with the high bit set, so the modulus magnitude is
    /// the full width.
    const MODULUS_TOP_BYTE: u8 = 0x80;
    /// DER INTEGER positive-sign leading byte.
    const SIGN_BYTE: u8 = 0x00;
    /// The unused-bits count opening a key BIT STRING: none.
    const NO_UNUSED_BITS: u8 = 0x00;
    /// Modulus filler byte.
    const FILL: u8 = 0xAB;
    /// The public exponent 65537, DER INTEGER value.
    const EXPONENT_65537: &[u8] = &[0x01, 0x00, 0x01];
    /// A synthetic serial number, DER INTEGER value.
    const SERIAL: &[u8] = &[0x2A];
    /// The TBS version value for a v3 certificate.
    const VERSION_V3: &[u8] = &[0x02];

    fn der(tag: u16, value: &[u8]) -> Vec<u8> {
        tlv(u8::try_from(tag).expect("test tag fits a byte"), value).expect("value fits")
    }

    fn seq(children: &[&[u8]]) -> Vec<u8> {
        der(TAG_SEQUENCE, &children.concat())
    }

    /// An RSA-3072 SubjectPublicKeyInfo.
    fn rsa_spki() -> Vec<u8> {
        let mut modulus = vec![SIGN_BYTE, MODULUS_TOP_BYTE];
        modulus.resize(1 + RSA_3072_BYTES, FILL);
        let rsa_public_key = seq(&[
            &der(TAG_INTEGER, &modulus),
            &der(TAG_INTEGER, EXPONENT_65537),
        ]);
        let mut bit_string = vec![NO_UNUSED_BITS];
        bit_string.extend_from_slice(&rsa_public_key);
        let algorithm = seq(&[&der(TAG_OID, OID_RSA_ENCRYPTION)]);
        seq(&[&algorithm, &der(TAG_BIT_STRING, &bit_string)])
    }

    /// A P-384 SubjectPublicKeyInfo. The point is synthetic; the parser
    /// classifies by the curve identifier, not the point.
    fn ec_spki(curve_oid: &[u8]) -> Vec<u8> {
        let algorithm = seq(&[&der(TAG_OID, OID_EC_PUBLIC_KEY), &der(TAG_OID, curve_oid)]);
        let mut bit_string = vec![NO_UNUSED_BITS];
        bit_string.extend_from_slice(&[FILL; RSA_3072_BYTES]);
        seq(&[&algorithm, &der(TAG_BIT_STRING, &bit_string)])
    }

    /// Wrap a SubjectPublicKeyInfo in a minimal certificate, with or
    /// without the explicit version field.
    fn certificate(spki: &[u8], with_version: bool) -> Vec<u8> {
        let empty_name = seq(&[]);
        let signature_algorithm = seq(&[&der(TAG_OID, OID_RSA_ENCRYPTION)]);
        let validity = seq(&[]);
        let mut tbs_fields: Vec<Vec<u8>> = Vec::new();
        if with_version {
            tbs_fields.push(der(TAG_VERSION, &der(TAG_INTEGER, VERSION_V3)));
        }
        tbs_fields.push(der(TAG_INTEGER, SERIAL));
        tbs_fields.push(signature_algorithm.clone());
        tbs_fields.push(empty_name.clone());
        tbs_fields.push(validity);
        tbs_fields.push(empty_name);
        tbs_fields.push(spki.to_vec());
        let tbs_refs: Vec<&[u8]> = tbs_fields.iter().map(Vec::as_slice).collect();
        let tbs = seq(&tbs_refs);
        seq(&[
            &tbs,
            &signature_algorithm,
            &der(TAG_BIT_STRING, &[NO_UNUSED_BITS]),
        ])
    }

    #[test]
    fn extracts_an_rsa_3072_key() {
        let spki = rsa_spki();
        let certificate = certificate(&spki, true);
        let parsed = Spki::from_certificate(&certificate).expect("parses");
        assert_eq!(
            parsed.key(),
            PublicKey::Rsa {
                modulus_bits: RSA_3072_BITS
            }
        );
        assert_eq!(parsed.der(), spki.as_slice());
    }

    #[test]
    fn extracts_a_p384_key() {
        let certificate = certificate(&ec_spki(OID_SECP384R1), true);
        let parsed = Spki::from_certificate(&certificate).expect("parses");
        assert_eq!(
            parsed.key(),
            PublicKey::Ecdsa {
                curve: EcCurve::P384
            }
        );
    }

    #[test]
    fn extracts_a_p256_key() {
        let certificate = certificate(&ec_spki(OID_PRIME256V1), true);
        let parsed = Spki::from_certificate(&certificate).expect("parses");
        assert_eq!(
            parsed.key(),
            PublicKey::Ecdsa {
                curve: EcCurve::P256
            }
        );
    }

    #[test]
    fn finds_the_key_when_the_version_field_is_absent() {
        let spki = rsa_spki();
        let certificate = certificate(&spki, false);
        let parsed = Spki::from_certificate(&certificate).expect("parses");
        assert_eq!(
            parsed.key(),
            PublicKey::Rsa {
                modulus_bits: RSA_3072_BITS
            }
        );
        assert_eq!(parsed.der(), spki.as_slice());
    }

    #[test]
    fn rejects_truncated_der() {
        // Cut the certificate in half, into the TBS, so the declared
        // length runs past the buffer.
        const HALVED: usize = 2;
        let certificate = certificate(&rsa_spki(), true);
        let truncated = &certificate[..certificate.len() / HALVED];
        assert!(Spki::from_certificate(truncated).is_err());
    }

    #[test]
    fn rejects_an_unknown_curve() {
        // A syntactically valid EC key over an unnamed curve identifier.
        let certificate = certificate(&ec_spki(OID_RSA_ENCRYPTION), true);
        assert_eq!(
            Spki::from_certificate(&certificate),
            Err(X509Error::UnsupportedCurve)
        );
    }
}
