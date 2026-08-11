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

//! The public key of an X.509 certificate, reconstructed from unvalidated
//! boundary bytes into deconstructed, owned key types.
//!
//! A certificate the read path returns is boundary data: raw DER from
//! outside the trust domain. It enters as an [`UnvalidatedCertificate`],
//! whose only purpose is to be consumed by
//! [`PublicKey::from_certificate`]. That constructor deconstructs the DER,
//! checks every structural invariant once, and reconstructs the key as
//! typed values with private fields -- an RSA key as its
//! [`RsaModulus`] and [`RsaPublicExponent`] magnitudes, an elliptic-curve
//! key as its named curve and validated point coordinates. No raw
//! certificate or SubjectPublicKeyInfo buffer survives the reconstruction;
//! a host verifier that needs SPKI bytes re-serializes them from the typed
//! meaning with [`PublicKey::to_spki_der`], which DER's canonical encoding
//! makes exact.
//!
//! The walk parses only enough of the certificate to reach and
//! deconstruct the SubjectPublicKeyInfo. Full X.509 -- validity windows,
//! extensions, chain building, name constraints, key usage, and
//! revocation -- stays out of the core, and the DER walk is built on
//! [`refineid_ber`] rather than a general X.509 parser, so no dependency
//! is added.

use refineid_ber::{BerError, BerTlvAny};

/// ASN.1 universal tag for SEQUENCE (constructed).
const TAG_SEQUENCE: u16 = 0x30;
/// ASN.1 universal tag for INTEGER.
const TAG_INTEGER: u16 = 0x02;
/// ASN.1 universal tag for BIT STRING.
const TAG_BIT_STRING: u16 = 0x03;
/// ASN.1 universal tag for OBJECT IDENTIFIER.
const TAG_OID: u16 = 0x06;
/// ASN.1 universal tag for NULL: the rsaEncryption parameters.
const TAG_NULL: u16 = 0x05;
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

/// The high bit of a DER INTEGER's leading byte: set, it would read as a
/// sign, so the canonical encoding pads a positive integer with one zero
/// byte (X.690 section 8.3).
const INTEGER_HIGH_BIT: u8 = 0x80;
/// The SEC1 uncompressed-point form indicator opening an EC subjectPublicKey
/// (SEC1 section 2.3.3; RFC 5480 section 2.2).
const SEC1_UNCOMPRESSED: u8 = 0x04;
/// P-256 field-element width in bytes (RFC 5480 section 2.1.1.1).
const P256_COORDINATE_BYTES: usize = 32;
/// P-384 field-element width in bytes (RFC 5480 section 2.1.1.1).
const P384_COORDINATE_BYTES: usize = 48;

/// A NIST elliptic curve a FINEID key may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
}

impl EcCurve {
    /// The width of one affine coordinate on this curve, in bytes.
    #[must_use]
    pub const fn coordinate_bytes(self) -> usize {
        match self {
            Self::P256 => P256_COORDINATE_BYTES,
            Self::P384 => P384_COORDINATE_BYTES,
        }
    }

    /// The named-curve object identifier, DER value.
    const fn oid(self) -> &'static [u8] {
        match self {
            Self::P256 => OID_PRIME256V1,
            Self::P384 => OID_SECP384R1,
        }
    }
}

/// A certificate as raw, unvalidated DER from outside the trust domain.
///
/// This is the boundary type. Its only consumer is
/// [`PublicKey::from_certificate`], which deconstructs it and reconstructs
/// typed key values; the raw bytes do not survive the reconstruction.
#[derive(Debug, Clone)]
pub struct UnvalidatedCertificate(Vec<u8>);

impl UnvalidatedCertificate {
    /// Wrap raw certificate DER as an unvalidated boundary value.
    #[must_use]
    pub const fn new(der: Vec<u8>) -> Self {
        Self(der)
    }
}

/// An RSA modulus as its validated big-endian magnitude.
///
/// Reconstructed only by the certificate walk: the DER INTEGER sign byte
/// is removed, and the magnitude is checked non-empty and minimal (no
/// leading zero byte), so a zero or non-canonical modulus never becomes a
/// value of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaModulus(Vec<u8>);

impl RsaModulus {
    /// The magnitude, big-endian and minimal.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The modulus bit length: 3072 for an RSA-3072 key.
    #[must_use]
    pub fn bit_length(&self) -> usize {
        match self.0.first() {
            None => 0,
            Some(&top) => {
                let full = self.0.len().saturating_mul(u8::BITS as usize);
                full - top.leading_zeros() as usize
            }
        }
    }

    fn reconstruct(integer_value: &[u8]) -> Result<Self, X509Error> {
        let magnitude = integer_magnitude(integer_value);
        match magnitude.first() {
            None | Some(0) => Err(X509Error::InvalidKey("zero or non-minimal RSA modulus")),
            Some(_) => Ok(Self(magnitude.to_vec())),
        }
    }
}

/// An RSA public exponent as its validated big-endian magnitude.
///
/// Checked non-empty, minimal, and odd -- an RSA public exponent is
/// coprime to the even totient, so an even value is never a valid key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicExponent(Vec<u8>);

impl RsaPublicExponent {
    /// The magnitude, big-endian and minimal.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn reconstruct(integer_value: &[u8]) -> Result<Self, X509Error> {
        let magnitude = integer_magnitude(integer_value);
        match (magnitude.first(), magnitude.last()) {
            (None | Some(0), _) => Err(X509Error::InvalidKey(
                "zero or non-minimal RSA public exponent",
            )),
            (_, Some(&last)) if last & 1 == 0 => {
                Err(X509Error::InvalidKey("even RSA public exponent"))
            }
            _ => Ok(Self(magnitude.to_vec())),
        }
    }
}

/// A validated RSA public key: its modulus and public exponent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    modulus: RsaModulus,
    exponent: RsaPublicExponent,
}

impl RsaPublicKey {
    /// The modulus.
    #[must_use]
    pub const fn modulus(&self) -> &RsaModulus {
        &self.modulus
    }

    /// The public exponent.
    #[must_use]
    pub const fn exponent(&self) -> &RsaPublicExponent {
        &self.exponent
    }

    /// Deconstruct the PKCS#1 `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
    /// publicExponent INTEGER }` a subjectPublicKey BIT STRING carries.
    fn reconstruct(rsa_public_key_der: &[u8]) -> Result<Self, X509Error> {
        let rsa_public_key = sequence(rsa_public_key_der)?;
        let modulus = child(rsa_public_key.value(), 0)?;
        expect_tag(modulus, TAG_INTEGER)?;
        let exponent = child(rsa_public_key.value(), 1)?;
        expect_tag(exponent, TAG_INTEGER)?;
        Ok(Self {
            modulus: RsaModulus::reconstruct(modulus.value())?,
            exponent: RsaPublicExponent::reconstruct(exponent.value())?,
        })
    }
}

/// A validated elliptic-curve public key: the named curve and the affine
/// coordinates of its point.
///
/// The SEC1 encoding is deconstructed on reconstruction: only the
/// uncompressed form is accepted, and each coordinate is checked to the
/// curve's exact field width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPublicKey {
    curve: EcCurve,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl EcPublicKey {
    /// The named curve.
    #[must_use]
    pub const fn curve(&self) -> EcCurve {
        self.curve
    }

    /// The affine X coordinate, big-endian, exactly
    /// [`EcCurve::coordinate_bytes`] wide.
    #[must_use]
    pub fn x(&self) -> &[u8] {
        &self.x
    }

    /// The affine Y coordinate, big-endian, exactly
    /// [`EcCurve::coordinate_bytes`] wide.
    #[must_use]
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Deconstruct a SEC1 point for `curve` into its validated coordinates.
    fn reconstruct(curve: EcCurve, point: &[u8]) -> Result<Self, X509Error> {
        let (&form, coordinates) = point
            .split_first()
            .ok_or(X509Error::InvalidKey("empty EC point"))?;
        if form != SEC1_UNCOMPRESSED {
            return Err(X509Error::InvalidKey("EC point is not uncompressed"));
        }
        let width = curve.coordinate_bytes();
        let (x, y) = coordinates
            .split_at_checked(width)
            .ok_or(X509Error::InvalidKey("EC point shorter than its curve"))?;
        if y.len() != width {
            return Err(X509Error::InvalidKey("EC point width off its curve"));
        }
        Ok(Self {
            curve,
            x: x.to_vec(),
            y: y.to_vec(),
        })
    }
}

/// The deconstructed, validated public key of a certificate.
///
/// Reconstructed once from an [`UnvalidatedCertificate`]; every field of
/// every variant is a typed, owned value with its invariants checked, and
/// no raw certificate or SubjectPublicKeyInfo buffer is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An RSA key (rsaEncryption or RSASSA-PSS).
    Rsa(RsaPublicKey),
    /// An elliptic-curve key.
    Ecdsa(EcPublicKey),
}

impl PublicKey {
    /// Reconstruct the public key from an unvalidated certificate.
    ///
    /// The boundary bytes are deconstructed down to the
    /// SubjectPublicKeyInfo, every structural invariant is checked once,
    /// and the typed key is reconstructed; the raw certificate is consumed
    /// and dropped.
    ///
    /// # Errors
    ///
    /// [`X509Error`] when the DER is malformed, the structure is not a
    /// certificate reaching a SubjectPublicKeyInfo, the algorithm or curve
    /// is not one this crate recognizes, or a key value fails its
    /// invariants.
    pub fn from_certificate(certificate: UnvalidatedCertificate) -> Result<Self, X509Error> {
        Self::reconstruct(&certificate.0)
    }

    /// Serialize this key as a SubjectPublicKeyInfo, for a host verifier
    /// that consumes SPKI DER.
    ///
    /// The bytes are produced from the typed meaning, which DER's
    /// canonical encoding makes exact: an RSA key is emitted under
    /// `rsaEncryption` with NULL parameters -- also for a key a
    /// certificate declared under RSASSA-PSS -- and an elliptic-curve key
    /// under `id-ecPublicKey` with its named curve.
    ///
    /// # Errors
    ///
    /// [`X509Error::Ber`] when a length exceeds the encoder's range.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, X509Error> {
        match self {
            Self::Rsa(rsa) => {
                let modulus = der_integer(rsa.modulus().as_bytes())?;
                let exponent = der_integer(rsa.exponent().as_bytes())?;
                let mut rsa_public_key_value = modulus;
                rsa_public_key_value.extend_from_slice(&exponent);
                let rsa_public_key = encode(TAG_SEQUENCE, &rsa_public_key_value)?;

                let mut bit_string = vec![0];
                bit_string.extend_from_slice(&rsa_public_key);

                let mut algorithm_value = encode(TAG_OID, OID_RSA_ENCRYPTION)?;
                algorithm_value.extend_from_slice(&encode(TAG_NULL, &[])?);
                let algorithm = encode(TAG_SEQUENCE, &algorithm_value)?;

                let mut spki_value = algorithm;
                spki_value.extend_from_slice(&encode(TAG_BIT_STRING, &bit_string)?);
                encode(TAG_SEQUENCE, &spki_value)
            }
            Self::Ecdsa(ec) => {
                let mut algorithm_value = encode(TAG_OID, OID_EC_PUBLIC_KEY)?;
                algorithm_value.extend_from_slice(&encode(TAG_OID, ec.curve().oid())?);
                let algorithm = encode(TAG_SEQUENCE, &algorithm_value)?;

                let mut bit_string = vec![0, SEC1_UNCOMPRESSED];
                bit_string.extend_from_slice(ec.x());
                bit_string.extend_from_slice(ec.y());

                let mut spki_value = algorithm;
                spki_value.extend_from_slice(&encode(TAG_BIT_STRING, &bit_string)?);
                encode(TAG_SEQUENCE, &spki_value)
            }
        }
    }

    /// Deconstruct one certificate DER to its SubjectPublicKeyInfo and
    /// reconstruct the typed key.
    fn reconstruct(certificate_der: &[u8]) -> Result<Self, X509Error> {
        let certificate = sequence(certificate_der)?;
        let tbs = sequence(first_child_bytes(certificate.value())?)?;

        let (first, _) = child_with_bytes(tbs.value(), 0)?;
        let spki_index = if first.tag() == TAG_VERSION {
            SPKI_INDEX_WITH_VERSION
        } else {
            SPKI_INDEX_NO_VERSION
        };
        let spki = child(tbs.value(), spki_index)?;
        expect_tag(spki, TAG_SEQUENCE)?;

        let algorithm = child(spki.value(), 0)?;
        expect_tag(algorithm, TAG_SEQUENCE)?;
        let subject_public_key = child(spki.value(), 1)?;
        expect_tag(subject_public_key, TAG_BIT_STRING)?;
        let algorithm_oid = child(algorithm.value(), 0)?;
        expect_tag(algorithm_oid, TAG_OID)?;
        let oid = algorithm_oid.value();

        // The BIT STRING opens with its unused-bits count; a key's is zero.
        let (&unused_bits, key_bytes) = subject_public_key
            .value()
            .split_first()
            .ok_or(X509Error::Malformed("empty subjectPublicKey bit string"))?;
        if unused_bits != 0 {
            return Err(X509Error::Malformed("subjectPublicKey with unused bits"));
        }

        if oid == OID_RSA_ENCRYPTION || oid == OID_RSASSA_PSS {
            return Ok(Self::Rsa(RsaPublicKey::reconstruct(key_bytes)?));
        }
        if oid == OID_EC_PUBLIC_KEY {
            let parameters = child(algorithm.value(), 1)?;
            expect_tag(parameters, TAG_OID)?;
            let curve = match parameters.value() {
                value if value == OID_SECP384R1 => EcCurve::P384,
                value if value == OID_PRIME256V1 => EcCurve::P256,
                _ => return Err(X509Error::UnsupportedCurve),
            };
            return Ok(Self::Ecdsa(EcPublicKey::reconstruct(curve, key_bytes)?));
        }
        Err(X509Error::UnsupportedAlgorithm)
    }
}

/// The big-endian magnitude of a DER INTEGER value. A DER INTEGER carries a
/// leading zero byte when the high bit would otherwise read as a sign;
/// strip it to leave the magnitude.
fn integer_magnitude(integer_value: &[u8]) -> &[u8] {
    match integer_value.split_first() {
        Some((&0, rest)) if !rest.is_empty() => rest,
        _ => integer_value,
    }
}

/// Encode a magnitude as a DER INTEGER, re-inserting the sign-pad byte
/// when the leading byte's high bit is set (X.690 section 8.3).
fn der_integer(magnitude: &[u8]) -> Result<Vec<u8>, X509Error> {
    let mut value = Vec::with_capacity(magnitude.len() + 1);
    if magnitude
        .first()
        .is_some_and(|&top| top & INTEGER_HIGH_BIT != 0)
    {
        value.push(0);
    }
    value.extend_from_slice(magnitude);
    encode(TAG_INTEGER, &value)
}

/// Encode one TLV with the crate's BER encoder.
fn encode(tag: u16, value: &[u8]) -> Result<Vec<u8>, X509Error> {
    let tag = u8::try_from(tag).map_err(|_error| X509Error::Malformed("tag exceeds one byte"))?;
    refineid_ber::tlv(tag, value)
        .map_err(|_too_large| X509Error::Malformed("value exceeds the encoder length"))
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
    /// The structure parsed but a key value failed its invariants; the
    /// note says which.
    InvalidKey(&'static str),
}

impl core::fmt::Display for X509Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ber(error) => write!(f, "x509 DER: {error}"),
            Self::Malformed(note) => write!(f, "x509: malformed certificate: {note}"),
            Self::UnsupportedAlgorithm => f.write_str("x509: unsupported key algorithm"),
            Self::UnsupportedCurve => f.write_str("x509: unsupported elliptic curve"),
            Self::InvalidKey(note) => write!(f, "x509: invalid key: {note}"),
        }
    }
}

impl core::error::Error for X509Error {}

#[cfg(test)]
mod tests {
    use super::{
        EcCurve, OID_EC_PUBLIC_KEY, OID_PRIME256V1, OID_RSA_ENCRYPTION, OID_SECP384R1, PublicKey,
        SEC1_UNCOMPRESSED, TAG_BIT_STRING, TAG_INTEGER, TAG_NULL, TAG_OID, TAG_SEQUENCE,
        TAG_VERSION, UnvalidatedCertificate, X509Error,
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
    /// X-coordinate filler byte.
    const X_FILL: u8 = 0xC1;
    /// Y-coordinate filler byte.
    const Y_FILL: u8 = 0xD2;
    /// The public exponent 65537, DER INTEGER value.
    const EXPONENT_65537: &[u8] = &[0x01, 0x00, 0x01];
    /// An even, and so invalid, public exponent value.
    const EXPONENT_EVEN: &[u8] = &[0x02];
    /// The SEC1 compressed-point form indicator for an even Y (SEC1
    /// section 2.3.3), which the key walk must refuse.
    const SEC1_COMPRESSED_EVEN: u8 = 0x02;
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

    fn parse(certificate: Vec<u8>) -> Result<PublicKey, X509Error> {
        PublicKey::from_certificate(UnvalidatedCertificate::new(certificate))
    }

    fn as_rsa(parsed: PublicKey) -> Option<super::RsaPublicKey> {
        match parsed {
            PublicKey::Rsa(rsa) => Some(rsa),
            PublicKey::Ecdsa(_) => None,
        }
    }

    fn as_ec(parsed: PublicKey) -> Option<super::EcPublicKey> {
        match parsed {
            PublicKey::Ecdsa(ec) => Some(ec),
            PublicKey::Rsa(_) => None,
        }
    }

    /// The canonical rsaEncryption AlgorithmIdentifier: OID plus NULL
    /// parameters (RFC 3279 section 2.3.1).
    fn rsa_algorithm() -> Vec<u8> {
        seq(&[&der(TAG_OID, OID_RSA_ENCRYPTION), &der(TAG_NULL, &[])])
    }

    /// An RSA-3072 SubjectPublicKeyInfo with `exponent` as the DER INTEGER
    /// value of the public exponent.
    fn rsa_spki_with_exponent(exponent: &[u8]) -> Vec<u8> {
        let mut modulus = vec![SIGN_BYTE, MODULUS_TOP_BYTE];
        modulus.resize(1 + RSA_3072_BYTES, FILL);
        let rsa_public_key = seq(&[&der(TAG_INTEGER, &modulus), &der(TAG_INTEGER, exponent)]);
        let mut bit_string = vec![NO_UNUSED_BITS];
        bit_string.extend_from_slice(&rsa_public_key);
        seq(&[&rsa_algorithm(), &der(TAG_BIT_STRING, &bit_string)])
    }

    /// An RSA-3072 SubjectPublicKeyInfo.
    fn rsa_spki() -> Vec<u8> {
        rsa_spki_with_exponent(EXPONENT_65537)
    }

    /// A SEC1 uncompressed point sized to `curve`, with distinct X and Y
    /// filler.
    fn ec_point(curve: EcCurve) -> Vec<u8> {
        let width = curve.coordinate_bytes();
        let mut point = vec![SEC1_UNCOMPRESSED];
        point.resize(1 + width, X_FILL);
        point.resize(1 + width + width, Y_FILL);
        point
    }

    /// An EC SubjectPublicKeyInfo over `curve_oid` carrying `point`.
    fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
        let algorithm = seq(&[&der(TAG_OID, OID_EC_PUBLIC_KEY), &der(TAG_OID, curve_oid)]);
        let mut bit_string = vec![NO_UNUSED_BITS];
        bit_string.extend_from_slice(point);
        seq(&[&algorithm, &der(TAG_BIT_STRING, &bit_string)])
    }

    /// Wrap a SubjectPublicKeyInfo in a minimal certificate, with or
    /// without the explicit version field.
    fn certificate(spki: &[u8], with_version: bool) -> Vec<u8> {
        let empty_name = seq(&[]);
        let signature_algorithm = rsa_algorithm();
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
    fn reconstructs_an_rsa_3072_key() {
        let parsed = parse(certificate(&rsa_spki(), true)).expect("parses");
        let rsa = as_rsa(parsed).expect("an RSA certificate reconstructs an RSA key");
        // The DER modulus is the sign byte, MODULUS_TOP_BYTE, then filler;
        // the magnitude drops the sign byte, keeping the RSA-3072 width and
        // the high-bit-set top byte.
        assert_eq!(rsa.modulus().bit_length(), RSA_3072_BITS);
        assert_eq!(rsa.modulus().as_bytes().len(), RSA_3072_BYTES);
        assert_eq!(rsa.modulus().as_bytes().first(), Some(&MODULUS_TOP_BYTE));
        // The exponent has no sign byte, so it is carried unchanged.
        assert_eq!(rsa.exponent().as_bytes(), EXPONENT_65537);
    }

    #[test]
    fn reconstructs_a_p384_key_with_its_coordinates() {
        let point = ec_point(EcCurve::P384);
        let parsed = parse(certificate(&ec_spki(OID_SECP384R1, &point), true)).expect("parses");
        let ec = as_ec(parsed).expect("an EC certificate reconstructs an EC key");
        let width = EcCurve::P384.coordinate_bytes();
        assert_eq!(ec.curve(), EcCurve::P384);
        assert_eq!(ec.x(), vec![X_FILL; width].as_slice());
        assert_eq!(ec.y(), vec![Y_FILL; width].as_slice());
    }

    #[test]
    fn reconstructs_a_p256_key() {
        let point = ec_point(EcCurve::P256);
        let parsed = parse(certificate(&ec_spki(OID_PRIME256V1, &point), true)).expect("parses");
        let ec = as_ec(parsed).expect("an EC certificate reconstructs an EC key");
        assert_eq!(ec.curve(), EcCurve::P256);
    }

    #[test]
    fn finds_the_key_when_the_version_field_is_absent() {
        let parsed = parse(certificate(&rsa_spki(), false)).expect("parses");
        let rsa = as_rsa(parsed).expect("an RSA certificate reconstructs an RSA key");
        assert_eq!(rsa.modulus().bit_length(), RSA_3072_BITS);
    }

    #[test]
    fn reserializes_the_rsa_spki_from_the_typed_meaning() {
        let spki = rsa_spki();
        let parsed = parse(certificate(&spki, true)).expect("parses");
        // DER is canonical, so the typed meaning re-encodes to the exact
        // SubjectPublicKeyInfo the certificate carried.
        assert_eq!(parsed.to_spki_der().expect("encodes"), spki);
    }

    #[test]
    fn reserializes_the_ec_spki_from_the_typed_meaning() {
        let spki = ec_spki(OID_SECP384R1, &ec_point(EcCurve::P384));
        let parsed = parse(certificate(&spki, true)).expect("parses");
        assert_eq!(parsed.to_spki_der().expect("encodes"), spki);
    }

    #[test]
    fn rejects_truncated_der() {
        // Cut the certificate in half, into the TBS, so the declared
        // length runs past the buffer.
        const HALVED: usize = 2;
        let certificate = certificate(&rsa_spki(), true);
        let truncated = certificate[..certificate.len() / HALVED].to_vec();
        assert!(parse(truncated).is_err());
    }

    #[test]
    fn rejects_an_unknown_curve() {
        // A syntactically valid EC key over an unnamed curve identifier.
        let spki = ec_spki(OID_RSA_ENCRYPTION, &ec_point(EcCurve::P256));
        assert_eq!(
            parse(certificate(&spki, true)),
            Err(X509Error::UnsupportedCurve)
        );
    }

    #[test]
    fn rejects_an_unknown_algorithm() {
        // An algorithm identifier that is neither an RSA nor an EC key OID.
        let algorithm = seq(&[&der(TAG_OID, OID_SECP384R1)]);
        let mut bit_string = vec![NO_UNUSED_BITS];
        bit_string.extend_from_slice(&ec_point(EcCurve::P384));
        let spki = seq(&[&algorithm, &der(TAG_BIT_STRING, &bit_string)]);
        assert_eq!(
            parse(certificate(&spki, true)),
            Err(X509Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rejects_an_even_public_exponent() {
        let spki = rsa_spki_with_exponent(EXPONENT_EVEN);
        assert_eq!(
            parse(certificate(&spki, true)),
            Err(X509Error::InvalidKey("even RSA public exponent"))
        );
    }

    #[test]
    fn rejects_a_compressed_ec_point() {
        // A compressed form indicator where the uncompressed one belongs.
        let mut point = ec_point(EcCurve::P384);
        point[0] = SEC1_COMPRESSED_EVEN;
        let spki = ec_spki(OID_SECP384R1, &point);
        assert_eq!(
            parse(certificate(&spki, true)),
            Err(X509Error::InvalidKey("EC point is not uncompressed"))
        );
    }

    #[test]
    fn rejects_a_point_off_its_curve_width() {
        // A P-256-sized point under the P-384 curve identifier.
        let spki = ec_spki(OID_SECP384R1, &ec_point(EcCurve::P256));
        assert!(matches!(
            parse(certificate(&spki, true)),
            Err(X509Error::InvalidKey(_))
        ));
    }

    #[test]
    fn rejects_unused_bits_in_the_key_bit_string() {
        // A subjectPublicKey BIT STRING must carry zero unused bits.
        let mut bit_string = vec![1];
        let mut modulus = vec![SIGN_BYTE, MODULUS_TOP_BYTE];
        modulus.resize(1 + RSA_3072_BYTES, FILL);
        bit_string.extend_from_slice(&seq(&[
            &der(TAG_INTEGER, &modulus),
            &der(TAG_INTEGER, EXPONENT_65537),
        ]));
        let spki = seq(&[&rsa_algorithm(), &der(TAG_BIT_STRING, &bit_string)]);
        assert_eq!(
            parse(certificate(&spki, true)),
            Err(X509Error::Malformed("subjectPublicKey with unused bits"))
        );
    }
}
