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

//! AES and CMAC primitives PACE and secure messaging need.
//!
//! ICAO Doc 9303 Part 11 section 9.7.1 defines the key-derivation
//! function the FINEID PACE handshake uses. For the AES-256 variant the
//! hash is SHA-256 and a counter distinguishes the derived keys: one for
//! encryption, two for message authentication, three for the
//! password-derived key used during the encrypted-nonce step.

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{
    BlockCipherEncrypt as _, BlockModeDecrypt as _, BlockModeEncrypt as _, KeyInit, KeyIvInit as _,
};
use cmac::{Cmac, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::container::{AesCbc, Ciphertext, CmacAesTruncated, Mac};

/// AES block size, in bytes.
pub const AES_BLOCK: usize = 16;

/// AES-256 key length, in bytes.
pub const AES_KEY_LEN: usize = 32;

/// Secure messaging truncates the CMAC tag to this length for the
/// message-authentication object (BSI TR-03110-3 section F.2).
pub const CMAC_TAG_TRUNCATED: usize = 8;

/// KDF counter for the encryption key.
const KDF_COUNTER_ENCRYPTION: u8 = 1;
/// KDF counter for the message-authentication key.
const KDF_COUNTER_MAC: u8 = 2;
/// KDF counter for the password-derived key.
const KDF_COUNTER_PASSWORD: u8 = 3;

/// Which key the KDF derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParam {
    /// The encryption key.
    Encryption,
    /// The message-authentication key.
    Mac,
    /// The PACE password-derived key.
    Password,
}

impl KdfParam {
    /// The counter byte for this derived key.
    const fn counter(self) -> u8 {
        match self {
            Self::Encryption => KDF_COUNTER_ENCRYPTION,
            Self::Mac => KDF_COUNTER_MAC,
            Self::Password => KDF_COUNTER_PASSWORD,
        }
    }
}

/// Thirty-two bytes of AES-256 key material.
///
/// Secret keying material with hygiene the type enforces: zeroized on
/// drop and redacted from any formatter, so the bytes never linger and
/// never leak through a debug rendering. Distinct from any other
/// thirty-two-byte array so a key cannot be swapped for a digest or an
/// initialisation vector by accident. The bytes are reachable only
/// through [`Aes256Key::as_bytes`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256Key([u8; AES_KEY_LEN]);

impl Aes256Key {
    /// Borrow the raw key bytes for an AES primitive. Crate-private: a
    /// session key never leaves the crate as bytes.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.0
    }

    /// Wrap key bytes that did not come from the KDF. Test-only: in
    /// production a session key is only ever produced by [`kdf_aes256`],
    /// so there is no non-test caller for a bytes-in constructor.
    #[cfg(test)]
    #[must_use]
    pub fn from_bytes(bytes: [u8; AES_KEY_LEN]) -> Option<Self> {
        let all_zero = bytes.iter().all(|&byte| byte == 0);
        let all_ones = bytes.iter().all(|&byte| byte == u8::MAX);
        if all_zero || all_ones {
            None
        } else {
            Some(Self(bytes))
        }
    }
}

impl core::fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Aes256Key([redacted])")
    }
}

/// ICAO Doc 9303 Part 11 section 9.7.1.2 key derivation for AES-256:
/// `SHA-256(K || counter)` with the counter as a four-byte big-endian
/// value. The digest is exactly the AES-256 key length.
#[must_use]
pub fn kdf_aes256(key_material: &[u8], param: KdfParam) -> Aes256Key {
    let mut hasher = Sha256::new();
    hasher.update(key_material);
    let counter = u32::from(param.counter());
    hasher.update(counter.to_be_bytes());
    let mut digest = hasher.finalize();
    let mut key = [0_u8; AES_KEY_LEN];
    key.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Aes256Key(key)
}

/// AES-CBC input was not a whole number of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnalignedInput {
    /// The offending buffer length.
    pub len: usize,
}

impl core::fmt::Display for UnalignedInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AES-CBC input length {} is not a multiple of {AES_BLOCK}",
            self.len
        )
    }
}

impl core::error::Error for UnalignedInput {}

/// AES-256-CBC encryption with no padding; the caller pre-pads. The
/// initialisation vector is explicit so the secure-messaging derivation
/// stays in the state machine.
///
/// # Errors
///
/// [`UnalignedInput`] when the plaintext is not a whole number of
/// blocks.
pub fn aes256_cbc_encrypt_no_padding(
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Result<Ciphertext<AesCbc>, UnalignedInput> {
    type Encryptor = cbc::Encryptor<aes::Aes256>;
    if !plaintext.len().is_multiple_of(AES_BLOCK) {
        return Err(UnalignedInput {
            len: plaintext.len(),
        });
    }
    let cipher = Encryptor::new(key.into(), iv.into());
    let mut buffer = plaintext.to_vec();
    let plaintext_len = plaintext.len();
    let _in_place = cipher.encrypt_padded::<NoPadding>(&mut buffer, plaintext_len);
    Ok(Ciphertext::new(buffer))
}

/// AES-256-CBC decryption with no padding.
///
/// # Errors
///
/// [`UnalignedInput`] when the ciphertext is not a whole number of
/// blocks.
pub fn aes256_cbc_decrypt_no_padding(
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; AES_BLOCK],
    ciphertext: &Ciphertext<AesCbc>,
) -> Result<Vec<u8>, UnalignedInput> {
    type Decryptor = cbc::Decryptor<aes::Aes256>;
    let mut buffer = ciphertext.as_bytes().to_vec();
    if !buffer.len().is_multiple_of(AES_BLOCK) {
        return Err(UnalignedInput { len: buffer.len() });
    }
    let cipher = Decryptor::new(key.into(), iv.into());
    let _in_place = cipher.decrypt_padded::<NoPadding>(&mut buffer);
    Ok(buffer)
}

/// AES-256-ECB encryption of one block. Secure messaging derives each
/// per-message initialisation vector as the ECB encryption of the send
/// sequence counter.
#[must_use]
pub fn aes256_ecb_encrypt_block(
    key: &[u8; AES_KEY_LEN],
    block: &[u8; AES_BLOCK],
) -> [u8; AES_BLOCK] {
    let cipher = <aes::Aes256 as KeyInit>::new(key.into());
    let mut buffer = *block;
    cipher.encrypt_block((&mut buffer).into());
    buffer
}

/// AES-256-CMAC producing the full sixteen-byte tag.
#[must_use]
pub fn aes256_cmac(key: &[u8; AES_KEY_LEN], message: &[u8]) -> [u8; AES_BLOCK] {
    let mut mac = <Cmac<aes::Aes256> as KeyInit>::new(key.into());
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0_u8; AES_BLOCK];
    out.copy_from_slice(&tag);
    out
}

/// AES-256-CMAC truncated to the secure-messaging length, in the typed
/// container that keeps it from standing in for a full tag.
#[must_use]
pub fn aes256_cmac_truncated(key: &[u8; AES_KEY_LEN], message: &[u8]) -> Mac<CmacAesTruncated> {
    let full = aes256_cmac(key, message);
    Mac::new(full[..CMAC_TAG_TRUNCATED].to_vec())
}

#[cfg(test)]
mod tests {
    use super::{
        AES_BLOCK, AES_KEY_LEN, Aes256Key, KdfParam, aes256_cbc_decrypt_no_padding,
        aes256_cbc_encrypt_no_padding, aes256_cmac, aes256_ecb_encrypt_block, kdf_aes256,
    };

    /// AES-256 key from NIST SP 800-38B Example 4 and SP 800-38A
    /// section F.1.5.
    const NIST_KEY: [u8; AES_KEY_LEN] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77,
        0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14,
        0xDF, 0xF4,
    ];
    /// First example message block from the same vector sets.
    const NIST_BLOCK_M1: [u8; AES_BLOCK] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A,
    ];
    /// Expected AES-256-CMAC of the empty message (SP 800-38B Example 4).
    const NIST_CMAC_EMPTY: [u8; AES_BLOCK] = [
        0x02, 0x89, 0x62, 0xF6, 0x1B, 0x7B, 0xF8, 0x9E, 0xFC, 0x6B, 0x55, 0x1F, 0x46, 0x67, 0xD9,
        0x83,
    ];
    /// Expected AES-256-CMAC of the one-block message.
    const NIST_CMAC_M1: [u8; AES_BLOCK] = [
        0x28, 0xA7, 0x02, 0x3F, 0x45, 0x2E, 0x8F, 0x82, 0xBD, 0x4B, 0xF2, 0x8D, 0x8C, 0x37, 0xC3,
        0x5C,
    ];
    /// Expected AES-256-ECB of the one-block message (SP 800-38A F.1.5).
    const NIST_ECB_M1: [u8; AES_BLOCK] = [
        0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81,
        0xF8,
    ];

    /// Non-sentinel test key filler.
    const TEST_KEY_FILL: u8 = 0x42;
    /// Non-sentinel test initialisation-vector filler.
    const TEST_IV_FILL: u8 = 0x77;

    #[test]
    fn cmac_matches_nist_vectors() {
        assert_eq!(aes256_cmac(&NIST_KEY, b""), NIST_CMAC_EMPTY);
        assert_eq!(aes256_cmac(&NIST_KEY, &NIST_BLOCK_M1), NIST_CMAC_M1);
    }

    #[test]
    fn ecb_matches_the_nist_vector() {
        assert_eq!(
            aes256_ecb_encrypt_block(&NIST_KEY, &NIST_BLOCK_M1),
            NIST_ECB_M1
        );
    }

    #[test]
    fn cbc_round_trips() {
        let key = [TEST_KEY_FILL; AES_KEY_LEN];
        let iv = [TEST_IV_FILL; AES_BLOCK];
        let plaintext = b"this is one block this is two   ".to_vec();
        let round_tripped = aes256_cbc_encrypt_no_padding(&key, &iv, &plaintext)
            .and_then(|cipher| aes256_cbc_decrypt_no_padding(&key, &iv, &cipher));
        assert_eq!(round_tripped, Ok(plaintext));
    }

    #[test]
    fn kdf_distinguishes_the_counters() {
        let material = b"shared secret bytes";
        let enc = kdf_aes256(material, KdfParam::Encryption);
        let mac = kdf_aes256(material, KdfParam::Mac);
        let password = kdf_aes256(material, KdfParam::Password);
        let enc_again = kdf_aes256(material, KdfParam::Encryption);
        assert_eq!(enc.as_bytes(), enc_again.as_bytes());
        let enc_differs_from_mac = enc.as_bytes() != mac.as_bytes();
        let enc_differs_from_password = enc.as_bytes() != password.as_bytes();
        let mac_differs_from_password = mac.as_bytes() != password.as_bytes();
        assert!(enc_differs_from_mac);
        assert!(enc_differs_from_password);
        assert!(mac_differs_from_password);
    }

    #[test]
    fn from_bytes_rejects_sentinel_keys() {
        assert!(Aes256Key::from_bytes([0_u8; AES_KEY_LEN]).is_none());
        assert!(Aes256Key::from_bytes([u8::MAX; AES_KEY_LEN]).is_none());
        let mut almost_zero = [0_u8; AES_KEY_LEN];
        almost_zero[AES_KEY_LEN - 1] = 1;
        assert!(Aes256Key::from_bytes(almost_zero).is_some());
    }
}
