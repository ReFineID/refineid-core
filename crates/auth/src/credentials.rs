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

//! Refined PIN input types.
//!
//! Raw input exists only in [`UnvalidatedSecret`]. Consuming construction
//! validates the candidate and reconstructs a fixed-capacity, role-specific
//! value. The resulting types are not `Clone`, `Copy`, serializable, or
//! raw-debuggable.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::verify::PinSlot;

/// Minimum PIN1 length from FINEID S4-1 v4.2 section 4.1.
pub const PIN1_MIN_LENGTH: usize = 4;
/// Minimum PIN2 length from FINEID S4-1 v4.2 section 4.1.
pub const PIN2_MIN_LENGTH: usize = 6;
/// Stored length for both PIN roles from FINEID S4-1 v4.2 section 4.1.
pub const PIN_MAX_LENGTH: usize = 12;
/// Minimum PUK length from FINEID S4-1 v4.2 section 8.1.5 (EF.AOD): the
/// unblocking password is eight to twelve digits. The seven-digit
/// activation code a newer card ships with is a separate, single-use
/// credential -- not the PUK, and not what unblocks a PIN.
pub const PUK_MIN_LENGTH: usize = 8;
/// Maximum PUK length: the stored (padded) block length from FINEID S4-1
/// v4.2 section 8.1.5, as for the PIN roles.
pub const PUK_MAX_LENGTH: usize = 12;

/// Explicitly unvalidated secret bytes at an input boundary.
///
/// This is the only public type in this module that owns a byte vector. It
/// exists to make the raw state visible in the type system and zeroizes its
/// allocation on every exit path. It must be consumed to obtain a PIN role.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnvalidatedSecret {
    bytes: Vec<u8>,
}

impl UnvalidatedSecret {
    /// Take ownership of bytes read from a secure input surface.
    #[must_use]
    pub fn from_owned_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for UnvalidatedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnvalidatedSecret([redacted])")
    }
}

/// Credential role being reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRole {
    /// PIN protecting authentication-key signing and decipher operations.
    Pin1,
    /// Qualified-signature PIN.
    Pin2,
    /// PIN Unblocking Key: resets a blocked PIN's retry counter while
    /// setting a new value. It never authorises an operation, and it
    /// spends its own counter.
    Puk,
}

impl fmt::Display for CredentialRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pin1 => f.write_str("PIN1"),
            Self::Pin2 => f.write_str("PIN2"),
            Self::Puk => f.write_str("PUK"),
        }
    }
}

/// Structural reason that secret input was rejected.
///
/// The error reports shape only. It never contains the rejected byte or any
/// credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialInputError {
    /// No bytes were supplied.
    Empty {
        /// Role that was being reconstructed.
        role: CredentialRole,
    },
    /// Candidate length was outside the role's accepted range.
    WrongLength {
        /// Role that was being reconstructed.
        role: CredentialRole,
        /// Minimum accepted digit count.
        expected_min: usize,
        /// Maximum accepted digit count.
        expected_max: usize,
        /// Candidate digit count.
        got: usize,
    },
    /// Candidate contained a non-ASCII-digit byte.
    NonDigit {
        /// Role that was being reconstructed.
        role: CredentialRole,
        /// Offset of the rejected byte. The byte itself is not retained.
        at: usize,
    },
}

#[derive(Zeroize)]
struct SecretDigits {
    bytes: [u8; PIN_MAX_LENGTH],
    length: u8,
}

impl SecretDigits {
    fn reconstruct(
        input: UnvalidatedSecret,
        role: CredentialRole,
        minimum: usize,
        maximum: usize,
    ) -> Result<Self, CredentialInputError> {
        if input.bytes.is_empty() {
            return Err(CredentialInputError::Empty { role });
        }
        if input.bytes.len() < minimum || input.bytes.len() > maximum {
            return Err(CredentialInputError::WrongLength {
                role,
                expected_min: minimum,
                expected_max: maximum,
                got: input.bytes.len(),
            });
        }
        if let Some(at) = input.bytes.iter().position(|byte| !byte.is_ascii_digit()) {
            return Err(CredentialInputError::NonDigit { role, at });
        }
        let length = match u8::try_from(input.bytes.len()) {
            Ok(length) => length,
            Err(_) => {
                return Err(CredentialInputError::WrongLength {
                    role,
                    expected_min: minimum,
                    expected_max: maximum,
                    got: input.bytes.len(),
                });
            }
        };

        let mut reconstructed = [0_u8; PIN_MAX_LENGTH];
        reconstructed[..input.bytes.len()].copy_from_slice(&input.bytes);
        Ok(Self {
            bytes: reconstructed,
            length,
        })
    }

    const fn digit_count(&self) -> usize {
        self.length as usize
    }

    fn secret_bytes(&self) -> &[u8] {
        &self.bytes[..self.digit_count()]
    }
}

/// Validated PIN1 value.
///
/// The type deliberately does not implement `Clone`, `Copy`, serialization,
/// or a raw-byte accessor. Future credential APDU construction will consume
/// this value through a crate-private, zeroizing path. A fresh, manually
/// entered PIN1 remains mandatory for each private-key signing operation.
#[derive(ZeroizeOnDrop)]
pub struct Pin1(SecretDigits);

impl Pin1 {
    /// Consume unvalidated input and reconstruct a PIN1.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] unless the input is
    /// [`PIN1_MIN_LENGTH`] through [`PIN_MAX_LENGTH`] ASCII digits.
    pub fn reconstruct(input: UnvalidatedSecret) -> Result<Self, CredentialInputError> {
        SecretDigits::reconstruct(input, CredentialRole::Pin1, PIN1_MIN_LENGTH, PIN_MAX_LENGTH)
            .map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    /// Borrow the validated digits for the verification command builder.
    ///
    /// This is the crate-private path the PIN operations consume PIN1
    /// through: the digits never leave this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn digits(&self) -> &[u8] {
        self.0.secret_bytes()
    }
}

impl fmt::Debug for Pin1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin1([redacted])")
    }
}

/// Validated PIN2 value.
///
/// PIN2 retention is bounded by the one-minute qualified-signature
/// convenience window in the credential custody contract. The type
/// deliberately does not implement `Clone`, `Copy`, serialization, or a
/// raw-byte accessor.
#[derive(ZeroizeOnDrop)]
pub struct Pin2(SecretDigits);

impl Pin2 {
    /// Consume unvalidated input and reconstruct a PIN2.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] unless the input is
    /// [`PIN2_MIN_LENGTH`] through [`PIN_MAX_LENGTH`] ASCII digits.
    pub fn reconstruct(input: UnvalidatedSecret) -> Result<Self, CredentialInputError> {
        SecretDigits::reconstruct(input, CredentialRole::Pin2, PIN2_MIN_LENGTH, PIN_MAX_LENGTH)
            .map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    /// Borrow the validated digits for the verification command builder.
    ///
    /// This is the crate-private path the PIN operations consume PIN2
    /// through: the digits never leave this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn digits(&self) -> &[u8] {
        self.0.secret_bytes()
    }
}

impl fmt::Debug for Pin2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin2([redacted])")
    }
}

mod sealed {
    /// Seals [`CachedPin`] so only this crate's PIN roles can implement it.
    pub trait Sealed {}
    impl Sealed for super::Pin1 {}
    impl Sealed for super::Pin2 {}
}

/// A PIN role whose card rejection a negative cache may remember.
///
/// Sealed: implemented only for [`Pin1`] and [`Pin2`]. The PUK is
/// deliberately excluded -- it authorises nothing, spends its own retry
/// counter, and has no cache path.
///
/// The digits are reachable only through the scoped
/// [`with_digits`](Self::with_digits) borrow -- the same custody idiom as
/// the credential-command wire. They are lent for one call so a keyed
/// fingerprint can absorb them, and are never handed out as an owned
/// value; there is still no public `as_bytes` on a PIN role.
pub trait CachedPin: sealed::Sealed {
    /// The slot this PIN targets.
    #[must_use]
    fn slot(&self) -> PinSlot;

    /// Number of validated digits.
    #[must_use]
    fn digit_count(&self) -> usize;

    /// Lend the validated digits to `read` for one call. The reader must
    /// absorb them (for example into a keyed fingerprint) and must not
    /// retain them.
    fn with_digits<R>(&self, read: impl FnOnce(&[u8]) -> R) -> R;
}

impl CachedPin for Pin1 {
    fn slot(&self) -> PinSlot {
        PinSlot::Pin1
    }

    fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    fn with_digits<R>(&self, read: impl FnOnce(&[u8]) -> R) -> R {
        read(self.digits())
    }
}

impl CachedPin for Pin2 {
    fn slot(&self) -> PinSlot {
        PinSlot::Pin2
    }

    fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    fn with_digits<R>(&self, read: impl FnOnce(&[u8]) -> R) -> R {
        read(self.digits())
    }
}

/// Validated PUK value.
///
/// The PUK is not a PIN: it never authorises an operation on the user's
/// behalf. It resets a blocked PIN's retry counter while setting a new
/// value (RESET RETRY COUNTER, FINEID S1 v4.2 section 3.5.4). The PUK
/// spends its own retry counter, and exhausting it is terminal for the
/// card, so a caller holds its retry floor against the PUK's counter, not
/// the target PIN's. Like the PIN roles, this type is not `Clone`, `Copy`,
/// serializable, or raw-debuggable, and there is no cache path.
#[derive(ZeroizeOnDrop)]
pub struct Puk(SecretDigits);

impl Puk {
    /// Consume unvalidated input and reconstruct a PUK.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] unless the input is
    /// [`PUK_MIN_LENGTH`] through [`PUK_MAX_LENGTH`] ASCII digits.
    pub fn reconstruct(input: UnvalidatedSecret) -> Result<Self, CredentialInputError> {
        SecretDigits::reconstruct(input, CredentialRole::Puk, PUK_MIN_LENGTH, PUK_MAX_LENGTH)
            .map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    /// Borrow the validated digits for the credential-command builder.
    ///
    /// This is the crate-private path the unblock operations consume the
    /// PUK through: the digits never leave this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn digits(&self) -> &[u8] {
        self.0.secret_bytes()
    }
}

impl fmt::Debug for Puk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Puk([redacted])")
    }
}

impl fmt::Display for CredentialInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { role } => write!(f, "{role} cannot be empty"),
            Self::WrongLength {
                role,
                expected_min,
                expected_max,
                got,
            } => write!(
                f,
                "{role} must contain {expected_min}-{expected_max} digits, got {got}"
            ),
            Self::NonDigit { role, at } => {
                write!(
                    f,
                    "{role} must contain ASCII digits; non-digit at offset {at}"
                )
            }
        }
    }
}

impl core::error::Error for CredentialInputError {}

#[cfg(test)]
mod tests {
    use super::{
        CredentialInputError, CredentialRole, PIN_MAX_LENGTH, PIN1_MIN_LENGTH, PIN2_MIN_LENGTH,
        PUK_MAX_LENGTH, PUK_MIN_LENGTH, Pin1, Pin2, Puk, UnvalidatedSecret,
    };
    use zeroize::Zeroize;

    const NON_DIGIT_OFFSET: usize = 2;
    const PIN1_TOO_SHORT_LENGTH: usize = PIN1_MIN_LENGTH - 1;
    const PIN2_TOO_SHORT_LENGTH: usize = PIN2_MIN_LENGTH - 1;
    const TOO_LONG_LENGTH: usize = PIN_MAX_LENGTH + 1;
    const PUK_TOO_SHORT_LENGTH: usize = PUK_MIN_LENGTH - 1;
    const PUK_TOO_LONG_LENGTH: usize = PUK_MAX_LENGTH + 1;

    fn input(bytes: &[u8]) -> UnvalidatedSecret {
        UnvalidatedSecret::from_owned_bytes(bytes.to_vec())
    }

    fn digits(length: usize) -> UnvalidatedSecret {
        UnvalidatedSecret::from_owned_bytes(vec![b'7'; length])
    }

    fn non_ascii_digits(length: usize) -> UnvalidatedSecret {
        let mut bytes = vec![b'7'; length];
        let last = bytes.last_mut().expect("fixture length is non-zero");
        *last = u8::MAX;
        UnvalidatedSecret::from_owned_bytes(bytes)
    }

    #[test]
    fn role_types_reconstruct_valid_input() {
        let pin1 = Pin1::reconstruct(input(b"1234")).expect("valid PIN1 fixture");
        let pin2 = Pin2::reconstruct(input(b"123456")).expect("valid PIN2 fixture");

        assert_eq!(pin1.digit_count(), PIN1_MIN_LENGTH);
        assert_eq!(pin1.0.secret_bytes(), b"1234");
        assert_eq!(pin2.digit_count(), PIN2_MIN_LENGTH);
        assert_eq!(pin2.0.secret_bytes(), b"123456");
    }

    #[test]
    fn role_specific_minimums_are_enforced() {
        let error = Pin2::reconstruct(input(b"1234")).expect_err("fixture is too short for PIN2");
        assert_eq!(
            error,
            CredentialInputError::WrongLength {
                role: CredentialRole::Pin2,
                expected_min: PIN2_MIN_LENGTH,
                expected_max: super::PIN_MAX_LENGTH,
                got: PIN1_MIN_LENGTH,
            }
        );
    }

    #[test]
    fn pin1_boundary_lengths_are_enforced() {
        assert!(matches!(
            Pin1::reconstruct(input(b"")),
            Err(CredentialInputError::Empty {
                role: CredentialRole::Pin1,
            })
        ));
        assert!(matches!(
            Pin1::reconstruct(digits(PIN1_TOO_SHORT_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin1,
                expected_min: PIN1_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
                got: PIN1_TOO_SHORT_LENGTH,
            })
        ));
        assert!(Pin1::reconstruct(digits(PIN1_MIN_LENGTH)).is_ok());
        assert!(Pin1::reconstruct(digits(PIN_MAX_LENGTH)).is_ok());
        assert!(matches!(
            Pin1::reconstruct(digits(TOO_LONG_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin1,
                expected_min: PIN1_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
                got: TOO_LONG_LENGTH,
            })
        ));
        assert!(matches!(
            Pin1::reconstruct(non_ascii_digits(PIN1_MIN_LENGTH)),
            Err(CredentialInputError::NonDigit {
                role: CredentialRole::Pin1,
                ..
            })
        ));
    }

    #[test]
    fn pin2_boundary_lengths_are_enforced() {
        assert!(matches!(
            Pin2::reconstruct(input(b"")),
            Err(CredentialInputError::Empty {
                role: CredentialRole::Pin2,
            })
        ));
        assert!(matches!(
            Pin2::reconstruct(digits(PIN2_TOO_SHORT_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin2,
                expected_min: PIN2_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
                got: PIN2_TOO_SHORT_LENGTH,
            })
        ));
        assert!(Pin2::reconstruct(digits(PIN2_MIN_LENGTH)).is_ok());
        assert!(Pin2::reconstruct(digits(PIN_MAX_LENGTH)).is_ok());
        assert!(matches!(
            Pin2::reconstruct(digits(TOO_LONG_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin2,
                expected_min: PIN2_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
                got: TOO_LONG_LENGTH,
            })
        ));
        assert!(matches!(
            Pin2::reconstruct(non_ascii_digits(PIN2_MIN_LENGTH)),
            Err(CredentialInputError::NonDigit {
                role: CredentialRole::Pin2,
                ..
            })
        ));
    }

    #[test]
    fn puk_boundary_lengths_are_enforced() {
        assert!(matches!(
            Puk::reconstruct(input(b"")),
            Err(CredentialInputError::Empty {
                role: CredentialRole::Puk,
            })
        ));
        assert!(matches!(
            Puk::reconstruct(digits(PUK_TOO_SHORT_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Puk,
                expected_min: PUK_MIN_LENGTH,
                expected_max: PUK_MAX_LENGTH,
                got: PUK_TOO_SHORT_LENGTH,
            })
        ));
        assert!(Puk::reconstruct(digits(PUK_MIN_LENGTH)).is_ok());
        assert!(Puk::reconstruct(digits(PUK_MAX_LENGTH)).is_ok());
        assert!(matches!(
            Puk::reconstruct(digits(PUK_TOO_LONG_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Puk,
                expected_min: PUK_MIN_LENGTH,
                expected_max: PUK_MAX_LENGTH,
                got: PUK_TOO_LONG_LENGTH,
            })
        ));
        assert!(matches!(
            Puk::reconstruct(non_ascii_digits(PUK_MIN_LENGTH)),
            Err(CredentialInputError::NonDigit {
                role: CredentialRole::Puk,
                ..
            })
        ));
        let puk = Puk::reconstruct(digits(PUK_MAX_LENGTH)).expect("valid PUK fixture");
        assert_eq!(puk.digit_count(), PUK_MAX_LENGTH);
        assert_eq!(format!("{puk:?}"), "Puk([redacted])");
    }

    #[test]
    fn errors_never_retain_the_rejected_byte() {
        let error =
            Pin1::reconstruct(input(b"12a4")).expect_err("fixture contains a non-digit byte");
        assert_eq!(
            error,
            CredentialInputError::NonDigit {
                role: CredentialRole::Pin1,
                at: NON_DIGIT_OFFSET,
            }
        );
    }

    #[test]
    fn debug_is_always_redacted() {
        let raw = input(b"1234");
        assert_eq!(format!("{raw:?}"), "UnvalidatedSecret([redacted])");

        let pin1 = Pin1::reconstruct(input(b"1234")).expect("valid PIN1 fixture");
        assert_eq!(format!("{pin1:?}"), "Pin1([redacted])");

        let pin2 = Pin2::reconstruct(input(b"123456")).expect("valid PIN2 fixture");
        assert_eq!(format!("{pin2:?}"), "Pin2([redacted])");
    }

    #[test]
    fn unvalidated_storage_is_zeroizable() {
        let mut raw = input(b"1234");
        raw.zeroize();
        assert!(raw.bytes.iter().all(|byte| *byte == 0));
    }
}
