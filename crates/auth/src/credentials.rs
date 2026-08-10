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

/// Minimum PIN1 length from FINEID S4-1 v4.2 section 4.1.
pub const PIN1_MIN_LENGTH: usize = 4;
/// Minimum PIN2 length from FINEID S4-1 v4.2 section 4.1.
pub const PIN2_MIN_LENGTH: usize = 6;
/// Stored length for both PIN roles from FINEID S4-1 v4.2 section 4.1.
pub const PIN_MAX_LENGTH: usize = 12;

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
}

impl fmt::Display for CredentialRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pin1 => f.write_str("PIN1"),
            Self::Pin2 => f.write_str("PIN2"),
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
    ) -> Result<Self, CredentialInputError> {
        if input.bytes.is_empty() {
            return Err(CredentialInputError::Empty { role });
        }
        if input.bytes.len() < minimum || input.bytes.len() > PIN_MAX_LENGTH {
            return Err(CredentialInputError::WrongLength {
                role,
                expected_min: minimum,
                expected_max: PIN_MAX_LENGTH,
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
                    expected_max: PIN_MAX_LENGTH,
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

    #[cfg(test)]
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
        SecretDigits::reconstruct(input, CredentialRole::Pin1, PIN1_MIN_LENGTH).map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
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
        SecretDigits::reconstruct(input, CredentialRole::Pin2, PIN2_MIN_LENGTH).map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }
}

impl fmt::Debug for Pin2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin2([redacted])")
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
        Pin1, Pin2, UnvalidatedSecret,
    };
    use zeroize::Zeroize;

    const NON_DIGIT_OFFSET: usize = 2;
    const PIN1_TOO_SHORT_LENGTH: usize = PIN1_MIN_LENGTH - 1;
    const PIN2_TOO_SHORT_LENGTH: usize = PIN2_MIN_LENGTH - 1;
    const TOO_LONG_LENGTH: usize = PIN_MAX_LENGTH + 1;

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
