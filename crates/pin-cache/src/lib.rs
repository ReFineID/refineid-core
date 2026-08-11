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

//! Process-lifetime negative PIN cache.
//!
//! A PIN1 or PIN2 value that a card has rejected is remembered until the
//! process exits and refused locally thereafter, so software never re-offers a
//! known-bad value and burns another card retry. A rejected value is retained
//! only as a keyed fingerprint under fresh process-local random material; the
//! raw PIN bytes are never stored by this cache.
//!
//! The two cache-lifetime constants describe how long a host may retain a
//! positively verified PIN in its own upstream policy. They are read by a host;
//! this crate keeps no positive cache and consumes neither constant.

use core::time::Duration;

use hmac::{Hmac, KeyInit as _, Mac as _};
use refineid_auth::{CachedPin, PinSlot};
use refineid_pkcs15::TokenSerial;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PIN1 idle-session policy: a positively verified PIN1 may be retained upstream
/// for at most this many minutes, its window refreshed on each use.
const PIN1_CACHE_MINUTES: u64 = 15;

/// Maximum lifetime a host may keep a positively verified PIN1, refreshed on
/// each use -- an idle authentication-session window.
pub const PIN1_CACHE_LIFETIME: Duration = Duration::from_mins(PIN1_CACHE_MINUTES);

/// Maximum lifetime a host may keep a positively verified PIN2, measured from
/// entry and never refreshed -- a bounded consent window for one signing batch.
pub const PIN2_CACHE_LIFETIME: Duration = Duration::from_mins(1);

/// SHA-256 emits a 256-bit digest, so an HMAC-SHA-256 fingerprint is 32 bytes.
const FINGERPRINT_LEN: usize = 32;

/// The per-process HMAC-SHA-256 fingerprint key is 32 bytes (256 bits) drawn
/// from the operating-system random source.
const FINGERPRINT_KEY_LEN: usize = 32;

/// Domain-separation tag bound into the fingerprint preimage for the PIN1 slot.
const SLOT_TAG_PIN1: u8 = 1;

/// Domain-separation tag bound into the fingerprint preimage for the PIN2 slot.
const SLOT_TAG_PIN2: u8 = 2;

/// Opaque keyed mark standing in for one card-rejected PIN value. Erases
/// on drop, so a discarded candidate mark leaves no residue.
#[derive(Zeroize, ZeroizeOnDrop)]
struct RejectedPinFingerprint([u8; FINGERPRINT_LEN]);

/// Process-lifetime memory of PIN values a card has already rejected.
///
/// The cache never stores a raw PIN: a rejected value is represented only by an
/// HMAC-SHA-256 fingerprint keyed with fresh process-local random material, and
/// membership is tested in constant time. Because the key is unique per process,
/// fingerprints cannot be correlated across runs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinSafetyCache {
    fingerprint_key: [u8; FINGERPRINT_KEY_LEN],
    rejected_pin1: Vec<RejectedPinFingerprint>,
    rejected_pin2: Vec<RejectedPinFingerprint>,
}

impl PinSafetyCache {
    /// Construct an empty cache with a fresh process-local fingerprint key.
    ///
    /// # Errors
    /// Returns the operating-system random-source failure rather than creating a
    /// predictable rejection-fingerprint key.
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut fingerprint_key = [0_u8; FINGERPRINT_KEY_LEN];
        getrandom::fill(&mut fingerprint_key)?;
        Ok(Self {
            fingerprint_key,
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        })
    }

    /// Whether `pin` has already been rejected by the card identified by
    /// `serial`, for that PIN's own slot. The comparison runs in constant
    /// time.
    #[must_use]
    pub fn is_rejected(&self, serial: &TokenSerial, pin: &impl CachedPin) -> bool {
        let candidate = self.fingerprint(serial, pin);
        self.rejected(pin.slot())
            .iter()
            .any(|known| bool::from(known.0.ct_eq(&candidate.0)))
    }

    /// Remember a card-side wrong-PIN response for the rest of this process, so
    /// the same value is never offered again for this card and slot. A value
    /// already remembered is not stored twice.
    pub fn record_rejected(&mut self, serial: &TokenSerial, pin: &impl CachedPin) {
        let fingerprint = self.fingerprint(serial, pin);
        let rejected = self.rejected_mut(pin.slot());
        if !rejected
            .iter()
            .any(|known| bool::from(known.0.ct_eq(&fingerprint.0)))
        {
            rejected.push(fingerprint);
        }
    }

    /// HMAC-SHA-256 over a domain-separated preimage so that no two distinct
    /// (serial, slot, pin) triples share a mark: the serial length is bound as a
    /// fixed-width big-endian integer ahead of the serial, then a slot tag byte,
    /// then the pin length ahead of the pin. The pin digits are absorbed
    /// through the scoped [`CachedPin::with_digits`] borrow, never copied
    /// out.
    fn fingerprint(&self, serial: &TokenSerial, pin: &impl CachedPin) -> RejectedPinFingerprint {
        let slot_tag = match pin.slot() {
            PinSlot::Pin1 => SLOT_TAG_PIN1,
            PinSlot::Pin2 => SLOT_TAG_PIN2,
        };
        let serial_bytes = serial.as_str().as_bytes();
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.fingerprint_key) else {
            // A fixed-length HMAC-SHA-256 key is always valid. Fail closed if
            // that invariant ever breaks: every value then shares one mark and
            // is refused after the first rejection, never replayed to the card.
            return RejectedPinFingerprint([0_u8; FINGERPRINT_LEN]);
        };
        let Ok(serial_len) = u32::try_from(serial_bytes.len()) else {
            return RejectedPinFingerprint([0_u8; FINGERPRINT_LEN]);
        };
        let Ok(pin_len) = u8::try_from(pin.digit_count()) else {
            return RejectedPinFingerprint([0_u8; FINGERPRINT_LEN]);
        };
        mac.update(&serial_len.to_be_bytes());
        mac.update(serial_bytes);
        mac.update(&[slot_tag]);
        mac.update(&[pin_len]);
        pin.with_digits(|digits| mac.update(digits));
        RejectedPinFingerprint(mac.finalize().into_bytes().into())
    }

    fn rejected(&self, slot: PinSlot) -> &[RejectedPinFingerprint] {
        match slot {
            PinSlot::Pin1 => &self.rejected_pin1,
            PinSlot::Pin2 => &self.rejected_pin2,
        }
    }

    const fn rejected_mut(&mut self, slot: PinSlot) -> &mut Vec<RejectedPinFingerprint> {
        match slot {
            PinSlot::Pin1 => &mut self.rejected_pin1,
            PinSlot::Pin2 => &mut self.rejected_pin2,
        }
    }
}

impl core::fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("rejected_pin1_count", &self.rejected_pin1.len())
            .field("rejected_pin2_count", &self.rejected_pin2.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl PinSafetyCache {
    /// Install a fixed fingerprint key so tests observe deterministic marks.
    fn with_fixed_fingerprint_key(fingerprint_key: [u8; FINGERPRINT_KEY_LEN]) -> Self {
        Self {
            fingerprint_key,
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        }
    }

    /// How many rejection fingerprints are retained for `slot`.
    fn rejected_count(&self, slot: PinSlot) -> usize {
        self.rejected(slot).len()
    }
}

#[cfg(test)]
mod tests {
    use refineid_auth::{Pin1, Pin2, PinSlot, UnvalidatedSecret};
    use refineid_pkcs15::TokenSerial;

    use super::{FINGERPRINT_KEY_LEN, PinSafetyCache};

    /// Arbitrary fixed fingerprint-key byte, repeated across the key so that
    /// test fingerprints are reproducible without touching the OS random source.
    const TEST_FINGERPRINT_KEY_BYTE: u8 = 0xA5;

    /// Two distinct synthetic card serials.
    const CARD_A_SERIAL: &str = "CARD-A-FULL-SERIAL";
    const CARD_B_SERIAL: &str = "CARD-B-FULL-SERIAL";

    /// Two distinct synthetic PIN values, each valid for either PIN role.
    const PIN_VALUE: &str = "135790";
    const OTHER_PIN_VALUE: &str = "246802";

    fn cache() -> PinSafetyCache {
        PinSafetyCache::with_fixed_fingerprint_key([TEST_FINGERPRINT_KEY_BYTE; FINGERPRINT_KEY_LEN])
    }

    fn serial(text: &str) -> TokenSerial {
        TokenSerial::new(text.to_owned())
    }

    fn pin1(digits: &str) -> Pin1 {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(
            digits.as_bytes().to_vec(),
        ))
        .expect("valid PIN1 fixture")
    }

    fn pin2(digits: &str) -> Pin2 {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(
            digits.as_bytes().to_vec(),
        ))
        .expect("valid PIN2 fixture")
    }

    #[test]
    fn recorded_value_is_rejected_for_its_serial_and_slot() {
        let mut cache = cache();
        cache.record_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE));
        assert!(cache.is_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE)));
    }

    #[test]
    fn a_different_value_is_not_rejected() {
        let mut cache = cache();
        cache.record_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE));
        assert!(!cache.is_rejected(&serial(CARD_A_SERIAL), &pin1(OTHER_PIN_VALUE)));
    }

    #[test]
    fn a_different_slot_is_not_rejected() {
        let mut cache = cache();
        cache.record_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE));
        assert!(!cache.is_rejected(&serial(CARD_A_SERIAL), &pin2(PIN_VALUE)));
    }

    #[test]
    fn a_different_serial_is_not_rejected() {
        let mut cache = cache();
        cache.record_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE));
        assert!(!cache.is_rejected(&serial(CARD_B_SERIAL), &pin1(PIN_VALUE)));
    }

    #[test]
    fn recording_the_same_value_twice_is_deduped() {
        let mut cache = cache();
        cache.record_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE));
        cache.record_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE));
        assert_eq!(cache.rejected_count(PinSlot::Pin1), 1);
        assert!(cache.is_rejected(&serial(CARD_A_SERIAL), &pin1(PIN_VALUE)));
    }
}
