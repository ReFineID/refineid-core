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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Positive PIN1 session caching and negative PIN retry protection for PKCS#11.

use core::time::Duration;
use std::time::Instant;

use refineid_auth::{Pin1, UnvalidatedSecret};
use refineid_pkcs15::TokenSerial;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pin::PinBytes;

/// Maximum lifetime of a positively cached PIN1, refreshed on each use.
pub const PIN1_CACHE_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Retention policy for positively cached PIN1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin1Retention {
    /// Reusable session cache (15 minutes).
    Reusable,
    /// One-shot bridge for C_Login -> immediate use (30 seconds).
    OneShot,
}

impl Pin1Retention {
    /// Lifetime for this retention tier.
    #[must_use]
    pub const fn lifetime(self) -> Duration {
        match self {
            Self::Reusable => PIN1_CACHE_LIFETIME,
            Self::OneShot => Duration::from_secs(30),
        }
    }
}

struct CachedPin1 {
    serial: TokenSerial,
    pin: PinBytes,
    last_successful_use: Instant,
    generation: u64,
    retention: Pin1Retention,
}

/// Destructively checked-out PIN1 state for one live card serial.
pub struct CheckedOutPin1 {
    entry: CachedPin1,
}

impl CheckedOutPin1 {
    /// Borrow the PIN for the single VERIFY associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Restore this entry and refresh its idle deadline after definite
    /// card-side success.
    pub fn restore_after_success(mut self, cache: &mut PinSafetyCache) {
        if self.entry.retention == Pin1Retention::OneShot {
            return;
        }
        if cache.generation != self.entry.generation || cache.positive_pin1.is_some() {
            return;
        }
        self.entry.last_successful_use = Instant::now();
        cache.positive_pin1 = Some(self.entry);
    }
}

impl core::fmt::Debug for CheckedOutPin1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedOutPin1")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

/// Rejection error when caching a PIN that was previously rejected by the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviouslyRejectedPin;

impl core::fmt::Display for PreviouslyRejectedPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PIN value was previously rejected by this token")
    }
}

impl core::error::Error for PreviouslyRejectedPin {}

/// Positive PIN1 session cache plus process-lifetime negative PIN cache.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinSafetyCache {
    #[zeroize(skip)]
    positive_pin1: Option<CachedPin1>,
    generation: u64,
    #[zeroize(skip)]
    negative: refineid_pin_cache::PinSafetyCache,
}

impl PinSafetyCache {
    /// Construct a fresh cache.
    ///
    /// # Errors
    /// Returns OS random-source error if fingerprint key generation fails.
    pub fn new() -> Result<Self, getrandom::Error> {
        Ok(Self {
            positive_pin1: None,
            generation: 0,
            negative: refineid_pin_cache::PinSafetyCache::new()?,
        })
    }

    /// Positively cache a just-verified PIN1 for reusable session lifetime.
    ///
    /// # Errors
    /// Returns [`PreviouslyRejectedPin`] if this PIN was previously recorded as rejected.
    pub fn store_pin1(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, &pin) {
            return Err(PreviouslyRejectedPin);
        }
        self.generation = self.generation.saturating_add(1);
        self.positive_pin1 = Some(CachedPin1 {
            serial,
            pin,
            last_successful_use: Instant::now(),
            generation: self.generation,
            retention: Pin1Retention::Reusable,
        });
        Ok(())
    }

    /// Stage a just-verified PIN1 for exactly one checkout.
    ///
    /// # Errors
    /// Returns [`PreviouslyRejectedPin`] if this PIN was previously recorded as rejected.
    pub fn stage_pin1_once(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, &pin) {
            return Err(PreviouslyRejectedPin);
        }
        self.generation = self.generation.saturating_add(1);
        self.positive_pin1 = Some(CachedPin1 {
            serial,
            pin,
            last_successful_use: Instant::now(),
            generation: self.generation,
            retention: Pin1Retention::OneShot,
        });
        Ok(())
    }

    /// Store a successfully verified PIN1 for this card serial.
    pub fn remember_pin1(&mut self, serial: &TokenSerial, pin: PinBytes) {
        let _ = self.store_pin1(serial.clone(), pin);
    }

    /// Check out the cached PIN1 for `serial`.
    #[must_use]
    pub fn checkout_pin1(&mut self, serial: &TokenSerial) -> Option<CheckedOutPin1> {
        let entry = self.positive_pin1.take()?;
        if &entry.serial != serial {
            return None;
        }
        if entry.last_successful_use.elapsed() > entry.retention.lifetime() {
            return None;
        }
        Some(CheckedOutPin1 { entry })
    }

    /// Drop any positively cached PIN1.
    pub fn clear_positive(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.positive_pin1 = None;
    }

    /// Drop positively cached PIN1 if it belongs to `serial`.
    pub fn clear_positive_for_serial(&mut self, serial: &TokenSerial) {
        if let Some(entry) = &self.positive_pin1
            && &entry.serial == serial
        {
            self.clear_positive();
        }
    }

    /// Whether unexpired positive PIN1 state exists.
    pub fn has_positive_pin1(&mut self) -> bool {
        let now = Instant::now();
        let live = self.positive_pin1.as_ref().is_some_and(|entry| {
            now.checked_duration_since(entry.last_successful_use)
                .is_some_and(|age| age < entry.retention.lifetime())
        });
        if !live {
            self.clear_positive();
        }
        live
    }

    /// Whether `pin` was previously rejected by the card identified by `serial`.
    #[must_use]
    pub fn is_rejected(&self, serial: &TokenSerial, pin: &PinBytes) -> bool {
        let secret = UnvalidatedSecret::from_owned_bytes(pin.as_bytes().to_vec());
        if let Ok(pin1) = Pin1::reconstruct(secret) {
            self.negative.is_rejected(serial, &pin1)
        } else {
            false
        }
    }

    /// Record a card-rejected PIN1 value.
    pub fn record_rejected(&mut self, serial: &TokenSerial, pin: &PinBytes) {
        self.clear_positive_for_serial(serial);
        let secret = UnvalidatedSecret::from_owned_bytes(pin.as_bytes().to_vec());
        if let Ok(pin1) = Pin1::reconstruct(secret) {
            self.negative.record_rejected(serial, &pin1);
        }
    }
}

impl core::fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("has_positive_pin1", &self.positive_pin1.is_some())
            .field("negative", &self.negative)
            .finish()
    }
}
