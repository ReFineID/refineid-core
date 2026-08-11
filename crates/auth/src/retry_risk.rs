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

//! FINEID PIN retry-risk states and the consumer safety floors.
//!
//! FINEID PINs allow five attempts before locking. The risk states
//! below map the live retry counter to a severity, and the permission
//! predicates encode one floor: refuse to spend a PIN at one or two
//! attempts remaining, so this software never spends the next-to-last
//! or last attempt and a lockout is never its doing. Every other state
//! passes, including a zero-attempt card -- nothing left to protect.
//! Arming a reusable authentication cache is separate and stricter: it
//! requires a pristine five-attempt state.

use refineid_apdu::PinRetries;

use crate::verify::PinStatus;

/// Retry count of a pristine FINEID PIN.
const RETRIES_PRISTINE: u8 = 5;
/// Retry count after one wrong attempt.
const RETRIES_ONE_SPENT: u8 = 4;
/// Retry count at the consumer floor.
const RETRIES_FLOOR: u8 = 3;
/// Retry count below the consumer floor.
const RETRIES_BELOW_FLOOR: u8 = 2;

/// Severity derived from the FINEID five-attempt PIN counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRetryRisk {
    /// Five attempts remain: normal operating conditions.
    NormalOperatingConditions,
    /// Four attempts remain: a disturbance was detected.
    DisturbanceDetected,
    /// Three attempts remain: a security incident is declared.
    SecurityIncidentDeclared,
    /// Two attempts remain: the blocked band -- no PIN is spent here.
    CriticalThreatLevel,
    /// One attempt remains: a credential lockout is imminent.
    LockdownImminent,
    /// No attempts remain: the credential is locked.
    DefencesFallen,
}

impl PinRetryRisk {
    /// Classify a FINEID retry counter. A value above the five-attempt
    /// limit is rejected rather than assigned a misleading state.
    #[must_use]
    pub const fn from_retries(retries: PinRetries) -> Option<Self> {
        match retries.get() {
            RETRIES_PRISTINE => Some(Self::NormalOperatingConditions),
            RETRIES_ONE_SPENT => Some(Self::DisturbanceDetected),
            RETRIES_FLOOR => Some(Self::SecurityIncidentDeclared),
            RETRIES_BELOW_FLOOR => Some(Self::CriticalThreatLevel),
            1 => Some(Self::LockdownImminent),
            0 => Some(Self::DefencesFallen),
            _ => None,
        }
    }

    /// The one blocked band is one or two attempts remaining; every other
    /// state passes, including an already-locked card. Refusing exactly
    /// `{1, 2}` keeps this software from spending the next-to-last or last
    /// attempt, so a lockout is never its doing.
    #[must_use]
    pub const fn permits_compatibility_module(self) -> bool {
        !matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
    }

    /// Ordinary graphical and system interfaces block the same one-or-two
    /// band and pass everything else. See
    /// [`Self::permits_compatibility_module`].
    #[must_use]
    pub const fn permits_consumer(self) -> bool {
        !matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
    }

    /// A reusable authentication cache requires a pristine five-attempt
    /// state -- a separate, stricter gate for arming the cache, not the
    /// operate floor.
    #[must_use]
    pub const fn permits_reusable_cache(self) -> bool {
        matches!(self, Self::NormalOperatingConditions)
    }
}

/// Whether a live PIN1 status permits an ordinary consumer
/// authentication operation.
///
/// A verified PIN1 is safe because the card has already accepted it in
/// the current security context. Unknown, malformed, and locked states
/// fail closed.
#[must_use]
pub const fn pin1_status_permits_consumer_authentication(pin1: PinStatus) -> bool {
    match pin1 {
        PinStatus::Verified => true,
        PinStatus::Remaining(retries) => matches!(
            PinRetryRisk::from_retries(retries),
            Some(risk) if risk.permits_consumer()
        ),
        PinStatus::Locked | PinStatus::NoInfo | PinStatus::Other(_) => false,
    }
}

/// Whether PIN1 may be retained in a reusable authentication cache.
#[must_use]
pub const fn pin1_status_permits_reusable_cache(pin1: PinStatus) -> bool {
    matches!(
        pin1,
        PinStatus::Remaining(retries)
            if matches!(
                PinRetryRisk::from_retries(retries),
                Some(risk) if risk.permits_reusable_cache()
            )
    )
}

#[cfg(test)]
mod tests {
    use super::{
        PinRetryRisk, PinStatus, RETRIES_BELOW_FLOOR, RETRIES_FLOOR, RETRIES_ONE_SPENT,
        RETRIES_PRISTINE, pin1_status_permits_consumer_authentication,
        pin1_status_permits_reusable_cache,
    };
    use refineid_apdu::{PinRetries, StatusWord};

    /// One above the five-attempt limit, for the rejection test.
    const ABOVE_LIMIT: u8 = 6;
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;

    fn risk(retries: u8) -> Option<PinRetryRisk> {
        PinRetries::from_nibble(retries).and_then(PinRetryRisk::from_retries)
    }

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(PinRetries::from_nibble(count).expect("fits a nibble"))
    }

    #[test]
    fn the_five_attempt_ladder_is_total() {
        assert_eq!(
            risk(RETRIES_PRISTINE),
            Some(PinRetryRisk::NormalOperatingConditions)
        );
        assert_eq!(
            risk(RETRIES_ONE_SPENT),
            Some(PinRetryRisk::DisturbanceDetected)
        );
        assert_eq!(
            risk(RETRIES_FLOOR),
            Some(PinRetryRisk::SecurityIncidentDeclared)
        );
        assert_eq!(
            risk(RETRIES_BELOW_FLOOR),
            Some(PinRetryRisk::CriticalThreatLevel)
        );
        assert_eq!(risk(1), Some(PinRetryRisk::LockdownImminent));
        assert_eq!(risk(0), Some(PinRetryRisk::DefencesFallen));
        assert_eq!(risk(ABOVE_LIMIT), None);
    }

    #[test]
    fn the_floors_follow_the_ladder() {
        assert!(PinRetryRisk::NormalOperatingConditions.permits_reusable_cache());
        assert!(!PinRetryRisk::DisturbanceDetected.permits_reusable_cache());
        // The operate floor passes every state except one or two attempts,
        // including an already-locked card.
        assert!(PinRetryRisk::SecurityIncidentDeclared.permits_compatibility_module());
        assert!(PinRetryRisk::DefencesFallen.permits_compatibility_module());
        assert!(!PinRetryRisk::CriticalThreatLevel.permits_compatibility_module());
        assert!(!PinRetryRisk::LockdownImminent.permits_compatibility_module());
        assert!(PinRetryRisk::SecurityIncidentDeclared.permits_consumer());
        assert!(PinRetryRisk::DefencesFallen.permits_consumer());
        assert!(!PinRetryRisk::CriticalThreatLevel.permits_consumer());
        assert!(!PinRetryRisk::LockdownImminent.permits_consumer());
    }

    #[test]
    fn consumer_authentication_depends_only_on_the_pin1_floor() {
        assert!(pin1_status_permits_consumer_authentication(remaining(
            RETRIES_PRISTINE
        )));
        assert!(pin1_status_permits_consumer_authentication(remaining(
            RETRIES_FLOOR
        )));
        assert!(!pin1_status_permits_consumer_authentication(remaining(
            RETRIES_BELOW_FLOOR
        )));
        assert!(!pin1_status_permits_consumer_authentication(remaining(1)));
        // Zero attempts passes the floor -- nothing left to protect; the card
        // surfaces its locked state instead.
        assert!(pin1_status_permits_consumer_authentication(remaining(0)));
        assert!(pin1_status_permits_consumer_authentication(
            PinStatus::Verified
        ));
        assert!(!pin1_status_permits_consumer_authentication(
            PinStatus::Locked
        ));
        assert!(!pin1_status_permits_consumer_authentication(
            PinStatus::NoInfo
        ));
        assert!(!pin1_status_permits_consumer_authentication(
            PinStatus::Other(StatusWord::from_u16(UNMODELED_SW))
        ));
    }

    #[test]
    fn a_reusable_cache_requires_a_pristine_pin1() {
        assert!(pin1_status_permits_reusable_cache(remaining(
            RETRIES_PRISTINE
        )));
        assert!(!pin1_status_permits_reusable_cache(remaining(
            RETRIES_ONE_SPENT
        )));
        assert!(!pin1_status_permits_reusable_cache(remaining(
            RETRIES_FLOOR
        )));
        assert!(!pin1_status_permits_reusable_cache(PinStatus::Verified));
    }
}
