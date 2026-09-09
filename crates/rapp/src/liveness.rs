//! Authenticated session liveness with explicit exponential backoff.

use core::fmt;

use super::LIVENESS_CHALLENGE_SIZE;

/// Unpredictable caller-supplied ping value echoed by the peer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PingChallenge([u8; LIVENESS_CHALLENGE_SIZE]);

impl PingChallenge {
    /// Constructs a challenge from cryptographically random bytes supplied by
    /// the platform RNG.
    #[must_use]
    pub const fn reconstruct(bytes: [u8; LIVENESS_CHALLENGE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Challenge bytes sent in the authenticated ping body.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LIVENESS_CHALLENGE_SIZE] {
        &self.0
    }
}

impl fmt::Debug for PingChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PingChallenge([redacted])")
    }
}

/// Liveness timing policy expressed against an injected monotonic clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessConfig {
    /// Interval before the first idle probe.
    pub base_interval_ms: u64,
    /// Time allowed for an authenticated pong.
    pub response_timeout_ms: u64,
    /// Maximum retry interval after exponential backoff.
    pub maximum_interval_ms: u64,
    /// Maximum absolute caller-supplied jitter applied after a missed probe.
    pub maximum_jitter_ms: u64,
    /// Number of consecutive missed probes that closes the session.
    pub maximum_misses: u8,
}

impl LivenessConfig {
    /// Validates a policy. Timing values are policy inputs rather than hidden
    /// UI delays.
    ///
    /// # Errors
    /// [`LivenessError::InvalidConfiguration`] on a nonsensical timing or
    /// retry policy.
    pub const fn validate(self) -> Result<Self, LivenessError> {
        if self.base_interval_ms == 0
            || self.response_timeout_ms == 0
            || self.maximum_interval_ms < self.base_interval_ms
            || self.maximum_jitter_ms > self.base_interval_ms
            || self.maximum_misses == 0
        {
            return Err(LivenessError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[allow(
    variant_size_differences,
    reason = "AwaitingPong carries the 32-byte outstanding challenge; boxing a 47-byte variant buys nothing"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Waiting {
        next_probe_at_ms: u64,
        consecutive_misses: u8,
    },
    AwaitingPong {
        challenge: PingChallenge,
        deadline_ms: u64,
        consecutive_misses: u8,
    },
    Closed,
}

/// Session-local liveness tracker.
#[allow(
    missing_copy_implementations,
    reason = "one tracker per session; a copied tracker would fork liveness state"
)]
#[derive(Debug)]
pub struct LivenessTracker {
    config: LivenessConfig,
    phase: Phase,
}

impl LivenessTracker {
    /// Starts liveness tracking at a monotonic timestamp.
    ///
    /// # Errors
    /// [`LivenessError::InvalidConfiguration`] when the policy fails
    /// validation.
    pub fn new(config: LivenessConfig, now_ms: u64) -> Result<Self, LivenessError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            phase: Phase::Waiting {
                next_probe_at_ms: now_ms.saturating_add(config.base_interval_ms),
                consecutive_misses: 0,
            },
        })
    }

    /// Advances the timer. The challenge is consumed only when a probe is due.
    pub fn poll(
        &mut self,
        now_ms: u64,
        next_challenge: PingChallenge,
        jitter_ms: i64,
    ) -> LivenessDecision {
        match self.phase {
            Phase::Waiting {
                next_probe_at_ms,
                consecutive_misses,
            } if now_ms >= next_probe_at_ms => {
                self.phase = Phase::AwaitingPong {
                    challenge: next_challenge,
                    deadline_ms: now_ms.saturating_add(self.config.response_timeout_ms),
                    consecutive_misses,
                };
                LivenessDecision::SendPing(next_challenge)
            }
            Phase::AwaitingPong {
                deadline_ms,
                consecutive_misses,
                ..
            } if now_ms >= deadline_ms => {
                let misses = consecutive_misses.saturating_add(1);
                if misses >= self.config.maximum_misses {
                    self.phase = Phase::Closed;
                    LivenessDecision::CloseSession
                } else {
                    let interval = jittered_interval(
                        backoff_interval(self.config, misses),
                        self.config.maximum_jitter_ms,
                        jitter_ms,
                    );
                    self.phase = Phase::Waiting {
                        next_probe_at_ms: now_ms.saturating_add(interval),
                        consecutive_misses: misses,
                    };
                    LivenessDecision::ProbeMissed {
                        next_probe_at_ms: now_ms.saturating_add(interval),
                    }
                }
            }
            Phase::Closed => LivenessDecision::AlreadyClosed,
            _ => LivenessDecision::NoAction,
        }
    }

    /// Accepts only the exact authenticated challenge currently outstanding.
    /// A different or late value is discarded as a normal race and is not
    /// liveness proof.
    pub fn receive_pong(&mut self, now_ms: u64, challenge: PingChallenge) -> PongDisposition {
        let Phase::AwaitingPong {
            challenge: expected,
            ..
        } = self.phase
        else {
            return PongDisposition::IgnoredUnmatched;
        };
        if challenge != expected {
            return PongDisposition::IgnoredUnmatched;
        }
        self.phase = Phase::Waiting {
            next_probe_at_ms: now_ms.saturating_add(self.config.base_interval_ms),
            consecutive_misses: 0,
        };
        PongDisposition::Accepted
    }

    /// Permanently closes this session-local tracker.
    pub const fn close(&mut self) {
        self.phase = Phase::Closed;
    }
}

fn backoff_interval(config: LivenessConfig, misses: u8) -> u64 {
    let shift = u32::from(misses.min(63));
    let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    config
        .base_interval_ms
        .saturating_mul(multiplier)
        .min(config.maximum_interval_ms)
}

fn jittered_interval(interval_ms: u64, maximum_jitter_ms: u64, jitter_ms: i64) -> u64 {
    let magnitude = jitter_ms.unsigned_abs().min(maximum_jitter_ms);
    if jitter_ms.is_negative() {
        interval_ms.saturating_sub(magnitude).max(1)
    } else {
        interval_ms.saturating_add(magnitude)
    }
}

/// Action emitted by a liveness timer tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessDecision {
    /// No wire activity is required.
    NoAction,
    /// Send an authenticated ping carrying this challenge.
    SendPing(PingChallenge),
    /// A probe timed out; retry at the supplied monotonic time.
    ProbeMissed {
        /// Monotonic time of the next probe after backoff.
        next_probe_at_ms: u64,
    },
    /// Repeated connectivity loss closes only the current session.
    CloseSession,
    /// The tracker was already closed.
    AlreadyClosed,
}

/// Result of receiving an authenticated pong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PongDisposition {
    /// Exact outstanding challenge matched and liveness was proven.
    Accepted,
    /// No outstanding challenge matched; discard as a normal delayed race.
    IgnoredUnmatched,
}

/// Liveness configuration or authenticated-message failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessError {
    /// Timing or retry policy is nonsensical.
    InvalidConfiguration,
}

impl fmt::Display for LivenessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for LivenessError {}
