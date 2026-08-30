//! Central security-incident classification.
//!
//! There is deliberately no strike counter. The first authenticated protocol
//! violation revokes the pair. Failures that cannot be authenticated are kept
//! session-scoped so an unauthenticated network attacker cannot erase a pair.

use super::CredentialKind;

/// Security-relevant event observed by an endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityIncident {
    /// A decrypted and authenticated peer message violated the RAPP grammar,
    /// sequence, role, profile, or negotiated grant.
    AuthenticatedProtocolViolation,
    /// A frame could not be decrypted or authenticated as part of this session.
    SessionIntegrityFailure,
    /// The selected transport disconnected or became unavailable.
    TransportFailure,
    /// The card rejected CAN, PIN 1, or PIN 2 during an operation.
    CredentialRejected(CredentialKind),
    /// The authorizer explicitly rejected the request.
    UserRejected,
    /// A request or approval expired before the card command was committed.
    OperationExpired,
    /// Connectivity was lost after the durable journal committed the physical
    /// card command, so retransmission is forbidden and the result is unknown.
    CommittedResultUnknown,
}

impl SecurityIncident {
    /// Returns the normative first-incident response.
    #[must_use]
    pub const fn disposition(self) -> IncidentDisposition {
        match self {
            Self::AuthenticatedProtocolViolation => IncidentDisposition {
                pair: PairDisposition::RevokeImmediately,
                session: SessionDisposition::CloseImmediately,
                operation: OperationDisposition::Fail,
                require_new_user_intent: true,
            },
            Self::SessionIntegrityFailure | Self::TransportFailure => IncidentDisposition {
                pair: PairDisposition::Keep,
                session: SessionDisposition::CloseImmediately,
                operation: OperationDisposition::ResolveFromJournal,
                require_new_user_intent: true,
            },
            Self::CredentialRejected(_) => IncidentDisposition {
                pair: PairDisposition::Keep,
                session: SessionDisposition::CloseImmediately,
                operation: OperationDisposition::Reject,
                require_new_user_intent: true,
            },
            Self::UserRejected | Self::OperationExpired => IncidentDisposition {
                pair: PairDisposition::Keep,
                session: SessionDisposition::Keep,
                operation: OperationDisposition::Reject,
                require_new_user_intent: true,
            },
            Self::CommittedResultUnknown => IncidentDisposition {
                pair: PairDisposition::Keep,
                session: SessionDisposition::CloseImmediately,
                operation: OperationDisposition::AmbiguousNeverRetry,
                require_new_user_intent: true,
            },
        }
    }
}

/// Long-term pair response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairDisposition {
    /// Preserve the authenticated long-term pairing.
    Keep,
    /// Destroy pair keys and require manual QR pairing again now.
    RevokeImmediately,
}

/// Current-session response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionDisposition {
    /// The current session can remain active.
    Keep,
    /// Tear down the current secure channel now.
    CloseImmediately,
}

/// Active-operation response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDisposition {
    /// Fail without retrying the operation.
    Fail,
    /// Reject before a physical card command was committed.
    Reject,
    /// Consult the durable journal to distinguish safe rejection from an
    /// ambiguous committed command.
    ResolveFromJournal,
    /// Report an ambiguous result and never transmit the command again.
    AmbiguousNeverRetry,
}

/// Complete response to one incident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncidentDisposition {
    /// Pair-key handling.
    pub pair: PairDisposition,
    /// Secure-session handling.
    pub session: SessionDisposition,
    /// Active-operation handling.
    pub operation: OperationDisposition,
    /// Whether subsequent work needs a new explicit user action.
    pub require_new_user_intent: bool,
}

#[cfg(test)]
mod tests {
    use super::{OperationDisposition, PairDisposition, SecurityIncident, SessionDisposition};

    #[test]
    fn first_authenticated_violation_revokes_immediately() {
        let response = SecurityIncident::AuthenticatedProtocolViolation.disposition();
        assert_eq!(response.pair, PairDisposition::RevokeImmediately);
        assert_eq!(response.session, SessionDisposition::CloseImmediately);
        assert_eq!(response.operation, OperationDisposition::Fail);
    }

    #[test]
    fn unauthenticated_integrity_failure_cannot_erase_pair() {
        let response = SecurityIncident::SessionIntegrityFailure.disposition();
        assert_eq!(response.pair, PairDisposition::Keep);
        assert_eq!(response.session, SessionDisposition::CloseImmediately);
    }
}
