//! Durable pairing records and the device-only persistence boundary.
//!
//! RAPP deliberately does not provide an in-memory default store. Platform
//! integrations must place the private key in device-only, non-backup secret
//! storage and make insertion/revocation atomic.

use core::fmt;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{EndpointRole, GrantsHash, PairId, ProfileName, RendezvousToken, WireValue};

const X25519_KEY_SIZE: usize = 32;

/// Transport metadata retained after pairing without retaining the QR secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairTransportBinding {
    /// Negotiated transport profile.
    pub profile: String,
    /// Opaque candidate identifier from the pairing offer.
    pub candidate_id: String,
    /// Non-secret transport parameters required to reconnect.
    pub parameters: BTreeMap<String, WireValue>,
}

/// Active long-term pairing material.
///
/// This type is intentionally neither `Clone` nor serializable. Persistence
/// adapters must explicitly extract the secret inside their protected storage
/// implementation instead of accidentally copying it through application
/// models, logs, backups, or diagnostics.
pub struct PairRecord {
    pair_id: PairId,
    rendezvous_token: RendezvousToken,
    role: EndpointRole,
    local_static_private: Zeroizing<[u8; X25519_KEY_SIZE]>,
    local_static_public: [u8; X25519_KEY_SIZE],
    remote_static_public: [u8; X25519_KEY_SIZE],
    grants_hash: GrantsHash,
    profiles: Vec<ProfileName>,
    transport: PairTransportBinding,
    created_at_ms: u64,
}

impl PairRecord {
    /// Constructs a validated active pairing record.
    ///
    /// # Errors
    /// [`PairRecordError`] on an all-zero static key, an empty profile set,
    /// or an empty transport binding.
    #[allow(
        clippy::too_many_arguments,
        reason = "one atomic constructor takes every field of the record"
    )]
    pub fn new(
        pair_id: PairId,
        rendezvous_token: RendezvousToken,
        role: EndpointRole,
        local_static_private: [u8; X25519_KEY_SIZE],
        local_static_public: [u8; X25519_KEY_SIZE],
        remote_static_public: [u8; X25519_KEY_SIZE],
        grants_hash: GrantsHash,
        profiles: Vec<ProfileName>,
        transport: PairTransportBinding,
        created_at_ms: u64,
    ) -> Result<Self, PairRecordError> {
        if local_static_private.iter().all(|byte| *byte == 0)
            || local_static_public.iter().all(|byte| *byte == 0)
            || remote_static_public.iter().all(|byte| *byte == 0)
        {
            return Err(PairRecordError::InvalidStaticKey);
        }
        if profiles.is_empty() {
            return Err(PairRecordError::NoNegotiatedProfiles);
        }
        if transport.profile.is_empty() || transport.candidate_id.is_empty() {
            return Err(PairRecordError::InvalidTransportBinding);
        }

        Ok(Self {
            pair_id,
            rendezvous_token,
            role,
            local_static_private: Zeroizing::new(local_static_private),
            local_static_public,
            remote_static_public,
            grants_hash,
            profiles,
            transport,
            created_at_ms,
        })
    }

    /// Stable identifier of the pairing.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// Pair-specific rendezvous value for transports that must name this
    /// pairing on the wire (Sections 16.1 and 17). Never `pair_id`.
    #[must_use]
    pub const fn rendezvous_token(&self) -> RendezvousToken {
        self.rendezvous_token
    }

    /// Local endpoint role fixed during pairing.
    #[must_use]
    pub const fn role(&self) -> EndpointRole {
        self.role
    }

    /// Remote static Noise public key pinned by the pairing handshake.
    #[must_use]
    pub const fn remote_static_public(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.remote_static_public
    }

    /// Local static Noise public key corresponding to protected private bytes.
    #[must_use]
    pub const fn local_static_public(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.local_static_public
    }

    /// Hash of the negotiated authorization grants.
    #[must_use]
    pub const fn grants_hash(&self) -> GrantsHash {
        self.grants_hash
    }

    /// Profiles permitted by this pairing.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileName] {
        &self.profiles
    }

    /// Transport binding used for reconnecting.
    #[must_use]
    pub const fn transport(&self) -> &PairTransportBinding {
        &self.transport
    }

    /// Pair creation time supplied by the platform wall clock.
    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Exposes the private key only to sibling protocol machinery and stores.
    pub(super) fn local_static_private(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.local_static_private
    }
}

impl fmt::Debug for PairRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairRecord")
            .field("pair_id", &self.pair_id)
            .field("rendezvous_token", &self.rendezvous_token)
            .field("role", &self.role)
            .field("local_static_private", &"[redacted]")
            .field("local_static_public", &"[public key]")
            .field("remote_static_public", &"[public key]")
            .field("grants_hash", &self.grants_hash)
            .field("profiles", &self.profiles)
            .field("transport", &self.transport)
            .field("created_at_ms", &self.created_at_ms)
            .finish()
    }
}

/// Non-secret marker retained after an irreversible revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairTombstone {
    /// Revoked pair identifier.
    pub pair_id: PairId,
    /// Local time at which the secret was destroyed.
    pub revoked_at_ms: u64,
}

/// Platform persistence boundary for long-term pair keys.
///
/// Implementations MUST use device-only, non-migrating, non-backup secret
/// storage. `insert` and `revoke` MUST be atomic. `revoke` MUST destroy the
/// private key before reporting success and retain only a non-secret tombstone.
pub trait PairStore {
    /// Platform storage error.
    type Error;

    /// Loads an active pair into zeroizing process memory.
    ///
    /// # Errors
    /// The platform storage failure.
    fn load(&mut self, pair_id: PairId) -> Result<Option<PairRecord>, Self::Error>;

    /// Atomically inserts a newly authenticated pair.
    ///
    /// # Errors
    /// [`PairStoreError`] on a reused identifier or a backend failure.
    fn insert(&mut self, record: PairRecord) -> Result<(), PairStoreError<Self::Error>>;

    /// Atomically destroys active secret material and stores a tombstone.
    ///
    /// # Errors
    /// [`PairStoreError`] when the pair does not exist or the backend fails.
    fn revoke(&mut self, tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>>;

    /// Reports whether an identifier has been permanently revoked locally.
    ///
    /// # Errors
    /// The platform storage failure.
    fn is_revoked(&mut self, pair_id: PairId) -> Result<bool, Self::Error>;
}

/// Pair-record validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairRecordError {
    /// A Noise static key was the all-zero invalid value.
    InvalidStaticKey,
    /// Pairing completed without any negotiated profile.
    NoNegotiatedProfiles,
    /// Selected transport profile or candidate identifier was empty.
    InvalidTransportBinding,
}

impl fmt::Display for PairRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for PairRecordError {}

/// Atomic pair-store operation failure.
#[derive(Debug)]
pub enum PairStoreError<E> {
    /// The identifier already has an active record or tombstone.
    IdentifierAlreadyUsed,
    /// The requested active pair does not exist.
    PairNotFound,
    /// Platform-provided storage failed.
    Backend(E),
}
