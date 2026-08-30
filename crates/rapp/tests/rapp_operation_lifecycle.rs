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

//! Executable evidence for the RAPP at-most-once and result-delivery boundary.

use refineid_rapp::{
    ApprovalOutcome, AuthorizationStage, AuthorizationTransaction, CardKeyProfile, CardOperation,
    CardOperationResult, JournalRecord, JournalStore, OperationId, OperationRequest,
    OperationResultMessage, OperationState, PairId, ProfileName, RequestHash, ResultJournalStore,
    SessionId, SignatureAlgorithm, UserApproval,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreEvent {
    Persist(OperationState, u8),
    PersistResult(OperationState, u8),
    RetainUncertain(OperationState, u8),
    Acknowledge(OperationState, u8),
}

#[derive(Default)]
struct MemoryResultStore {
    events: Vec<StoreEvent>,
    retained_result: Option<OperationResultMessage>,
    fail_next_write: bool,
}

impl MemoryResultStore {
    const fn maybe_fail(&mut self) -> Result<(), &'static str> {
        if self.fail_next_write {
            self.fail_next_write = false;
            Err("injected durable-store failure")
        } else {
            Ok(())
        }
    }
}

impl JournalStore for MemoryResultStore {
    type Error = &'static str;

    fn persist(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        self.events
            .push(StoreEvent::Persist(record.state, record.transmission_count));
        Ok(())
    }
}

impl ResultJournalStore for MemoryResultStore {
    fn persist_result(
        &mut self,
        record: &JournalRecord,
        result: &OperationResultMessage,
    ) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        self.retained_result = Some(result.clone());
        self.events.push(StoreEvent::PersistResult(
            record.state,
            record.transmission_count,
        ));
        Ok(())
    }

    fn retain_uncertain_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        assert!(
            self.retained_result.is_some(),
            "delivery uncertainty must retain an already-durable result"
        );
        self.events.push(StoreEvent::RetainUncertain(
            record.state,
            record.transmission_count,
        ));
        Ok(())
    }

    fn acknowledge_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        self.retained_result = None;
        self.events.push(StoreEvent::Acknowledge(
            record.state,
            record.transmission_count,
        ));
        Ok(())
    }
}

fn consequential_request() -> OperationRequest {
    OperationRequest::reconstruct(
        OperationId::from_array([0x11; 16]),
        PairId::from_array([0x22; 16]),
        SessionId::from_array([0x33; 16]),
        ProfileName::Authentication,
        1_000,
        5_000,
        CardOperation::BrowserAuthenticate {
            origin: "https://example.invalid".into(),
            key_profile: CardKeyProfile::EcdsaP256,
            algorithm: SignatureAlgorithm::EcdsaSha256,
            digest: vec![0x44; 32],
        },
    )
    .expect("the fixed request vector is valid")
}

fn approved_transaction() -> AuthorizationTransaction {
    let request = consequential_request();
    let approval = UserApproval::for_request(&request, 1_100)
        .expect("the fixed request vector has a deterministic hash");
    let mut transaction =
        AuthorizationTransaction::prepare(request).expect("the fixed request vector is valid");
    transaction
        .prerequisites_complete()
        .expect("prerequisites complete once");
    assert!(matches!(
        transaction
            .approve(approval, 1_100, 10_000)
            .expect("fresh exact approval is accepted"),
        ApprovalOutcome::Prepared(_)
    ));
    transaction
}

fn committed_transaction(store: &mut MemoryResultStore) -> AuthorizationTransaction {
    let mut transaction = approved_transaction();
    transaction
        .commit(store, transaction.reference(), 1_200, 10_000)
        .expect("exact fresh commit is persisted");
    transaction
}

fn completed_result(transaction: &AuthorizationTransaction) -> OperationResultMessage {
    OperationResultMessage::completed(
        transaction.reference(),
        CardOperationResult::Signature(vec![0x55; 64]),
    )
}

#[test]
fn durable_commit_precedes_the_only_physical_command() {
    let mut store = MemoryResultStore::default();
    let mut transaction = committed_transaction(&mut store);
    let mut physical_transmissions = 0_u8;

    assert_eq!(
        store.events,
        [StoreEvent::Persist(OperationState::Committed, 0)]
    );

    let pending = transaction
        .begin_card_command(&mut store)
        .expect("the durable committed operation may start once");
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::Persist(OperationState::Executing, 1))
    );
    pending.execute(|command| {
        physical_transmissions += 1;
        assert_eq!(command.operation, consequential_request().operation);
    });

    assert_eq!(physical_transmissions, 1);
    assert_eq!(transaction.journal().record().transmission_count, 1);
    assert!(!transaction.journal().record().automatic_retry_permitted);
    assert!(transaction.begin_card_command(&mut store).is_err());
    assert_eq!(physical_transmissions, 1);
}

#[test]
fn duplicate_commit_cannot_create_another_card_command() {
    let mut store = MemoryResultStore::default();
    let mut transaction = committed_transaction(&mut store);
    let writes_after_first_commit = store.events.len();

    assert!(
        transaction
            .commit(&mut store, transaction.reference(), 1_201, 10_000)
            .is_err()
    );
    assert_eq!(store.events.len(), writes_after_first_commit);

    let mut physical_transmissions = 0_u8;
    transaction
        .begin_card_command(&mut store)
        .expect("the original commit remains executable once")
        .execute(|_| physical_transmissions += 1);
    assert!(transaction.begin_card_command(&mut store).is_err());
    assert_eq!(physical_transmissions, 1);
}

#[test]
fn persistence_failure_prevents_command_exposure() {
    let mut store = MemoryResultStore::default();
    let mut transaction = committed_transaction(&mut store);
    let writes_before_failure = store.events.len();
    store.fail_next_write = true;

    assert!(transaction.begin_card_command(&mut store).is_err());
    assert_eq!(transaction.stage(), AuthorizationStage::Committed);
    assert_eq!(transaction.journal().record().transmission_count, 0);
    assert_eq!(store.events.len(), writes_before_failure);
}

#[test]
fn result_is_durable_before_release_and_acknowledgment_erases_it() {
    let mut store = MemoryResultStore::default();
    let mut transaction = committed_transaction(&mut store);
    transaction
        .begin_card_command(&mut store)
        .expect("the command starts once")
        .execute(|_| ());
    let result = completed_result(&transaction);

    transaction
        .finish_completed(&mut store, result.clone())
        .expect("a valid completed result is persisted");
    assert_eq!(transaction.stage(), AuthorizationStage::ResultPending);
    assert_eq!(transaction.retained_result(), Some(&result));
    assert_eq!(store.retained_result.as_ref(), Some(&result));
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::PersistResult(OperationState::ResultPending, 1))
    );

    transaction
        .acknowledge_result(&mut store, transaction.reference())
        .expect("the exact acknowledgment completes delivery");
    assert_eq!(transaction.stage(), AuthorizationStage::Terminal);
    assert_eq!(transaction.operation_state(), OperationState::Completed);
    assert_eq!(transaction.retained_result(), None);
    assert_eq!(store.retained_result, None);
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::Acknowledge(OperationState::Completed, 1))
    );
}

#[test]
fn lost_ack_retains_result_and_forbids_automatic_replay() {
    let mut store = MemoryResultStore::default();
    let mut transaction = committed_transaction(&mut store);
    transaction
        .begin_card_command(&mut store)
        .expect("the command starts once")
        .execute(|_| ());
    let result = completed_result(&transaction);
    transaction
        .finish_completed(&mut store, result.clone())
        .expect("result is durable before transport release");

    transaction
        .delivery_became_uncertain(&mut store)
        .expect("session loss marks delivery uncertain");
    assert_eq!(
        transaction.operation_state(),
        OperationState::DeliveryUncertain
    );
    assert_eq!(transaction.retained_result(), Some(&result));
    assert_eq!(store.retained_result.as_ref(), Some(&result));
    assert!(!transaction.journal().record().automatic_retry_permitted);
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::RetainUncertain(
            OperationState::DeliveryUncertain,
            1,
        ))
    );
    assert!(
        transaction
            .acknowledge_result(&mut store, transaction.reference())
            .is_err()
    );
    assert!(transaction.begin_card_command(&mut store).is_err());
}

#[test]
fn crash_after_transmission_is_ambiguous_and_never_retried() {
    let mut store = MemoryResultStore::default();
    let mut transaction = committed_transaction(&mut store);
    transaction
        .begin_card_command(&mut store)
        .expect("the command starts once")
        .execute(|_| ());

    transaction
        .recover_after_crash(&mut store)
        .expect("executing work recovers as ambiguous");
    assert_eq!(transaction.operation_state(), OperationState::Ambiguous);
    assert_eq!(transaction.journal().record().transmission_count, 1);
    assert!(!transaction.journal().record().automatic_retry_permitted);
    assert!(transaction.begin_card_command(&mut store).is_err());
}

#[test]
fn request_hash_is_bound_to_semantics_but_not_local_time_or_expiry() {
    let original = consequential_request();
    let mut local_only_change = original.clone();
    local_only_change.local_start_ms += 99_000;
    local_only_change.expires_after_ms += 99_000;
    assert_eq!(
        original.request_hash().expect("hash succeeds"),
        local_only_change.request_hash().expect("hash succeeds")
    );

    let mut semantic_change = original.clone();
    semantic_change.operation = CardOperation::BrowserAuthenticate {
        origin: "https://different.example.invalid".into(),
        key_profile: CardKeyProfile::EcdsaP256,
        algorithm: SignatureAlgorithm::EcdsaSha256,
        digest: vec![0x44; 32],
    };
    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        semantic_change.request_hash().expect("hash succeeds")
    );

    let mut session_change = original.clone();
    session_change.session_id = SessionId::from_array([0x99; 16]);
    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        session_change.request_hash().expect("hash succeeds")
    );

    let mut operation_id_change = original.clone();
    operation_id_change.operation_id = OperationId::from_array([0xaa; 16]);
    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        operation_id_change.request_hash().expect("hash succeeds")
    );

    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        RequestHash::from_array([0; 32]),
        "the fixed vector must not collapse to the all-zero sentinel"
    );
}
