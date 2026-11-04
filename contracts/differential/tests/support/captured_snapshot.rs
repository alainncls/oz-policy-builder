//! SDK snapshot source with explicit captured and candidate-state provenance.

use ozpb_source_rpc::InvocationFootprintCapture;
use soroban_ledger_snapshot::LedgerSnapshot;
use soroban_sdk::{
    testutils::{HostError, Ledger, SnapshotSource, SnapshotSourceInput},
    xdr::{self as sdk_xdr, ReadXdr as _, WriteXdr as _},
    Env,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

type StoredEntries = BTreeMap<String, (Rc<sdk_xdr::LedgerEntry>, Option<u32>)>;

struct ExactSource {
    entries: StoredEntries,
    allowed_absent_keys: BTreeSet<String>,
    absent_reads: Rc<RefCell<BTreeSet<String>>>,
    rejected: Rc<RefCell<usize>>,
}

impl SnapshotSource for ExactSource {
    fn get(
        &self,
        key: &Rc<sdk_xdr::LedgerKey>,
    ) -> Result<Option<(Rc<sdk_xdr::LedgerEntry>, Option<u32>)>, HostError> {
        let encoded = key.to_xdr_base64(sdk_xdr::Limits::none()).unwrap();
        if let Some(entry) = self.entries.get(&encoded) {
            return Ok(Some(entry.clone()));
        }
        if self.allowed_absent_keys.contains(&encoded) {
            // Only the exact new nonce keys declared by this candidate run may
            // begin absent. Existing account and policy storage must be present.
            self.absent_reads.borrow_mut().insert(encoded);
            return Ok(None);
        }
        *self.rejected.borrow_mut() += 1;
        Err(HostError::from((
            sdk_xdr::ScErrorType::Storage,
            sdk_xdr::ScErrorCode::ExceededLimit,
        )))
    }
}

pub struct ReconstructedEnv {
    pub env: Env,
    pub rejected: Rc<RefCell<usize>>,
    /// Encoded keys allowed to begin absent, and those the host actually read.
    /// A caller can require every allowance to be used.
    pub allowed_absent: BTreeSet<String>,
    pub absent_reads: Rc<RefCell<BTreeSet<String>>>,
    pub captured_entry_count: usize,
    pub candidate_entry_count: usize,
    initial: StoredEntries,
}

/// Entry data and live-until ledger for one key, absent as `None`.
pub type EntryState = Option<(sdk_xdr::LedgerEntryData, Option<u32>)>;

/// One key whose committed state differs from its captured or candidate state.
#[derive(Debug)]
pub struct StateChange {
    pub before: EntryState,
    pub after: EntryState,
}

impl ReconstructedEnv {
    /// Every encoded key whose committed host state differs from the combined
    /// captured and candidate state. `Env::to_ledger_snapshot` is built from
    /// these stored entries; reading them directly also shows deletions, which
    /// the snapshot would drop. Last-modified ledger numbers are not compared,
    /// so a write that keeps the same data and TTL is not a change.
    pub fn committed_changes(&self) -> BTreeMap<String, StateChange> {
        let mut changes = BTreeMap::new();
        for (key, stored) in self.env.host().get_stored_entries().unwrap() {
            let encoded = key.to_xdr_base64(sdk_xdr::Limits::none()).unwrap();
            let before = self
                .initial
                .get(&encoded)
                .map(|(entry, live_until)| (entry.data.clone(), *live_until));
            let after = stored.map(|(entry, live_until)| (entry.data.clone(), live_until));
            if before != after {
                changes.insert(encoded, StateChange { before, after });
            }
        }
        changes
    }
}

/// Candidate entries come from a locally created account/policy snapshot. The
/// target entries come from one checked RPC reply at its reported ledger. Key
/// overlap is refused, and every other key fails rather than appearing absent.
/// The source governs reads only; `committed_changes` reports what committed.
pub fn reconstruct(
    capture: &InvocationFootprintCapture,
    candidate: Option<&LedgerSnapshot>,
    allowed_absent_keys: Vec<sdk_xdr::LedgerKey>,
) -> ReconstructedEnv {
    let mut entries = BTreeMap::new();
    for (encoded, captured) in &capture.entries {
        let sdk_key = sdk_xdr::LedgerKey::from_xdr_base64(encoded, sdk_xdr::Limits::none())
            .expect("captured key is SDK-readable");
        let data_xdr =
            xdr30::WriteXdr::to_xdr_base64(&captured.data, xdr30::Limits::none()).unwrap();
        let sdk_data =
            sdk_xdr::LedgerEntryData::from_xdr_base64(&data_xdr, sdk_xdr::Limits::none())
                .expect("captured data is SDK-readable");
        assert_eq!(sdk_data.to_key(), sdk_key, "captured key/data mismatch");
        assert!(
            entries
                .insert(
                    encoded.clone(),
                    (
                        Rc::new(sdk_xdr::LedgerEntry {
                            last_modified_ledger_seq: captured.last_modified_ledger.0,
                            data: sdk_data,
                            ext: sdk_xdr::LedgerEntryExt::V0,
                        }),
                        captured.live_until_ledger.map(|seq| seq.0),
                    ),
                )
                .is_none(),
            "duplicate captured entry"
        );
    }
    let captured_entry_count = entries.len();
    let mut candidate_entry_count = 0;
    if let Some(candidate) = candidate {
        assert_eq!(candidate.network_id, capture.network_id.0 .0);
        assert_eq!(candidate.sequence_number, capture.reported_ledger.0);
        for (key, (entry, live_until)) in candidate.entries() {
            let encoded = key.to_xdr_base64(sdk_xdr::Limits::none()).unwrap();
            assert!(
                entries
                    .insert(encoded, (Rc::new(entry.as_ref().clone()), *live_until))
                    .is_none(),
                "candidate state overlaps captured target state"
            );
            candidate_entry_count += 1;
        }
    }
    let mut allowed_absent = BTreeSet::new();
    for key in allowed_absent_keys {
        let encoded = key.to_xdr_base64(sdk_xdr::Limits::none()).unwrap();
        assert!(
            !entries.contains_key(&encoded),
            "new key was already present"
        );
        assert!(
            allowed_absent.insert(encoded),
            "duplicate allowed absent key"
        );
    }
    let rejected = Rc::new(RefCell::new(0));
    let absent_reads = Rc::new(RefCell::new(BTreeSet::new()));
    // RPC gives no full header or network configuration. These are SDK test
    // defaults except for the reported sequence and network ID.
    let mut ledger_info = Env::default().ledger().get();
    ledger_info.sequence_number = capture.reported_ledger.0;
    ledger_info.network_id = capture.network_id.0 .0;
    let initial = entries.clone();
    let env = Env::from_ledger_snapshot(SnapshotSourceInput {
        source: Rc::new(ExactSource {
            entries,
            allowed_absent_keys: allowed_absent.clone(),
            absent_reads: absent_reads.clone(),
            rejected: rejected.clone(),
        }),
        ledger_info: Some(ledger_info),
        snapshot: None,
    });
    ReconstructedEnv {
        env,
        rejected,
        allowed_absent,
        absent_reads,
        captured_entry_count,
        candidate_entry_count,
        initial,
    }
}
