//! Race-free local backend lifecycle and lease accounting.
//!
//! This module deliberately contains no HTTP, configuration parsing, health
//! checking, routing policy, metrics, or persistence.  It provides the small
//! synchronization core those layers need:
//!
//! - a stable backend identity and opaque endpoint specification;
//! - an operator-controlled `Active` / `Draining` / `Disabled` gate;
//! - atomic acquire-versus-drain semantics under one mutex;
//! - RAII leases which cover the complete lifetime of backend work;
//! - race-free asynchronous waiting for a particular drain generation; and
//! - registry reconciliation which preserves live slots and operator drains.
//!
//! A routing decision is not complete until [`BackendSlot::try_acquire`]
//! returns a [`BackendLease`].  Merely cloning a slot or its specification does
//! not reserve it.  Both lease acquisition and `Active -> Draining` take the
//! same short-held mutex, so exactly one linearizes first: a lease acquired
//! first is counted by the drain, while a drain begun first rejects the lease.

use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    hash::Hash,
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Stable identity of one logical backend.
///
/// Display names and endpoints may change during reconciliation; this value
/// must not.  Drains and local accounting are attached to this identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendId(Arc<str>);

impl BackendId {
    pub fn new(value: impl Into<Arc<str>>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BackendId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for BackendId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<&str> for BackendId {
    fn from(value: &str) -> Self {
        Self::new(Arc::<str>::from(value))
    }
}

impl From<String> for BackendId {
    fn from(value: String) -> Self {
        Self::new(Arc::<str>::from(value))
    }
}

/// Immutable specification captured by a lease.
///
/// `endpoint` is intentionally opaque here.  The HTTP layer may parse it into
/// its own transport type.  Reconciliation can replace a slot's current spec;
/// leases already acquired retain the previous spec and therefore cannot jump
/// to a different endpoint halfway through a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSpec {
    id: BackendId,
    endpoint: Arc<str>,
}

impl BackendSpec {
    pub fn new(id: impl Into<BackendId>, endpoint: impl Into<Arc<str>>) -> Self {
        Self {
            id: id.into(),
            endpoint: endpoint.into(),
        }
    }

    pub fn id(&self) -> &BackendId {
        &self.id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Operator gate for a backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    /// New leases may be acquired while the backend is registered.
    Active,
    /// New leases are rejected; existing leases are allowed to finish.
    Draining,
    /// New leases are rejected without representing an in-progress drain.
    Disabled,
}

impl fmt::Display for BackendMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Disabled => "disabled",
        })
    }
}

/// Point-in-time local state of one backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSnapshot {
    pub spec: BackendSpec,
    /// False after the backend disappeared during registry reconciliation.
    /// Retired slots remain alive while leases or drain waiters reference them.
    pub registered: bool,
    pub mode: BackendMode,
    /// Changes whenever the operator mode changes.  A drain token contains this
    /// value so a concurrent activate/disable cannot produce false success.
    pub mode_epoch: u64,
    /// Changes on every observable state change, including lease activity and
    /// specification replacement.
    pub sequence: u64,
    pub spec_revision: u64,
    /// Monotonic number of leases ever acquired by this process. A telemetry
    /// sample records this value so routing can account for assignments made
    /// after that sample and avoid a burst stampeding onto an apparently idle
    /// backend.
    pub total_acquired: u64,
    pub local_active: usize,
    pub oldest_active_age: Option<Duration>,
}

impl BackendSnapshot {
    pub fn id(&self) -> &BackendId {
        self.spec.id()
    }

    /// Whether this snapshot is the locally safe completion of a drain.
    pub fn locally_drained(&self) -> bool {
        self.mode == BackendMode::Draining && self.local_active == 0
    }
}

/// Identifies one particular transition into `Draining`.
///
/// Waiting with this token fails if another operator transition supersedes the
/// drain.  It can therefore never return success for a backend that was
/// reactivated while the waiter was asleep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainToken {
    backend_id: BackendId,
    mode_epoch: u64,
}

impl DrainToken {
    pub fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    pub fn mode_epoch(&self) -> u64 {
        self.mode_epoch
    }
}

/// Lease acquisition failed because the slot cannot currently accept work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquireError {
    Retired {
        backend_id: BackendId,
    },
    NotActive {
        backend_id: BackendId,
        mode: BackendMode,
    },
}

impl fmt::Display for AcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retired { backend_id } => {
                write!(formatter, "backend {backend_id} is no longer registered")
            }
            Self::NotActive { backend_id, mode } => {
                write!(formatter, "backend {backend_id} is {mode:?}")
            }
        }
    }
}

impl Error for AcquireError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModeChangeError {
    Retired { backend_id: BackendId },
}

impl fmt::Display for ModeChangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retired { backend_id } => {
                write!(formatter, "backend {backend_id} is no longer registered")
            }
        }
    }
}

impl Error for ModeChangeError {}

/// Waiting for a drain can fail only when the token is invalid or superseded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainWaitError {
    WrongBackend {
        token_backend_id: BackendId,
        slot_backend_id: BackendId,
    },
    Superseded {
        backend_id: BackendId,
        expected_epoch: u64,
        current_epoch: u64,
        current_mode: BackendMode,
    },
}

impl fmt::Display for DrainWaitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongBackend {
                token_backend_id,
                slot_backend_id,
            } => write!(
                formatter,
                "drain token belongs to backend {token_backend_id}, not {slot_backend_id}"
            ),
            Self::Superseded {
                backend_id,
                expected_epoch,
                current_epoch,
                current_mode,
            } => write!(
                formatter,
                "drain for backend {backend_id} at epoch {expected_epoch} was superseded by epoch {current_epoch} ({current_mode:?})"
            ),
        }
    }
}

impl Error for DrainWaitError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LeaseKey {
    started_at: Instant,
    serial: u64,
}

struct SlotState {
    spec: BackendSpec,
    registered: bool,
    mode: BackendMode,
    mode_epoch: u64,
    sequence: u64,
    spec_revision: u64,
    next_lease_serial: u64,
    total_acquired: u64,
    leases: BTreeMap<LeaseKey, ()>,
}

impl SlotState {
    fn snapshot(&self, now: Instant) -> BackendSnapshot {
        BackendSnapshot {
            spec: self.spec.clone(),
            registered: self.registered,
            mode: self.mode,
            mode_epoch: self.mode_epoch,
            sequence: self.sequence,
            spec_revision: self.spec_revision,
            total_acquired: self.total_acquired,
            local_active: self.leases.len(),
            oldest_active_age: self
                .leases
                .first_key_value()
                .map(|(key, ())| now.saturating_duration_since(key.started_at)),
        }
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("backend state sequence exhausted");
        self.sequence
    }

    fn next_mode_epoch(&mut self) {
        self.mode_epoch = self
            .mode_epoch
            .checked_add(1)
            .expect("backend mode epoch exhausted");
    }
}

/// One logical backend and its local lease gate.
pub struct BackendSlot {
    state: Mutex<SlotState>,
    changed: watch::Sender<u64>,
}

impl fmt::Debug for BackendSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendSlot")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl BackendSlot {
    pub fn new(spec: BackendSpec, mode: BackendMode) -> Arc<Self> {
        let (changed, _) = watch::channel(0);
        Arc::new(Self {
            state: Mutex::new(SlotState {
                spec,
                registered: true,
                mode,
                mode_epoch: 0,
                sequence: 0,
                spec_revision: 0,
                next_lease_serial: 0,
                total_acquired: 0,
                leases: BTreeMap::new(),
            }),
            changed,
        })
    }

    pub fn id(&self) -> BackendId {
        self.lock_state().spec.id.clone()
    }

    pub fn snapshot(&self) -> BackendSnapshot {
        self.lock_state().snapshot(Instant::now())
    }

    /// Subscribe to state changes.  The value is the snapshot sequence.
    /// Consumers should call [`Self::snapshot`] after observing a change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Atomically acquire this backend if and only if it is registered and
    /// active.  The returned lease captures the current specification.
    pub fn try_acquire(self: &Arc<Self>) -> Result<BackendLease, AcquireError> {
        let now = Instant::now();
        let mut state = self.lock_state();
        if !state.registered {
            return Err(AcquireError::Retired {
                backend_id: state.spec.id.clone(),
            });
        }
        if state.mode != BackendMode::Active {
            return Err(AcquireError::NotActive {
                backend_id: state.spec.id.clone(),
                mode: state.mode,
            });
        }

        let serial = state.next_lease_serial;
        state.next_lease_serial = state
            .next_lease_serial
            .checked_add(1)
            .expect("backend lease serial exhausted");
        state.total_acquired = state
            .total_acquired
            .checked_add(1)
            .expect("backend acquisition counter exhausted");
        let key = LeaseKey {
            started_at: now,
            serial,
        };
        let previous = state.leases.insert(key, ());
        debug_assert!(previous.is_none());
        let spec = state.spec.clone();
        self.publish_locked(&mut state);

        Ok(BackendLease {
            slot: Arc::clone(self),
            key: Some(key),
            spec,
        })
    }

    /// Make the backend eligible for new leases.
    ///
    /// Repeating `activate` while already active is idempotent and does not
    /// supersede an existing token with a new epoch.
    pub fn activate(&self) -> Result<BackendSnapshot, ModeChangeError> {
        self.set_mode(BackendMode::Active, true)
    }

    /// Reject new leases without representing a drain operation.
    pub fn disable(&self) -> BackendSnapshot {
        // Disabling a retired slot is useful for disposing a retained drain and
        // is therefore allowed even though activating one is not.
        self.set_mode(BackendMode::Disabled, false)
            .expect("retired slots may be disabled")
    }

    /// Close the acquisition gate and return a token for this drain epoch.
    ///
    /// Repeating the operation while already draining joins the same epoch.
    pub fn begin_drain(&self) -> DrainToken {
        let mut state = self.lock_state();
        if state.mode != BackendMode::Draining {
            state.mode = BackendMode::Draining;
            state.next_mode_epoch();
            self.publish_locked(&mut state);
        }

        DrainToken {
            backend_id: state.spec.id.clone(),
            mode_epoch: state.mode_epoch,
        }
    }

    /// Wait until every lease included by this drain has been released.
    ///
    /// No timeout is imposed here.  Callers may wrap the future in
    /// `tokio::time::timeout`; dropping the wait future does not cancel or undo
    /// the drain.  A concurrent activate/disable produces `Superseded`, never a
    /// false zero-count success.
    pub async fn wait_for_local_zero(
        &self,
        token: &DrainToken,
    ) -> Result<BackendSnapshot, DrainWaitError> {
        let slot_id = self.id();
        if token.backend_id != slot_id {
            return Err(DrainWaitError::WrongBackend {
                token_backend_id: token.backend_id.clone(),
                slot_backend_id: slot_id,
            });
        }

        // Subscribe before checking.  A transition between these two actions
        // advances the retained watch version, so `changed` then returns
        // immediately instead of losing the notification.
        let mut changes = self.changed.subscribe();
        loop {
            let snapshot = self.snapshot();
            if snapshot.mode != BackendMode::Draining || snapshot.mode_epoch != token.mode_epoch {
                return Err(DrainWaitError::Superseded {
                    backend_id: snapshot.id().clone(),
                    expected_epoch: token.mode_epoch,
                    current_epoch: snapshot.mode_epoch,
                    current_mode: snapshot.mode,
                });
            }
            if snapshot.local_active == 0 {
                return Ok(snapshot);
            }

            // A sender exists for the lifetime of `self`, so closure is not a
            // normal outcome.  Should an implementation change violate that,
            // simply re-checking prevents a false success or a stuck waiter.
            if changes.changed().await.is_err() {
                continue;
            }
        }
    }

    fn set_mode(
        &self,
        mode: BackendMode,
        require_registered: bool,
    ) -> Result<BackendSnapshot, ModeChangeError> {
        let mut state = self.lock_state();
        if require_registered && !state.registered {
            return Err(ModeChangeError::Retired {
                backend_id: state.spec.id.clone(),
            });
        }
        if state.mode != mode {
            state.mode = mode;
            state.next_mode_epoch();
            self.publish_locked(&mut state);
        }

        Ok(state.snapshot(Instant::now()))
    }

    fn reconcile_present(&self, spec: BackendSpec) -> ReconciledSlot {
        let mut state = self.lock_state();
        debug_assert_eq!(state.spec.id, spec.id);
        let was_registered = state.registered;
        let changed_spec = state.spec != spec;

        state.registered = true;
        if changed_spec {
            state.spec = spec;
            state.spec_revision = state
                .spec_revision
                .checked_add(1)
                .expect("backend spec revision exhausted");
        }
        if !was_registered || changed_spec {
            self.publish_locked(&mut state);
        }

        ReconciledSlot {
            revived: !was_registered,
            updated: changed_spec,
        }
    }

    fn reconcile_absent(&self) -> bool {
        let mut state = self.lock_state();
        if !state.registered {
            return false;
        }

        state.registered = false;
        // Preserve a drain epoch so its waiter remains valid after a concurrent
        // config removal.  An active removed backend becomes disabled.
        if state.mode == BackendMode::Active {
            state.mode = BackendMode::Disabled;
            state.next_mode_epoch();
        }
        self.publish_locked(&mut state);
        true
    }

    fn releasable_tombstone(&self) -> bool {
        let state = self.lock_state();
        !state.registered && state.leases.is_empty() && state.mode != BackendMode::Draining
    }

    fn release(&self, key: LeaseKey) {
        let mut state = self.lock_state();
        let removed = state.leases.remove(&key);
        assert!(removed.is_some(), "backend lease released more than once");
        self.publish_locked(&mut state);
    }

    fn publish_locked(&self, state: &mut SlotState) {
        // Publishing while holding the same mutex preserves sequence order when
        // several threads make back-to-back changes.
        let sequence = state.next_sequence();
        self.changed.send_replace(sequence);
    }

    fn lock_state(&self) -> MutexGuard<'_, SlotState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// RAII proof that one request owns local work on a backend.
///
/// The forwarding layer should retain this value while awaiting response
/// headers, then move it into the downstream body completion guard.  Dropping
/// it on any error or cancellation path releases exactly once.
#[must_use = "dropping the lease releases the backend request"]
pub struct BackendLease {
    slot: Arc<BackendSlot>,
    key: Option<LeaseKey>,
    spec: BackendSpec,
}

impl fmt::Debug for BackendLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendLease")
            .field("spec", &self.spec)
            .field("started_at", &self.key.map(|key| key.started_at))
            .finish_non_exhaustive()
    }
}

impl BackendLease {
    pub fn backend_id(&self) -> &BackendId {
        self.spec.id()
    }

    pub fn spec(&self) -> &BackendSpec {
        &self.spec
    }

    pub fn age(&self) -> Duration {
        self.key
            .map(|key| key.started_at.elapsed())
            .unwrap_or_default()
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.slot.release(key);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReconciledSlot {
    revived: bool,
    updated: bool,
}

/// Result of atomically reconciling the registry's membership set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    pub added: Vec<BackendId>,
    pub revived: Vec<BackendId>,
    pub updated: Vec<BackendId>,
    pub retired: Vec<BackendId>,
}

/// Why a registry reconciliation was rejected without changing the registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileError {
    DuplicateBackendId(BackendId),
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBackendId(id) => {
                write!(formatter, "backend {id} appears more than once")
            }
        }
    }
}

impl Error for ReconcileError {}

/// Lookup/acquisition failure at registry scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryAcquireError {
    UnknownBackend(BackendId),
    Unavailable(AcquireError),
}

impl fmt::Display for RegistryAcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBackend(id) => write!(formatter, "unknown backend {id}"),
            Self::Unavailable(error) => error.fmt(formatter),
        }
    }
}

impl Error for RegistryAcquireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnknownBackend(_) => None,
            Self::Unavailable(error) => Some(error),
        }
    }
}

/// Registry of stable backend slots.
///
/// Slots are retained as tombstones after removal so an outstanding lease or
/// drain remains attached to the same counter if the ID is later reconciled
/// back into the desired set.
#[derive(Default)]
pub struct BackendRegistry {
    slots: RwLock<HashMap<BackendId, Arc<BackendSlot>>>,
}

impl fmt::Debug for BackendRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendRegistry")
            .field("snapshots", &self.snapshots())
            .finish()
    }
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a registered slot.  Retired tombstones are intentionally hidden
    /// from ordinary routing lookups.
    pub fn get(&self, id: &BackendId) -> Option<Arc<BackendSlot>> {
        self.get_retained(id)
            .filter(|slot| slot.snapshot().registered)
    }

    /// Return a slot even if reconciliation retired it.
    pub fn get_retained(&self, id: &BackendId) -> Option<Arc<BackendSlot>> {
        self.read_slots().get(id).cloned()
    }

    pub fn try_acquire(&self, id: &BackendId) -> Result<BackendLease, RegistryAcquireError> {
        let slot = self
            .get_retained(id)
            .ok_or_else(|| RegistryAcquireError::UnknownBackend(id.clone()))?;
        slot.try_acquire()
            .map_err(RegistryAcquireError::Unavailable)
    }

    /// Sorted snapshots of registered backends.
    pub fn snapshots(&self) -> Vec<BackendSnapshot> {
        let slots: Vec<_> = self.read_slots().values().cloned().collect();
        let mut snapshots: Vec<_> = slots
            .into_iter()
            .map(|slot| slot.snapshot())
            .filter(|snapshot| snapshot.registered)
            .collect();
        snapshots.sort_by(|left, right| left.id().cmp(right.id()));
        snapshots
    }

    /// Reconcile stable IDs and opaque specs while preserving existing
    /// operator modes and local counters.
    ///
    /// New slots start `Disabled`; callers explicitly activate them after any
    /// higher-level validation or health check.  Missing active slots become
    /// retired and disabled.  Missing draining slots retain their drain epoch,
    /// allowing an in-progress waiter to complete.  The method validates all
    /// duplicate IDs before making any mutation.
    pub fn reconcile<I>(&self, specs: I) -> Result<ReconcileReport, ReconcileError>
    where
        I: IntoIterator<Item = BackendSpec>,
    {
        let mut desired = HashMap::<BackendId, BackendSpec>::new();
        for spec in specs {
            let id = spec.id.clone();
            if desired.insert(id.clone(), spec).is_some() {
                return Err(ReconcileError::DuplicateBackendId(id));
            }
        }

        let mut report = ReconcileReport::default();
        let mut slots = self.write_slots();

        for (id, slot) in slots.iter() {
            if !desired.contains_key(id) && slot.reconcile_absent() {
                report.retired.push(id.clone());
            }
        }

        for (id, spec) in desired {
            match slots.get(&id) {
                Some(slot) => {
                    let outcome = slot.reconcile_present(spec);
                    if outcome.revived {
                        report.revived.push(id.clone());
                    }
                    if outcome.updated {
                        report.updated.push(id);
                    }
                }
                None => {
                    slots.insert(id.clone(), BackendSlot::new(spec, BackendMode::Disabled));
                    report.added.push(id);
                }
            }
        }

        report.added.sort();
        report.revived.sort();
        report.updated.sort();
        report.retired.sort();
        Ok(report)
    }

    /// Remove quiescent retired tombstones which have no drain waiter state to
    /// preserve.  This is optional housekeeping, not part of reconciliation.
    pub fn prune_retired(&self) -> Vec<BackendId> {
        let mut slots = self.write_slots();
        let mut removed = Vec::new();
        slots.retain(|id, slot| {
            let retain = !slot.releasable_tombstone();
            if !retain {
                removed.push(id.clone());
            }
            retain
        });
        removed.sort();
        removed
    }

    fn read_slots(&self) -> RwLockReadGuard<'_, HashMap<BackendId, Arc<BackendSlot>>> {
        self.slots
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_slots(&self) -> RwLockWriteGuard<'_, HashMap<BackendId, Arc<BackendSlot>>> {
        self.slots
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, Barrier, mpsc},
        thread,
    };

    use super::*;

    fn spec(id: &str, endpoint: &str) -> BackendSpec {
        BackendSpec::new(id, endpoint)
    }

    fn active_slot(id: &str) -> Arc<BackendSlot> {
        BackendSlot::new(spec(id, "backend-a"), BackendMode::Active)
    }

    #[tokio::test]
    async fn acquire_before_drain_is_counted_until_the_lease_drops() {
        let slot = active_slot("a");
        let lease = slot.try_acquire().unwrap();
        let token = slot.begin_drain();

        assert_eq!(slot.snapshot().local_active, 1);
        assert_eq!(
            slot.try_acquire().unwrap_err(),
            AcquireError::NotActive {
                backend_id: BackendId::from("a"),
                mode: BackendMode::Draining,
            }
        );

        let waiter = {
            let slot = Arc::clone(&slot);
            let token = token.clone();
            tokio::spawn(async move { slot.wait_for_local_zero(&token).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(lease);
        let drained = waiter.await.unwrap().unwrap();
        assert!(drained.locally_drained());
        assert_eq!(drained.local_active, 0);
    }

    #[test]
    fn drain_before_acquire_rejects_the_request() {
        let slot = active_slot("a");
        let first = slot.begin_drain();
        let repeated = slot.begin_drain();

        assert_eq!(first, repeated, "repeated drains join one epoch");
        assert!(matches!(
            slot.try_acquire(),
            Err(AcquireError::NotActive {
                mode: BackendMode::Draining,
                ..
            })
        ));
        assert!(slot.snapshot().locally_drained());
    }

    #[tokio::test]
    async fn concurrent_acquire_and_drain_have_only_linearizable_outcomes() {
        // The barrier starts both operations together without sleeps.  Whichever
        // takes the gate first determines the allowed outcome; both outcomes
        // prove the same invariant and are asserted exactly.
        let slot = active_slot("a");
        let barrier = Arc::new(Barrier::new(3));
        let (lease_tx, lease_rx) = mpsc::channel();
        let (drain_tx, drain_rx) = mpsc::channel();

        let acquire_thread = {
            let slot = Arc::clone(&slot);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                lease_tx.send(slot.try_acquire()).unwrap();
            })
        };
        let drain_thread = {
            let slot = Arc::clone(&slot);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                drain_tx.send(slot.begin_drain()).unwrap();
            })
        };

        barrier.wait();
        let lease = lease_rx.recv().unwrap();
        let token = drain_rx.recv().unwrap();
        acquire_thread.join().unwrap();
        drain_thread.join().unwrap();

        match lease {
            Ok(lease) => {
                assert_eq!(slot.snapshot().local_active, 1);
                drop(lease);
            }
            Err(AcquireError::NotActive {
                mode: BackendMode::Draining,
                ..
            }) => assert_eq!(slot.snapshot().local_active, 0),
            Err(other) => panic!("unexpected acquire result: {other}"),
        }
        assert!(
            slot.wait_for_local_zero(&token)
                .await
                .unwrap()
                .locally_drained()
        );
    }

    #[tokio::test]
    async fn activating_supersedes_a_waiter_instead_of_returning_false_success() {
        let slot = active_slot("a");
        let lease = slot.try_acquire().unwrap();
        let token = slot.begin_drain();
        let waiter = {
            let slot = Arc::clone(&slot);
            let token = token.clone();
            tokio::spawn(async move { slot.wait_for_local_zero(&token).await })
        };

        slot.activate().unwrap();
        drop(lease);

        assert!(matches!(
            waiter.await.unwrap(),
            Err(DrainWaitError::Superseded {
                current_mode: BackendMode::Active,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn aborting_a_task_drops_its_lease_and_wakes_the_drain() {
        let slot = active_slot("a");
        let lease = slot.try_acquire().unwrap();
        let task = tokio::spawn(async move {
            let _lease = lease;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        let token = slot.begin_drain();
        task.abort();
        let _ = task.await;

        assert!(
            slot.wait_for_local_zero(&token)
                .await
                .unwrap()
                .locally_drained()
        );
    }

    #[test]
    fn unwinding_drops_a_lease_exactly_once() {
        let slot = active_slot("a");
        let result = catch_unwind(AssertUnwindSafe({
            let lease = slot.try_acquire().unwrap();
            move || {
                let _lease = lease;
                panic!("request task failed");
            }
        }));

        assert!(result.is_err());
        assert_eq!(slot.snapshot().local_active, 0);
    }

    #[test]
    fn snapshot_tracks_count_and_the_oldest_live_lease() {
        let slot = active_slot("a");
        let first = slot.try_acquire().unwrap();
        let second = slot.try_acquire().unwrap();

        let both = slot.snapshot();
        assert_eq!(both.local_active, 2);
        assert!(both.oldest_active_age.is_some());

        drop(first);
        let one = slot.snapshot();
        assert_eq!(one.local_active, 1);
        assert!(one.oldest_active_age.is_some());

        drop(second);
        let zero = slot.snapshot();
        assert_eq!(zero.local_active, 0);
        assert_eq!(zero.oldest_active_age, None);
    }

    #[tokio::test]
    async fn reconcile_preserves_specs_captured_by_old_leases_and_drain_state() {
        let registry = BackendRegistry::new();
        let added = registry.reconcile([spec("a", "old")]).unwrap();
        assert_eq!(added.added, vec![BackendId::from("a")]);

        let id = BackendId::from("a");
        let slot = registry.get(&id).unwrap();
        slot.activate().unwrap();
        let old_lease = registry.try_acquire(&id).unwrap();
        assert_eq!(old_lease.spec().endpoint(), "old");

        let changed = registry.reconcile([spec("a", "new")]).unwrap();
        assert_eq!(changed.updated, vec![id.clone()]);
        let new_lease = registry.try_acquire(&id).unwrap();
        assert_eq!(new_lease.spec().endpoint(), "new");
        assert_eq!(old_lease.spec().endpoint(), "old");

        let token = slot.begin_drain();
        let removed = registry.reconcile([]).unwrap();
        assert_eq!(removed.retired, vec![id.clone()]);
        assert_eq!(slot.snapshot().mode, BackendMode::Draining);
        assert!(registry.get(&id).is_none());

        drop(old_lease);
        drop(new_lease);
        assert!(
            slot.wait_for_local_zero(&token)
                .await
                .unwrap()
                .locally_drained()
        );

        // Reconciliation revives the same slot and preserves the operator
        // drain.  It cannot silently make the backend active again.
        let revived = registry.reconcile([spec("a", "new")]).unwrap();
        assert_eq!(revived.revived, vec![id.clone()]);
        assert!(Arc::ptr_eq(&slot, &registry.get(&id).unwrap()));
        assert_eq!(slot.snapshot().mode, BackendMode::Draining);
        assert!(registry.try_acquire(&id).is_err());
    }

    #[test]
    fn duplicate_reconcile_is_rejected_before_mutating_membership() {
        let registry = BackendRegistry::new();
        registry.reconcile([spec("existing", "one")]).unwrap();
        let before = registry.snapshots();

        let error = registry
            .reconcile([spec("duplicate", "one"), spec("duplicate", "two")])
            .unwrap_err();

        assert_eq!(
            error,
            ReconcileError::DuplicateBackendId(BackendId::from("duplicate"))
        );
        assert_eq!(registry.snapshots(), before);
    }

    #[test]
    fn quiescent_disabled_tombstones_can_be_pruned() {
        let registry = BackendRegistry::new();
        let id = BackendId::from("a");
        registry.reconcile([spec("a", "one")]).unwrap();
        registry.reconcile([]).unwrap();

        assert!(registry.get_retained(&id).is_some());
        assert_eq!(registry.prune_retired(), vec![id.clone()]);
        assert!(registry.get_retained(&id).is_none());
    }
}
