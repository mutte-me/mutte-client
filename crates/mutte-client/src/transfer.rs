use std::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};
use tokio::sync::watch;

#[derive(Debug)]
pub struct AttachmentCancelled;
impl std::fmt::Display for AttachmentCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("attachment cancelled")
    }
}
impl std::error::Error for AttachmentCancelled {}

/// One-use control, independent of the engine/vault lock. State 2 reserves the
/// non-interruptible local commit: a late cancel must never claim success.
pub struct AttachmentCancellation {
    started: AtomicBool,
    state: AtomicU8,
    signal: watch::Sender<bool>,
}
impl Default for AttachmentCancellation {
    fn default() -> Self {
        Self {
            started: AtomicBool::new(false),
            state: AtomicU8::new(0),
            signal: watch::channel(false).0,
        }
    }
}
impl AttachmentCancellation {
    pub fn start(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.started.swap(true, Ordering::SeqCst),
            "attachment cancellation control cannot be reused"
        );
        Ok(())
    }
    pub fn cancel(&self) -> bool {
        if self
            .state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.signal.send_replace(true);
            true
        } else {
            self.is_cancelled()
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::SeqCst) == 1
    }
    pub fn finish(&self) {
        let _ = self
            .state
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
    }
    pub fn begin_commit(&self) -> anyhow::Result<()> {
        self.state
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| AttachmentCancelled.into())
    }
    pub async fn run<T>(
        &self,
        operation: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let mut signal = self.signal.subscribe();
        if self.is_cancelled() {
            return Err(AttachmentCancelled.into());
        }
        tokio::select! {
            biased;
            _ = signal.changed() => Err(AttachmentCancelled.into()),
            result = operation => result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AttachmentDirection {
    Upload,
    Download,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferPhase {
    Preparing,
    Transferring,
    Finalizing,
    Cancelling,
}

/// Content-free counters, readable without the engine/vault mutex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferProgress {
    pub attachment_id: uuid::Uuid,
    pub direction: AttachmentDirection,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub phase: TransferPhase,
    pub explicit: bool,
}

/// Exact-file controls for active and durably known queued transfers. Queue
/// refreshes preserve accepted intent until the engine can commit local cleanup.
#[derive(Default)]
pub struct ActiveAttachmentTransfers {
    entries: std::sync::Mutex<
        std::collections::HashMap<(uuid::Uuid, AttachmentDirection), TransferEntry>,
    >,
}
struct TransferEntry {
    active: bool,
    progress: Option<TransferProgress>,
    control: std::sync::Arc<AttachmentCancellation>,
}
pub(crate) struct ActiveTransferLease {
    registry: std::sync::Arc<ActiveAttachmentTransfers>,
    key: (uuid::Uuid, AttachmentDirection),
    control: std::sync::Arc<AttachmentCancellation>,
}
impl ActiveAttachmentTransfers {
    pub fn progress(&self) -> Vec<TransferProgress> {
        let Ok(entries) = self.entries.lock() else {
            return vec![];
        };
        entries
            .values()
            .filter(|entry| entry.active)
            .filter_map(|entry| {
                let mut progress = entry.progress.clone()?;
                if entry.control.is_cancelled() {
                    progress.phase = TransferPhase::Cancelling;
                }
                Some(progress)
            })
            .collect()
    }

    pub(crate) fn report_progress(
        &self,
        id: uuid::Uuid,
        direction: AttachmentDirection,
        control: &AttachmentCancellation,
        completed_bytes: u64,
        total_bytes: u64,
        phase: TransferPhase,
    ) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let Some(entry) = entries.get_mut(&(id, direction)) else {
            return false;
        };
        if !entry.active
            || !std::ptr::eq(entry.control.as_ref(), control)
            || completed_bytes > total_bytes
        {
            return false;
        }
        if entry.progress.as_ref().is_some_and(|old| {
            completed_bytes < old.completed_bytes
                || (old.total_bytes != 0 && old.total_bytes != total_bytes)
        }) {
            return false;
        }
        let explicit = entry.progress.as_ref().is_some_and(|item| item.explicit);
        entry.progress = Some(TransferProgress {
            attachment_id: id,
            direction,
            completed_bytes,
            total_bytes,
            phase,
            explicit,
        });
        true
    }

    pub fn cancel(&self, id: uuid::Uuid, direction: AttachmentDirection) -> bool {
        let Ok(entries) = self.entries.lock() else {
            return false;
        };
        entries
            .get(&(id, direction))
            .is_some_and(|entry| entry.control.cancel())
    }
    pub(crate) fn prepare_pending(
        &self,
        keys: impl IntoIterator<Item = (uuid::Uuid, AttachmentDirection)>,
    ) -> anyhow::Result<()> {
        let pending: std::collections::HashSet<_> = keys.into_iter().collect();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry unavailable"))?;
        entries.retain(|key, entry| entry.active || pending.contains(key));
        for key in pending {
            entries.entry(key).or_insert_with(|| TransferEntry {
                active: false,
                progress: None,
                control: Default::default(),
            });
        }
        Ok(())
    }
    pub(crate) fn cancelled_pending(
        &self,
    ) -> anyhow::Result<Vec<(uuid::Uuid, AttachmentDirection)>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry unavailable"))?;
        Ok(entries
            .iter()
            .filter(|(_, entry)| !entry.active && entry.control.is_cancelled())
            .map(|(key, _)| *key)
            .collect())
    }
    pub(crate) fn register(
        self: &std::sync::Arc<Self>,
        id: uuid::Uuid,
        direction: AttachmentDirection,
        control: std::sync::Arc<AttachmentCancellation>,
        explicit: bool,
    ) -> anyhow::Result<ActiveTransferLease> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("transfer registry unavailable"))?;
        anyhow::ensure!(
            !entries.values().any(|entry| entry.active),
            "another attachment is active"
        );
        let key = (id, direction);
        if entries
            .get(&key)
            .is_some_and(|entry| entry.control.is_cancelled())
        {
            control.cancel();
        }
        entries.insert(
            key,
            TransferEntry {
                active: true,
                progress: Some(TransferProgress {
                    attachment_id: id,
                    direction,
                    completed_bytes: 0,
                    total_bytes: 0,
                    phase: TransferPhase::Preparing,
                    explicit,
                }),
                control: control.clone(),
            },
        );
        Ok(ActiveTransferLease {
            registry: self.clone(),
            key,
            control,
        })
    }
}
impl Drop for ActiveTransferLease {
    fn drop(&mut self) {
        self.control.finish();
        if let Ok(mut entries) = self.registry.entries.lock()
            && entries
                .get(&self.key)
                .is_some_and(|entry| std::sync::Arc::ptr_eq(&entry.control, &self.control))
        {
            if self.control.is_cancelled() {
                // Keep accepted intent until a queue refresh confirms that
                // durable cleanup removed the file, including storage errors.
                let entry = entries.get_mut(&self.key).unwrap();
                entry.active = false;
                entry.progress = None;
            } else {
                entries.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    #[test]
    fn progress_is_live_bounded_and_scoped_to_the_current_attempt() {
        let registry = Arc::new(ActiveAttachmentTransfers::default());
        let id = uuid::Uuid::new_v4();
        let control = Arc::new(AttachmentCancellation::default());
        let lease = registry
            .register(id, AttachmentDirection::Upload, control.clone(), false)
            .unwrap();
        assert!(registry.report_progress(
            id,
            AttachmentDirection::Upload,
            &control,
            250,
            1000,
            TransferPhase::Transferring
        ));
        let progress = registry.progress();
        assert_eq!(progress[0].completed_bytes, 250);
        assert_eq!(progress[0].total_bytes, 1000);
        assert!(!registry.report_progress(
            id,
            AttachmentDirection::Upload,
            &control,
            1001,
            1000,
            TransferPhase::Transferring
        ));
        assert!(!registry.report_progress(
            id,
            AttachmentDirection::Upload,
            &control,
            10,
            1000,
            TransferPhase::Transferring
        ));
        assert!(registry.report_progress(
            id,
            AttachmentDirection::Upload,
            &control,
            1000,
            1000,
            TransferPhase::Finalizing
        ));
        assert_eq!(registry.progress()[0].phase, TransferPhase::Finalizing);
        drop(lease);
        assert!(registry.progress().is_empty());
        let next = Arc::new(AttachmentCancellation::default());
        let _lease = registry
            .register(id, AttachmentDirection::Upload, next, false)
            .unwrap();
        assert!(!registry.report_progress(
            id,
            AttachmentDirection::Upload,
            &control,
            500,
            1000,
            TransferPhase::Transferring
        ));
        assert!(registry.cancel(id, AttachmentDirection::Upload));
        assert_eq!(registry.progress()[0].phase, TransferPhase::Cancelling);
    }

    #[test]
    fn queued_cancellation_survives_refresh_and_is_scoped_to_its_file() {
        let registry = Arc::new(ActiveAttachmentTransfers::default());
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let keys = [
            (first, AttachmentDirection::Upload),
            (second, AttachmentDirection::Download),
        ];
        registry.prepare_pending(keys).unwrap();
        let running = Arc::new(AttachmentCancellation::default());
        let lease = registry
            .register(first, AttachmentDirection::Upload, running.clone(), false)
            .unwrap();
        assert!(registry.cancel(second, AttachmentDirection::Download));
        assert!(!running.is_cancelled());
        registry.prepare_pending(keys).unwrap();
        drop(lease);
        let next = Arc::new(AttachmentCancellation::default());
        let _lease = registry
            .register(second, AttachmentDirection::Download, next.clone(), false)
            .unwrap();
        assert!(
            next.is_cancelled(),
            "entering a queued transfer must preserve the earlier cancel"
        );
    }

    #[test]
    fn obsolete_queue_entries_are_removed_without_touching_active_work() {
        let registry = Arc::new(ActiveAttachmentTransfers::default());
        let id = uuid::Uuid::new_v4();
        registry
            .prepare_pending([(id, AttachmentDirection::Upload)])
            .unwrap();
        registry.prepare_pending([]).unwrap();
        assert!(!registry.cancel(id, AttachmentDirection::Upload));
        let control = Arc::new(AttachmentCancellation::default());
        let _lease = registry
            .register(id, AttachmentDirection::Upload, control, false)
            .unwrap();
        registry.prepare_pending([]).unwrap();
        assert!(registry.cancel(id, AttachmentDirection::Upload));
    }

    #[test]
    fn registry_targets_exact_file_and_direction_and_retires_old_attempts() {
        let registry = Arc::new(ActiveAttachmentTransfers::default());
        let id = uuid::Uuid::new_v4();
        let first = Arc::new(AttachmentCancellation::default());
        let lease = registry
            .register(id, AttachmentDirection::Upload, first.clone(), false)
            .unwrap();
        assert!(!registry.cancel(uuid::Uuid::new_v4(), AttachmentDirection::Upload));
        assert!(!registry.cancel(id, AttachmentDirection::Download));
        assert!(registry.cancel(id, AttachmentDirection::Upload));
        drop(lease);
        assert!(
            registry
                .cancelled_pending()
                .unwrap()
                .contains(&(id, AttachmentDirection::Upload))
        );
        registry.prepare_pending([]).unwrap(); // Durable cleanup has removed the file.
        assert!(!registry.cancel(id, AttachmentDirection::Upload));
        let next = Arc::new(AttachmentCancellation::default());
        let _lease = registry
            .register(id, AttachmentDirection::Upload, next.clone(), false)
            .unwrap();
        assert!(first.cancel());
        assert!(!next.is_cancelled());
        next.begin_commit().unwrap();
        assert!(!registry.cancel(id, AttachmentDirection::Upload));
    }

    #[test]
    fn registry_cannot_replace_an_active_transfer_and_drop_finishes_it() {
        let registry = Arc::new(ActiveAttachmentTransfers::default());
        let control = Arc::new(AttachmentCancellation::default());
        let id = uuid::Uuid::new_v4();
        let lease = registry
            .register(id, AttachmentDirection::Download, control.clone(), false)
            .unwrap();
        assert!(
            registry
                .register(id, AttachmentDirection::Upload, Arc::default(), false)
                .is_err()
        );
        drop(lease);
        assert!(!control.cancel());
        assert!(!registry.cancel(id, AttachmentDirection::Download));
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_stalled_transfer_without_its_state_lock() {
        let control = Arc::new(AttachmentCancellation::default());
        let waiting = control.clone();
        let task = tokio::spawn(async move {
            waiting
                .run(std::future::pending::<anyhow::Result<()>>())
                .await
        });
        assert!(control.cancel());
        let error = tokio::time::timeout(Duration::from_millis(250), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is::<AttachmentCancelled>());
    }

    #[test]
    fn cancellation_and_commit_are_mutually_exclusive() {
        let cancelled = AttachmentCancellation::default();
        assert!(cancelled.cancel());
        assert!(cancelled.begin_commit().is_err());
        let committed = AttachmentCancellation::default();
        committed.begin_commit().unwrap();
        assert!(!committed.cancel());
        assert!(!committed.is_cancelled());
    }

    #[test]
    fn control_is_one_use_and_finished_operations_reject_cancellation() {
        let control = AttachmentCancellation::default();
        control.start().unwrap();
        assert!(control.start().is_err());
        control.finish();
        assert!(!control.cancel());
    }
}
