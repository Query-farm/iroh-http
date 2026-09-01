//! Typed lifecycle objects for the serve loop (Slice C.4 of #182, closes #178).
//!
//! [`ConnectionTracker`] folds the previous inline `PeerConnectionGuard` +
//! `TotalGuard` into a single Drop-owning object. [`RequestTracker`] owns the
//! public active-request statistic, while [`DeliveryTracker`] owns the private
//! graceful-drain boundary through transport acknowledgement.
//!
//! Counter mutations and connect/disconnect-event firing happen exactly once
//! in `acquire` / `Drop`, so a future change can no longer drift between
//! sites.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::ConnectionEvent;

use super::ConnectionEventFn;

// ── ConnectionTracker ─────────────────────────────────────────────────────────

/// Which shared connection-admission bound rejected a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionAdmissionError {
    Total,
    Peer,
}

/// Runtime-wide connection admission shared by every router handler clone.
pub(crate) struct ConnectionAdmission {
    counts: Mutex<HashMap<iroh::PublicKey, usize>>,
    total: Arc<AtomicUsize>,
    max_per_peer: usize,
    max_total: usize,
    on_event: Option<ConnectionEventFn>,
    released: Arc<tokio::sync::Notify>,
}

impl ConnectionAdmission {
    pub(crate) fn new(
        max_per_peer: usize,
        max_total: usize,
        total: Arc<AtomicUsize>,
        on_event: Option<ConnectionEventFn>,
    ) -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::new(HashMap::new()),
            total,
            max_per_peer,
            max_total,
            on_event,
            released: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub(crate) fn acquire(
        self: &Arc<Self>,
        peer: iroh::PublicKey,
        peer_id_str: String,
    ) -> Result<ConnectionTracker, ConnectionAdmissionError> {
        // One lock covers both limits, so concurrent connections from
        // different peers cannot race through the total-cap check.
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.total.load(Ordering::Relaxed) >= self.max_total {
            return Err(ConnectionAdmissionError::Total);
        }
        let count = counts.entry(peer).or_insert(0);
        if *count >= self.max_per_peer {
            return Err(ConnectionAdmissionError::Peer);
        }
        let was_zero = *count == 0;
        *count = count.saturating_add(1);
        self.total.fetch_add(1, Ordering::Relaxed);
        drop(counts);

        if was_zero {
            if let Some(callback) = &self.on_event {
                callback(ConnectionEvent {
                    peer_id: peer_id_str.clone(),
                    connected: true,
                });
            }
        }

        Ok(ConnectionTracker {
            admission: Arc::clone(self),
            peer,
            peer_id_str,
        })
    }

    pub(crate) fn total(&self) -> &AtomicUsize {
        &self.total
    }

    pub(crate) fn released(&self) -> &tokio::sync::Notify {
        &self.released
    }
}

/// Per-connection lifecycle. Drop releases the runtime-wide total/per-peer
/// admission slot and fires disconnect on the final connection from a peer.
pub(crate) struct ConnectionTracker {
    admission: Arc<ConnectionAdmission>,
    peer: iroh::PublicKey,
    peer_id_str: String,
}

impl Drop for ConnectionTracker {
    fn drop(&mut self) {
        let mut map = self
            .admission
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut disconnected = false;
        if let Some(c) = map.get_mut(&self.peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                map.remove(&self.peer);
                disconnected = true;
            }
        }
        self.admission.total.fetch_sub(1, Ordering::Release);
        drop(map);
        self.admission.released.notify_waiters();

        if disconnected {
            if let Some(callback) = &self.admission.on_event {
                callback(ConnectionEvent {
                    peer_id: self.peer_id_str.clone(),
                    connected: false,
                });
            }
        }
    }
}

// ── RequestTracker ────────────────────────────────────────────────────────────

/// Per-request processing lifecycle exposed through endpoint statistics.
pub(crate) struct RequestTracker {
    counter: Arc<AtomicUsize>,
}

impl RequestTracker {
    /// Own a request slot already incremented by the accept loop.
    pub(crate) fn new(counter: Arc<AtomicUsize>) -> Self {
        RequestTracker { counter }
    }
}

impl Drop for RequestTracker {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── DeliveryTracker ──────────────────────────────────────────────────────────

/// Private graceful-drain lifecycle. A request remains delivery-in-flight until
/// the response stream is transport-acknowledged, stopped, or its connection
/// fails. This deliberately does not affect public active-request statistics.
pub(crate) struct DeliveryTracker {
    in_flight: Arc<AtomicUsize>,
    drain_notify: Arc<tokio::sync::Notify>,
}

impl DeliveryTracker {
    /// Own a delivery slot already incremented by the accept loop.
    pub(crate) fn new(in_flight: Arc<AtomicUsize>, drain_notify: Arc<tokio::sync::Notify>) -> Self {
        DeliveryTracker {
            in_flight,
            drain_notify,
        }
    }
}

impl Drop for DeliveryTracker {
    fn drop(&mut self) {
        if self.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Last in-flight delivery completed — signal drain.
            self.drain_notify.notify_waiters();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_peer() -> iroh::PublicKey {
        iroh::SecretKey::generate().public()
    }

    #[test]
    fn connection_tracker_increments_and_decrements_total() {
        let total = Arc::new(AtomicUsize::new(0));
        let admission = ConnectionAdmission::new(4, 8, total.clone(), None);
        let peer = dummy_peer();
        {
            let _tracker = admission
                .acquire(peer, "p".to_string())
                .expect("acquire should succeed under cap");
            assert_eq!(total.load(Ordering::Relaxed), 1);
        }
        assert_eq!(total.load(Ordering::Relaxed), 0);
        assert!(admission.counts.lock().unwrap().is_empty());
    }

    #[test]
    fn connection_tracker_enforces_shared_total_and_per_peer_caps() {
        let total = Arc::new(AtomicUsize::new(0));
        let admission = ConnectionAdmission::new(1, 2, total.clone(), None);
        let peer = dummy_peer();
        let _first = admission.acquire(peer, "p".into()).unwrap();
        assert!(matches!(
            admission.acquire(peer, "p".into()),
            Err(ConnectionAdmissionError::Peer),
        ));
        let _second = admission.acquire(dummy_peer(), "q".into()).unwrap();
        assert!(matches!(
            admission.acquire(dummy_peer(), "r".into()),
            Err(ConnectionAdmissionError::Total),
        ));
        assert_eq!(total.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn delivery_tracker_notifies_when_in_flight_reaches_zero() {
        let counter = Arc::new(AtomicUsize::new(1));
        let in_flight = Arc::new(AtomicUsize::new(1));
        let drain = Arc::new(tokio::sync::Notify::new());

        let waiter = drain.clone();
        let waited = tokio::spawn(async move {
            waiter.notified().await;
        });

        // Give the waiter a chance to register.
        tokio::task::yield_now().await;

        let request = RequestTracker::new(counter.clone());
        let delivery = DeliveryTracker::new(in_flight.clone(), drain.clone());

        drop(request);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(in_flight.load(Ordering::Relaxed), 1);

        drop(delivery);

        tokio::time::timeout(std::time::Duration::from_millis(100), waited)
            .await
            .expect("waiter must be notified")
            .unwrap();

        assert_eq!(in_flight.load(Ordering::Relaxed), 0);
    }
}
