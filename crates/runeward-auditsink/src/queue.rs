//! The bounded, drop-oldest queue and worker plumbing shared by the network
//! sinks.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Default bound on buffered events before the oldest is dropped.
pub(crate) const DEFAULT_QUEUE_SIZE: usize = 1024;
/// Minimum interval between "dropping events" warnings.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct State<T> {
    items: VecDeque<T>,
    closed: bool,
}

/// A bounded queue whose `push` never blocks: when full, the oldest item is
/// discarded to make room so the newest data keeps flowing.
pub(crate) struct DropQueue<T> {
    state: Mutex<State<T>>,
    cv: Condvar,
    cap: usize,
}

impl<T> DropQueue<T> {
    pub(crate) fn new(cap: usize) -> Self {
        let cap = if cap == 0 { DEFAULT_QUEUE_SIZE } else { cap };
        Self {
            state: Mutex::new(State {
                items: VecDeque::with_capacity(cap.min(64)),
                closed: false,
            }),
            cv: Condvar::new(),
            cap,
        }
    }

    /// Enqueues `item`, returning true when an older item had to be dropped.
    pub(crate) fn push(&self, item: T) -> bool {
        let mut st = lock(&self.state);
        // The worker only waits on an empty queue, so only the push that
        // makes the queue non-empty needs to wake it.
        let was_empty = st.items.is_empty();
        let dropped = if st.items.len() >= self.cap {
            st.items.pop_front()
        } else {
            None
        };
        st.items.push_back(item);
        drop(st);
        if was_empty {
            self.cv.notify_all();
        }
        // Free the dropped item outside the lock.
        dropped.is_some()
    }

    /// Blocks for the next item. After [`close`](Self::close) it keeps
    /// returning queued items and yields `None` once the queue is drained.
    pub(crate) fn pop(&self) -> Option<T> {
        let mut st = lock(&self.state);
        loop {
            if let Some(item) = st.items.pop_front() {
                return Some(item);
            }
            if st.closed {
                return None;
            }
            st = self.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Signals the worker to drain and stop.
    pub(crate) fn close(&self) {
        lock(&self.state).closed = true;
        self.cv.notify_all();
    }

    /// Sleeps up to `d`, returning true early if the queue was closed.
    pub(crate) fn wait_closed(&self, d: Duration) -> bool {
        let deadline = Instant::now() + d;
        let mut st = lock(&self.state);
        while !st.closed {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// Counts dropped events and throttles the warning about them, lock-free so
/// a saturated queue stays cheap to push into.
pub(crate) struct DropCounter {
    dropped: AtomicI64,
    /// Nanoseconds since `epoch` of the last warning; negative before the
    /// first one.
    last_log: AtomicI64,
    epoch: Instant,
}

impl Default for DropCounter {
    fn default() -> Self {
        Self {
            dropped: AtomicI64::new(0),
            last_log: AtomicI64::new(i64::MIN),
            epoch: Instant::now(),
        }
    }
}

impl DropCounter {
    /// Records one drop and returns the running total when a (throttled)
    /// warning should be logged now.
    pub(crate) fn record(&self) -> Option<i64> {
        let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let now = i64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(i64::MAX);
        let last = self.last_log.load(Ordering::Relaxed);
        let interval = i64::try_from(DROP_LOG_INTERVAL.as_nanos()).unwrap_or(i64::MAX);
        if (last == i64::MIN || now.saturating_sub(last) >= interval)
            && self
                .last_log
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(n);
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn total(&self) -> i64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Lets `close` wait, with a timeout, for a worker thread to finish and
/// collect its exit value.
pub(crate) struct Joiner<R> {
    rx: Mutex<Option<Receiver<R>>>,
}

impl<R> Joiner<R> {
    pub(crate) fn new() -> (SyncSender<R>, Self) {
        let (tx, rx) = mpsc::sync_channel(1);
        (
            tx,
            Self {
                rx: Mutex::new(Some(rx)),
            },
        )
    }

    /// Waits up to `timeout` for the worker's exit value. Returns
    /// `Ok(None)` if a previous call already collected it (or the worker
    /// vanished), and `Err(())` on timeout.
    pub(crate) fn wait(&self, timeout: Duration) -> Result<Option<R>, ()> {
        let mut guard = lock(&self.rx);
        let Some(rx) = guard.as_ref() else {
            return Ok(None);
        };
        match rx.recv_timeout(timeout) {
            Ok(r) => {
                *guard = None;
                Ok(Some(r))
            }
            Err(RecvTimeoutError::Disconnected) => {
                *guard = None;
                Ok(None)
            }
            Err(RecvTimeoutError::Timeout) => Err(()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn push_drops_oldest_when_full() {
        let q = DropQueue::new(2);
        assert!(!q.push(1));
        assert!(!q.push(2));
        assert!(q.push(3));
        q.close();
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn wait_closed_wakes_on_close() {
        let q = std::sync::Arc::new(DropQueue::<i32>::new(1));
        let q2 = q.clone();
        let h = std::thread::spawn(move || q2.wait_closed(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(20));
        q.close();
        assert!(h.join().unwrap());
        assert!(!DropQueue::<i32>::new(1).wait_closed(Duration::from_millis(5)));
    }

    #[test]
    fn drop_counter_throttles() {
        let c = DropCounter::default();
        assert_eq!(c.record(), Some(1));
        assert_eq!(c.record(), None);
        assert_eq!(c.total(), 2);
    }
}
