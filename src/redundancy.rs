//! Redundancy / failed-proxy recheck — the original's "Recheck failed proxy each
//! (sec.)" (fnd_13: Redundancy Options). When a proxy server fails to connect,
//! it is marked DOWN; further attempts fail fast (instead of waiting out the
//! full connect timeout) until the recheck interval elapses, at which point the
//! next attempt is allowed to probe it again and, on success, clears the mark.
//!
//! The state machine takes an explicit `now` so the recheck window is testable
//! without sleeping; the thin global helpers feed it `Instant::now()`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Redundancy {
    // proxy id -> when it last failed
    down: HashMap<u32, Instant>,
}

impl Redundancy {
    /// Is `id` usable right now? True if it was never marked down, or it has been
    /// down at least `recheck_secs` (so we let a probe through). `recheck_secs==0`
    /// disables fail-fast entirely (always usable).
    pub fn is_available(&self, id: u32, now: Instant, recheck_secs: u64) -> bool {
        if recheck_secs == 0 {
            return true;
        }
        match self.down.get(&id) {
            None => true,
            Some(&failed_at) => now.duration_since(failed_at) >= Duration::from_secs(recheck_secs),
        }
    }

    pub fn note_failure(&mut self, id: u32, now: Instant) {
        self.down.insert(id, now);
    }

    pub fn note_success(&mut self, id: u32) {
        self.down.remove(&id);
    }

    pub fn is_down(&self, id: u32) -> bool {
        self.down.contains_key(&id)
    }

    pub fn down_count(&self) -> usize {
        self.down.len()
    }
}

static STATE: OnceLock<Mutex<Redundancy>> = OnceLock::new();
fn state() -> &'static Mutex<Redundancy> {
    STATE.get_or_init(|| Mutex::new(Redundancy::default()))
}

/// Process-global checks used by the engine (a down proxy should fail fast).
pub fn is_available(id: u32, recheck_secs: u64) -> bool {
    let g = state().lock().unwrap_or_else(|e| e.into_inner());
    g.is_available(id, Instant::now(), recheck_secs)
}

pub fn note_failure(id: u32) {
    let mut g = state().lock().unwrap_or_else(|e| e.into_inner());
    g.note_failure(id, Instant::now());
}

pub fn note_success(id: u32) {
    let mut g = state().lock().unwrap_or_else(|e| e.into_inner());
    g.note_success(id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_failed_is_available() {
        let r = Redundancy::default();
        assert!(r.is_available(1, Instant::now(), 60));
    }

    #[test]
    fn failed_proxy_unavailable_until_recheck_window_elapses() {
        let mut r = Redundancy::default();
        let t0 = Instant::now();
        r.note_failure(7, t0);
        // Immediately after failure: down -> not available (fail fast).
        assert!(!r.is_available(7, t0 + Duration::from_secs(1), 60));
        assert!(!r.is_available(7, t0 + Duration::from_secs(59), 60));
        // At/after the recheck interval: a probe is allowed.
        assert!(r.is_available(7, t0 + Duration::from_secs(60), 60));
        assert!(r.is_available(7, t0 + Duration::from_secs(120), 60));
    }

    #[test]
    fn success_clears_the_mark() {
        let mut r = Redundancy::default();
        let t0 = Instant::now();
        r.note_failure(3, t0);
        assert!(r.is_down(3));
        r.note_success(3);
        assert!(!r.is_down(3));
        assert!(r.is_available(3, t0 + Duration::from_secs(1), 60));
    }

    #[test]
    fn recheck_zero_disables_fail_fast() {
        let mut r = Redundancy::default();
        let t0 = Instant::now();
        r.note_failure(9, t0);
        // recheck_secs=0 => never fail-fast (always available, even right after).
        assert!(r.is_available(9, t0, 0));
    }

    #[test]
    fn one_proxy_being_down_does_not_affect_others() {
        let mut r = Redundancy::default();
        let t0 = Instant::now();
        r.note_failure(1, t0);
        assert!(!r.is_available(1, t0, 60));
        assert!(r.is_available(2, t0, 60), "an unrelated proxy stays available");
        assert_eq!(r.down_count(), 1);
    }
}
