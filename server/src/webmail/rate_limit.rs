use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct RateLimiter {
    state: Mutex<HashMap<String, Bucket>>,
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
}

struct Bucket {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            max_attempts,
            window: Duration::from_secs(window_secs),
            lockout: Duration::from_secs(lockout_secs),
        }
    }

    /// Returns false if the key is currently locked out.
    pub fn is_allowed(&self, key: &str) -> bool {
        let now = Instant::now();
        let map = self.state.lock().unwrap();
        if let Some(Some(lu)) = map.get(key).map(|b| b.locked_until) {
            return now >= lu;
        }
        true
    }

    /// Record one failed attempt. Locks out the key after max_attempts failures.
    pub fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap();
        let b = map.entry(key.to_string()).or_insert_with(|| Bucket {
            count: 0,
            window_start: now,
            locked_until: None,
        });
        if now.duration_since(b.window_start) > self.window {
            b.count = 0;
            b.window_start = now;
            b.locked_until = None;
        }
        b.count += 1;
        if b.count >= self.max_attempts {
            b.locked_until = Some(now + self.lockout);
        }
    }

    /// Clear rate-limit state for a key (e.g., after a successful auth).
    pub fn record_success(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_key_is_allowed() {
        let rl = RateLimiter::new(3, 60, 300);
        assert!(rl.is_allowed("alice"));
    }

    #[test]
    fn under_limit_stays_allowed() {
        let rl = RateLimiter::new(3, 60, 300);
        rl.record_failure("alice");
        rl.record_failure("alice");
        assert!(rl.is_allowed("alice"));
    }

    #[test]
    fn at_limit_becomes_locked() {
        let rl = RateLimiter::new(3, 60, 300);
        rl.record_failure("alice");
        rl.record_failure("alice");
        rl.record_failure("alice");
        assert!(!rl.is_allowed("alice"));
    }

    #[test]
    fn success_clears_lockout() {
        let rl = RateLimiter::new(3, 60, 300);
        rl.record_failure("alice");
        rl.record_failure("alice");
        rl.record_failure("alice");
        rl.record_success("alice");
        assert!(rl.is_allowed("alice"));
    }

    #[test]
    fn different_keys_are_independent() {
        let rl = RateLimiter::new(2, 60, 300);
        rl.record_failure("alice");
        rl.record_failure("alice");
        assert!(!rl.is_allowed("alice"));
        assert!(rl.is_allowed("bob"));
    }
}
