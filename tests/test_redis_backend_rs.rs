//! Regression tests for the `redis-backend`-gated distributed state used by
//! `gateway::AgentRateLimiter::with_backend`. Requires a real local Redis
//! (no mock/testcontainers dependency exists in this repo) — every test
//! probes connectivity first and skips gracefully (prints and returns,
//! matching `python/tests/test_wrap.py`'s convention) rather than
//! hard-failing when Redis isn't reachable.
#![cfg(feature = "redis-backend")]

use std::sync::Arc;
use std::time::Duration;

use saacp::gateway::{AgentRateLimiter, RATE_LIMITER_THRESHOLD};
use saacp::state_backend::{RedisBackend, StateBackend};

const REDIS_URL: &str = "redis://127.0.0.1:6379/";

fn redis_available() -> bool {
    match RedisBackend::with_timeout(REDIS_URL, Duration::from_millis(200)) {
        Ok(backend) => backend.get("saacp:redis-backend-test:probe").is_ok(),
        Err(_) => false,
    }
}

macro_rules! skip_if_no_redis {
    () => {
        if !redis_available() {
            eprintln!(
                "skipping: no local Redis reachable at {} (this test requires a real Redis instance)",
                REDIS_URL
            );
            return;
        }
    };
}

#[test]
fn redis_incr_with_ttl_is_atomic() {
    skip_if_no_redis!();
    let backend = Arc::new(RedisBackend::new(REDIS_URL).unwrap());
    let key = format!("test:saacp:atomic:{}", std::process::id());
    let _ = backend.delete(&key);

    let mut handles = vec![];
    for _ in 0..8 {
        let b = Arc::clone(&backend);
        let k = key.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                b.incr_with_ttl(&k, 1, Duration::from_secs(30)).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let v = backend.get(&key).unwrap().unwrap();
    assert_eq!(std::str::from_utf8(&v).unwrap(), "400");
    let _ = backend.delete(&key);
}

#[test]
fn redis_incr_with_ttl_sets_ttl_once() {
    skip_if_no_redis!();
    let backend = RedisBackend::new(REDIS_URL).unwrap();
    let key = format!("test:saacp:ttlonce:{}", std::process::id());
    let _ = backend.delete(&key);

    backend.incr_with_ttl(&key, 1, Duration::from_secs(1)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    // A second increment before expiry must NOT reset the TTL clock.
    backend.incr_with_ttl(&key, 1, Duration::from_secs(999)).unwrap();
    std::thread::sleep(Duration::from_millis(700));

    assert_eq!(
        backend.get(&key).unwrap(),
        None,
        "TTL should have expired from the FIRST creation, not been reset by the second increment"
    );
}

#[test]
fn redis_backend_cross_process_lockout() {
    skip_if_no_redis!();
    let backend_a: Arc<dyn StateBackend> = Arc::new(RedisBackend::new(REDIS_URL).unwrap());
    let backend_b: Arc<dyn StateBackend> = Arc::new(RedisBackend::new(REDIS_URL).unwrap());
    let agent = format!("redis-test-agent-{}", std::process::id());

    let node_a = AgentRateLimiter::with_backend(backend_a);
    let node_b = AgentRateLimiter::with_backend(backend_b);
    node_a.reset(Some(&agent)); // clean slate in case of leftover state from a prior run

    let mut tripped = false;
    for _ in 0..RATE_LIMITER_THRESHOLD {
        if node_a.record_error(&agent).is_err() {
            tripped = true;
        }
    }
    assert!(tripped, "node A should have tripped the fleet-wide circuit breaker");

    assert!(!node_b.is_locked(&agent), "node B shouldn't know yet without a refresh");
    node_b.refresh_from_backend();
    assert!(node_b.is_locked(&agent), "node B should observe the real cross-process lockout after refresh");

    node_a.reset(Some(&agent));
}

#[test]
fn redis_backend_unreachable_fails_safe() {
    // Port 1 on localhost: nothing listens there. `redis::Client::open` is
    // lazy (just parses the URL), so this succeeds; the actual connect
    // attempt — and its failure — happens inside `record_error`.
    let backend = Arc::new(RedisBackend::with_timeout("redis://127.0.0.1:1/", Duration::from_millis(50)).unwrap());
    let rl = AgentRateLimiter::with_backend(backend);

    let started = std::time::Instant::now();
    let mut tripped = false;
    for _ in 0..RATE_LIMITER_THRESHOLD {
        if rl.record_error("unreachable-redis-agent").is_err() {
            tripped = true;
        }
    }
    assert!(tripped, "circuit breaker must still enforce locally when Redis is unreachable (fail-safe, not fail-open)");
    assert!(started.elapsed() < Duration::from_secs(5), "must fail fast on a bounded timeout, not hang");
}
