# SAACP Benchmark Results

Measured performance of the SAACP Rust implementation, produced by the Criterion
harness in [`benches/benchmarks.rs`](benches/benchmarks.rs). **Every number in this
file is a real measurement from an actual `cargo bench` run on this repository — no
values are estimated, extrapolated, or hand-edited.** Each figure is Criterion's
reported estimate in the form `[lower  median  upper]`, where the bounds are the 95%
confidence interval around the median and the median is the point estimate.

---

## Run environment

| Property | Value |
|----------|-------|
| CPU | Intel® Core™ i7-14700K (20 physical cores / 28 logical threads, 3.4 GHz base) |
| Memory | 32 GB (34,062,921,728 bytes) |
| OS | Microsoft Windows 11, build 10.0.26200.8875 |
| Toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` / `cargo 1.96.0 (30a34c682 2026-05-25)` |
| Build profile | `release` — `lto = "thin"`, `codegen-units = 1`, `opt-level = 3` |
| Benchmark framework | Criterion 0.5 (`harness = false`) |
| Command | `cargo bench --bench benchmarks` |
| Total benchmarks | 175 |

### Methodology & honesty notes

- Criterion default sampling was used except where a benchmark group overrides
  `sample_size` in the harness (e.g. Gate 6.0 audit = 100, AEGF = 50, WAL sustained =
  20, several worst-case groups = 20–30). Each benchmark warms up for 3 s and then
  collects samples over ~5 s.
- Times are wall-clock per single invocation of the benchmarked closure **unless the
  benchmark name says otherwise**. Several benchmarks deliberately loop N operations
  inside one timed iteration (e.g. `*_per_iter`, `*_100_*`, `*_1000_*`,
  `append_event_100k_sustained`); for those the reported time is for the whole batch,
  and a per-operation figure is noted in the relevant section below.
- The machine was a normal interactive desktop, not an isolated/quiesced benchmarking
  host. A handful of benchmarks show Criterion outlier warnings; two runs in
  particular exhibited high variance and are called out explicitly rather than
  cherry-picked:
  - **`WC11_.../cscs_1000_unique_sessions_burst`** measured `[2.04 ms 71.05 ms 209.03 ms]`
    — an extreme spread (the median and upper bound differ by ~3×). This benchmark
    inserts 1000 unique sessions per iteration into a globally-shared `CSCSLoopDetector`
    and is dominated by allocation/eviction and lock contention on shared global state;
    treat it as an unstable upper-bound indicator, not a precise figure.
  - **`Gate_12_0_..._detect_fresh_unique_sessions`** `[98.78 µs 105.31 µs 113.81 µs]`
    similarly stresses global CSCS state and shows wider-than-typical bounds.
- Numbers are specific to the hardware above. They will differ on other CPUs; reproduce
  locally with the exact command in the table.

---

## Executive summary — representative figures

| Operation | Median | Notes |
|-----------|-------:|-------|
| Gate tier resolution | **1.46 ns** | pure branch logic |
| Replay-window check (sequential accept) | **3.22 ns** | per packet |
| Replay-window duplicate/replay reject | **6.90 ns** | per replayed packet |
| Financial circuit breaker (incl. NaN/∞ attack) | **3.63 ns** | constant-time reject |
| Epistemic CB fast-skip (non-schema-3) | **2.81 ns** | |
| Gate 0 crypto integrity, 100 B frame | **1.53 µs** | full AES-256-GCM decrypt + auth |
| Gate 0 reject garbage (DDoS drop) | **~265 ns** | fail-cheap before AEAD |
| MEASC frame build, 64 B payload | **1.56 µs** | encrypt + tag + checksum |
| Full 12-gate pipeline, valid read-only | **2.01 µs** | end-to-end, all gates pass |
| Full pipeline, injection rejected @ Gate 4.0 | **2.03 µs** | end-to-end reject |
| Ed25519 capability token issue | **25.0 µs** | signing |
| Ed25519 capability token verify (valid) | **93.6 µs** | verification incl. lookup |
| Prompt-injection scan, clean 50 B | **3.66 µs** | Unicode-normalized |
| Audit log append (hash-chain + WAL) | **2.54 µs** | per event, chain-length-independent |
| WAL sustained append throughput | **276.5 ms / 100k events** | ≈ **362k events/sec** |

> **Full-pipeline throughput (gate-pipeline compute only — NOT a system throughput
> claim):** a valid frame traverses all mandatory gates in ~2.0 µs on this hardware,
> i.e. on the order of **~500k packets/sec per core of gate-pipeline compute**.
>
> P-3: this figure is measured single-threaded, one pre-parsed `ParsedPacket` at a
> time, with no I/O and no concurrency. Real daemon throughput is materially lower,
> because the serving path additionally pays: TCP accept + read, the X25519 ECDH
> handshake (amortized across a persistent connection), tokio task-spawn and
> `spawn_blocking` hand-off for the gate pipeline, and cross-connection contention on
> the shared audit-WAL and rate-limiter state. Treat ~500k as an upper bound on the
> compute half of one core, never as "this system serves 500k packets/sec".
>
> The audit WAL sustains ~333k appended events/sec (see T14) — that IS a concurrent,
> lock-serialized number, so in practice it, not the 2 µs gate cost, is the ceiling
> that a real deployment reaches first.

---

## Per-gate latency (`Gate_*`)

### Gate tier resolution
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| lightweight_readonly_pinned | 1.4612 ns | **1.4650 ns** | 1.4699 ns |
| standard_readonly_unpinned | 1.4633 ns | **1.4788 ns** | 1.4987 ns |
| full_irreversible | 1.4612 ns | **1.4649 ns** | 1.4690 ns |
| full_external_input_flag | 1.4535 ns | **1.4574 ns** | 1.4617 ns |

### Gate 0 — Crypto integrity (AES-256-GCM decrypt + auth)
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| parse_header_100B | 1.5229 µs | **1.5256 µs** | 1.5288 µs |
| parse_header_1KB | 2.1668 µs | **2.1688 µs** | 2.1712 µs |
| parse_header_10KB | 8.2285 µs | **8.2361 µs** | 8.2443 µs |
| reject_garbage_200B | 266.82 ns | **267.43 ns** | 268.17 ns |
| reject_wrong_magic | 260.38 ns | **261.16 ns** | 261.96 ns |
| reject_too_short | 113.88 ns | **114.27 ns** | 114.68 ns |

### Gate 0.5 — Financial circuit breaker
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| non_cost_status_skip | 3.6318 ns | **3.6490 ns** | 3.6708 ns |
| within_budget_pass | 3.6532 ns | **3.6637 ns** | 3.6759 ns |
| over_budget_fail | 3.6361 ns | **3.6451 ns** | 3.6544 ns |

### Gate 1.5 — Intent envelope
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| good_overlap_pass | 5.4989 µs | **5.5186 µs** | 5.5398 µs |
| poor_overlap_fail | 5.7839 µs | **5.7986 µs** | 5.8148 µs |
| large_task_1600B | 81.328 µs | **81.611 µs** | 81.890 µs |

### Gate 2.5 — Kinetic firewall
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| allow_equal_class | 2.2221 ns | **2.2260 ns** | 2.2303 ns |
| allow_lower_class | 2.2213 ns | **2.2269 ns** | 2.2331 ns |
| block_escalation_read_to_irrev | 95.690 ns | **95.929 ns** | 96.189 ns |
| block_escalation_rev_to_irrev | 95.201 ns | **95.702 ns** | 96.250 ns |

### Gate 3.0 — Lateral movement
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| non_mutative_pass | 2.4318 ns | **2.4495 ns** | 2.4747 ns |
| mutative_0x0b_blocked | 48.214 ns | **48.460 ns** | 48.742 ns |
| mutative_0x0b_with_token | 20.933 ns | **21.020 ns** | 21.113 ns |

### Gate 4.0 — Injection scan
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| clean_small_50B | 3.6350 µs | **3.6643 µs** | 3.7128 µs |
| clean_medium_1KB | 93.862 µs | **94.083 µs** | 94.319 µs |
| clean_large_50KB | 998.15 µs | **1.0027 ms** | 1.0072 ms |
| injection_simple | 2.7892 µs | **2.8020 µs** | 2.8156 µs |
| injection_nested | 3.6992 µs | **3.7141 µs** | 3.7301 µs |
| injection_confusable_unicode | 2.5971 µs | **2.6047 µs** | 2.6129 µs |
| injection_sql | 1.4919 µs | **1.4969 µs** | 1.5017 µs |

### Gate 4.0 — Normalize hot path
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| ascii/80 | 3.0636 µs | **3.0771 µs** | 3.0919 µs |
| mixed_uni/50 | 2.2158 µs | **2.2264 µs** | 2.2381 µs |
| zero_width/40 | 1.6738 µs | **1.6797 µs** | 1.6858 µs |
| large/1000 | 39.996 µs | **40.126 µs** | 40.273 µs |

### Gate 4.0 — Payload size scaling (clean scan)
| Payload bytes | low | median | high |
|--------------:|----:|-------:|-----:|
| 64 | 4.6958 µs | **4.7060 µs** | 4.7169 µs |
| 512 | 26.828 µs | **26.902 µs** | 26.983 µs |
| 4096 | 198.45 µs | **199.29 µs** | 200.26 µs |
| 16384 | 787.07 µs | **791.30 µs** | 796.13 µs |
| 65536 | 1.0752 ms | **1.0789 ms** | 1.0829 ms |

### Gate 5.0 — Epistemic circuit breaker
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| non_schema3_fast_skip | 2.7999 ns | **2.8067 ns** | 2.8139 ns |
| schema3_high_conf_pass | 25.637 ns | **25.674 ns** | 25.714 ns |
| schema3_low_conf_fail | 219.12 ns | **220.47 ns** | 222.37 ns |
| schema3_bare_conf_pass | 23.212 ns | **23.481 ns** | 23.839 ns |
| schema3_at_threshold | 25.620 ns | **25.661 ns** | 25.706 ns |

### Gate 6.0 — Audit checkpoint
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| append_event_single | 2.5275 µs | **2.5430 µs** | 2.5618 µs |
| append_event_burst_100 (100 events/iter) | 250.75 µs | **252.84 µs** | 255.25 µs |

`append_event_burst_100` ≈ **2.53 µs/event** across a 100-event batch — consistent with
the single-append figure.

### Gate 11.0 — AEGF governance
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| submit_complete_unique_sessions | 3.4823 µs | **3.4968 µs** | 3.5119 µs |
| submit_complete_same_session | 3.4515 µs | **3.4747 µs** | 3.4990 µs |

### Gate 12.0 — CSCS loop detection
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| detect_fresh_unique_sessions ⚠️ | 98.779 µs | **105.31 µs** | 113.81 µs |
| detect_same_session_varying_seq | 2.0029 µs | **2.0093 µs** | 2.0173 µs |

⚠️ High variance — stresses globally-shared CSCS state; see methodology notes.

### Pre-gate — Rate limiter
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| is_locked_fresh_agent | 70.120 ns | **70.451 ns** | 70.849 ns |
| is_locked_locked_agent | 85.090 ns | **85.154 ns** | 85.229 ns |
| record_error_below_threshold | 1.8306 µs | **1.8360 µs** | 1.8426 µs |
| record_cover_traffic | 326.24 ns | **328.68 ns** | 331.46 ns |

### Cover-traffic fast path
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| auth_and_discard | 182.19 ns | **182.54 ns** | 182.97 ns |

### Pipeline rejection by gate (early-exit cost)
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| reject_at_gate_0_garbage | 181.80 ns | **182.47 ns** | 183.20 ns |
| reject_at_gate_0_wrong_magic | 181.18 ns | **181.66 ns** | 182.15 ns |
| reject_at_gate_2_5_escalation | 92.467 ns | **92.753 ns** | 93.064 ns |
| reject_at_gate_3_0_no_secondary | 47.971 ns | **48.196 ns** | 48.480 ns |
| reject_at_gate_4_0_injection | 3.1559 µs | **3.1678 µs** | 3.1801 µs |
| reject_at_gate_5_0_low_confidence | 212.75 ns | **214.08 ns** | 215.71 ns |

---

## End-to-end throughput (`T1`–`T14`)

### T1 — MEASC frame build (encrypt + tag + checksum)
| Payload bytes | low | median | high |
|--------------:|----:|-------:|-----:|
| 64 | 1.5589 µs | **1.5616 µs** | 1.5648 µs |
| 512 | 1.9921 µs | **1.9939 µs** | 1.9960 µs |
| 4096 | 5.4943 µs | **5.5013 µs** | 5.5082 µs |
| 65536 | 69.527 µs | **69.599 µs** | 69.675 µs |

### T2 — Replay window
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| sequential_no_duplicate | 3.2157 ns | **3.2213 ns** | 3.2285 ns |
| duplicate_detection | 4.4704 ns | **4.5391 ns** | 4.6799 ns |
| advance_50_packets | 3.2232 ns | **3.2284 ns** | 3.2345 ns |
| max_advance_boundary | 3.2397 ns | **3.2501 ns** | 3.2629 ns |

### T3 — AEGF governance
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| submit_complete_100_sessions_per_iter (100/iter) | 365.16 µs | **368.02 µs** | 370.84 µs |
| submit_only | 19.704 µs | **19.931 µs** | 20.154 µs |

`submit_complete_100_sessions_per_iter` ≈ **3.68 µs** per submit+complete pair.

### T4 — Capability token issue / verify (Ed25519)
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| issue_ed25519 | 24.994 µs | **25.043 µs** | 25.098 µs |
| verify_ed25519_valid | 93.054 µs | **93.641 µs** | 94.296 µs |
| verify_ed25519_tampered | 1.2527 µs | **1.2646 µs** | 1.2778 µs |

### T5 — Injection scanner worst-case DoS
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| scan_100KB_clean | 1.5059 ms | **1.5102 ms** | 1.5159 ms |
| scan_max_depth_8 | 8.3629 µs | **8.4112 µs** | 8.4621 µs |
| scan_wide_1000_items | 1.0150 ms | **1.0166 ms** | 1.0186 ms |

### T6 — Multi-agent rate-limiter scaling
| Agents | low | median | high |
|-------:|----:|-------:|-----:|
| 1 | 88.829 ns | **88.891 ns** | 88.973 ns |
| 10 | 858.09 ns | **858.87 ns** | 859.80 ns |
| 100 | 8.6861 µs | **8.8745 µs** | 9.0678 µs |
| 1000 | 70.038 µs | **70.106 µs** | 70.192 µs |

Scales linearly (~70 ns per `is_locked` check regardless of population).

### T7 — E2E build + decrypt round-trip
| Payload bytes | low | median | high |
|--------------:|----:|-------:|-----:|
| 64 | 3.1200 µs | **3.1399 µs** | 3.1683 µs |
| 1024 | 4.7818 µs | **4.7883 µs** | 4.7960 µs |
| 8192 | 17.347 µs | **17.363 µs** | 17.381 µs |
| 65536 | 123.63 µs | **123.80 µs** | 123.98 µs |

### T8 — Pipeline gate-rejection timing
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| gate_0_reject_garbage | 180.95 ns | **181.40 ns** | 181.93 ns |
| gate_2_5_reject_escalation | 92.679 ns | **92.967 ns** | 93.285 ns |
| gate_3_0_reject_no_secondary | 47.791 ns | **47.924 ns** | 48.077 ns |
| gate_4_0_reject_injection | 2.5250 µs | **2.5353 µs** | 2.5458 µs |
| gate_5_0_reject_low_confidence | 214.56 ns | **215.10 ns** | 215.70 ns |

### T9 — CSCS session scaling
| Sessions | low | median | high |
|---------:|----:|-------:|-----:|
| 1 | 2.0567 µs | **2.0629 µs** | 2.0706 µs |
| 10 | 2.0849 µs | **2.0937 µs** | 2.1044 µs |
| 100 | 2.1347 µs | **2.1412 µs** | 2.1480 µs |
| 1000 | 2.4788 µs | **2.4898 µs** | 2.5006 µs |

### T10 — Audit log hash-chain growth (append cost vs. existing chain length)
| Pre-existing entries | low | median | high |
|---------------------:|----:|-------:|-----:|
| 0 | 2.5635 µs | **2.5838 µs** | 2.6084 µs |
| 100 | 2.5565 µs | **2.5680 µs** | 2.5833 µs |
| 1000 | 2.5765 µs | **2.5955 µs** | 2.6204 µs |
| 10000 | 2.5906 µs | **2.6028 µs** | 2.6171 µs |

Append cost is **O(1)** in chain length — ~2.6 µs whether the chain has 0 or 10,000
prior entries.

### T14 — WAL sustained throughput
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| append_event_100k_sustained (100,000 events/iter) | 268.52 ms | **276.50 ms** | 289.71 ms |

**≈ 361,700 events/sec** sustained (100,000 events / 276.5 ms), steady-state, with the
persistent `BufWriter<File>` batching flush/sync every 200 entries or 50 ms.

---

## Worst-case / adversarial (`WC1`–`WC13`)

Protocol under attack: DDoS floods, replay saturation, lockout storms, maximal
injection inputs, concurrency, token exhaustion, epoch pressure, session explosion.

### WC1 — DDoS flood rejection
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| ddos_raw_garbage_128B | 264.45 ns | **264.99 ns** | 265.61 ns |
| ddos_spoofed_magic_corrupt_rest | 127.47 ns | **127.71 ns** | 128.00 ns |
| ddos_max_size_garbage_1MB | 263.23 ns | **263.76 ns** | 264.38 ns |
| ddos_auth_tag_1bit_flip | 1.5122 µs | **1.5354 µs** | 1.5646 µs |
| ddos_auth_tag_all_zeros | 1.5098 µs | **1.5116 µs** | 1.5135 µs |
| ddos_auth_tag_all_ones | 1.5086 µs | **1.5118 µs** | 1.5157 µs |
| ddos_truncated_at_127B | 116.77 ns | **118.11 ns** | 119.48 ns |
| ddos_truncated_at_143B | 120.33 ns | **120.96 ns** | 121.79 ns |
| ddos_body_corrupted_valid_tag_structure | 1.5073 µs | **1.5103 µs** | 1.5145 µs |
| ddos_full_pipeline_garbage_128B | 184.98 ns | **185.38 ns** | 185.84 ns |

A 1 MB garbage flood packet is dropped in ~264 ns — the same cost as a 128 B one,
because the size/magic checks fail before any AEAD work.

### WC2 — Replay attack flood
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| replay_flood_single_psn_1 | 6.9030 ns | **6.9386 ns** | 6.9872 ns |
| replay_flood_psn_100_always_duplicate | 6.8781 ns | **6.8960 ns** | 6.9158 ns |
| replay_saturate_4096_then_flood_window_interior | 6.9259 ns | **6.9526 ns** | 6.9819 ns |
| replay_anomaly_jump_storm_gt512 | 4.8660 ns | **4.9197 ns** | 4.9859 ns |
| replay_out_of_window_ancient_psn | 5.2446 ns | **5.2583 ns** | 5.2736 ns |
| replay_accept_sequential_sustained_4096 | 11.892 ns | **11.923 ns** | 11.960 ns |
| replay_max_advance_boundary_2047 | 4.8447 ns | **4.8686 ns** | 4.9054 ns |

Replayed packets are rejected in ~7 ns even against a fully saturated 4096-entry window.

### WC3 — Rate limiter lockout storm
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| lockout_drive_to_threshold_5_errors | 1.6049 µs | **1.6085 µs** | 1.6125 µs |
| lockout_post_lockout_1000_is_locked_checks (1000/iter) | 88.656 µs | **88.880 µs** | 89.189 µs |
| lockout_100_unique_agents_all_to_threshold | 104.78 µs | **105.04 µs** | 105.33 µs |
| lockout_reset_then_relockout_cycle | 1.9805 µs | **1.9855 µs** | 1.9911 µs |
| cover_traffic_exhaust_threshold_50 | 10.178 µs | **10.196 µs** | 10.216 µs |
| lockout_mixed_agents_1000_error_calls (1000/iter) | 275.60 µs | **276.59 µs** | 277.67 µs |

Post-lockout `is_locked` checks cost ~89 ns each (88.9 µs / 1000) — cheap to keep an
attacker locked out.

### WC4 — Injection scanner adversarial
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| injection_max_depth_8_nested | 5.7559 µs | **5.7751 µs** | 5.7968 µs |
| injection_at_max_length_16384_attack | 569.25 µs | **574.75 µs** | 580.85 µs |
| injection_at_max_length_16384_clean | 793.26 µs | **803.09 µs** | 815.35 µs |
| injection_confusable_unicode_dense | 24.491 µs | **24.611 µs** | 24.734 µs |
| injection_zero_width_dense | 10.389 µs | **10.438 µs** | 10.492 µs |
| injection_combined_multi_vector | 4.0962 µs | **4.1357 µs** | 4.2043 µs |
| injection_array_1000_every10th_attack | 2.3441 µs | **2.3613 µs** | 2.3820 µs |
| injection_base64_wrapped_attack | 7.9702 µs | **8.0289 µs** | 8.1014 µs |
| normalize_max_confusable_500_chars | 19.859 µs | **20.148 µs** | 20.443 µs |

### WC5 — Multi-agent concurrent (real OS threads)
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| concurrent_6_agents_read_only | 822.16 µs | **871.90 µs** | 926.32 µs |
| concurrent_12_agents_mixed_tiers | 1.2873 ms | **1.3127 ms** | 1.3373 ms |
| concurrent_20_agents_all_irreversible | 2.3090 ms | **2.4171 ms** | 2.5103 ms |
| concurrent_6_agents_injection_scan | 823.24 µs | **867.52 µs** | 908.79 µs |
| concurrent_8_agents_rate_limiter_contention | 1.1057 ms | **1.1279 ms** | 1.1503 ms |

(Each concurrent benchmark spawns N threads via `std::thread::scope`; timing includes
thread spawn/join overhead per iteration.)

### WC6 — Token system exhaustion
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| token_revocation_insert_100_per_iter (100/iter) | 82.676 µs | **83.931 µs** | 85.249 µs |
| token_validate_revoked_token_fast_reject | 3.8132 µs | **3.8242 µs** | 3.8371 µs |
| token_tampered_signature_reject | 2.1270 µs | **2.1396 µs** | 2.1554 µs |
| token_expired_ttl_zero_reject | 4.8044 µs | **4.8686 µs** | 4.9355 µs |
| token_forbidden_agent_reject | 5.3596 µs | **5.4018 µs** | 5.4505 µs |
| token_issue_1000_unique_per_iter_cache_pressure (1000/iter) | 2.6284 ms | **2.6511 ms** | 2.6751 ms |

### WC7 — Epoch rotation pressure
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| epoch_rotation_single_hkdf_cost | 2.8125 µs | **2.8463 µs** | 2.8857 µs |
| epoch_create_send50_destroy_full_lifecycle | 77.951 µs | **78.140 µs** | 78.361 µs |
| epoch_rapid_rotate_100_times (100/iter) | 162.49 µs | **165.21 µs** | 168.13 µs |
| epoch_session_count_1000_concurrent_sessions | 1.3705 ms | **1.3732 ms** | 1.3762 ms |

### WC8 — Full pipeline end-to-end
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| e2e_valid_read_only_all_gates_pass | 2.0063 µs | **2.0099 µs** | 2.0145 µs |
| e2e_valid_irreversible_full_tier | 2.0114 µs | **2.0159 µs** | 2.0210 µs |
| e2e_injection_payload_rejected_gate4 | 2.0304 µs | **2.0335 µs** | 2.0370 µs |
| e2e_action_escalation_rejected_gate2_5 | 2.0084 µs | **2.0122 µs** | 2.0169 µs |
| e2e_schema3_epistemic_gate_exercised | 2.0520 µs | **2.0544 µs** | 2.0571 µs |
| e2e_100_frames_sequential_throughput (100/iter) | 200.87 µs | **201.10 µs** | 201.37 µs |

The 100-frame batch ≈ **2.01 µs/frame**, matching the single-frame figures — the full
mandatory pipeline runs in ~2 µs per packet on this hardware
(**~497k packets/sec/core of gate-pipeline compute**).

> P-3 caveat: single-threaded, pre-parsed packets, no I/O, no concurrency. This is the
> compute cost of the gate pipeline in isolation — not end-to-end system throughput.
> See the "Full-pipeline throughput" note above for what the serving path adds.

### WC9 — Circuit breaker cascade / boundary attacks
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| financial_cb_cost_equals_budget_boundary | 3.6211 ns | **3.6274 ns** | 3.6349 ns |
| financial_cb_nan_cost_attack | 3.6259 ns | **3.6334 ns** | 3.6418 ns |
| financial_cb_inf_cost_attack | 3.6277 ns | **3.6387 ns** | 3.6522 ns |
| financial_cb_neg_inf_cost_attack | 3.6228 ns | **3.6340 ns** | 3.6478 ns |
| epistemic_cb_schema_id_259_no_u8_truncation | 2.8138 ns | **2.8230 ns** | 2.8327 ns |
| epistemic_cb_nan_confidence_reject | 102.59 ns | **103.52 ns** | 105.35 ns |
| epistemic_cb_exactly_at_threshold_0_85 | 25.491 ns | **25.549 ns** | 25.621 ns |
| epistemic_cb_claimed_1_0_confidence_reject | 214.80 ns | **215.18 ns** | 215.63 ns |
| epistemic_cb_claimed_0_99_confidence_reject | 224.62 ns | **225.06 ns** | 225.57 ns |

NaN / ±∞ cost attacks are rejected in the same ~3.6 ns as the normal boundary case —
the finite-value guard adds no measurable overhead.

### WC10 — Audit log bombardment
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| audit_burst_100_appends_per_iter (100/iter) | 260.95 µs | **263.32 µs** | 266.10 µs |
| audit_rapid_1000_sequential_appends (1000/iter) | 2.4919 ms | **2.5164 ms** | 2.5505 ms |
| audit_post_50k_entries_single_append_cost | 2.5509 µs | **2.5888 µs** | 2.6301 µs |
| audit_16_concurrent_appenders (16 threads/iter) | 839.59 µs | **840.81 µs** | 841.99 µs |

Single-append cost after 50,000 existing entries (~2.59 µs) matches the cold-chain cost
— confirming O(1) append.

### WC11 — CSCS oscillation at scale
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| cscs_1000_unique_sessions_burst ⚠️ | 2.0392 ms | **71.051 ms** | 209.03 ms |
| cscs_same_session_100_back_to_back (100/iter) | 196.36 µs | **196.87 µs** | 197.42 µs |
| cscs_oscillation_pattern_ABAB_10_cycles | 39.967 µs | **40.130 µs** | 40.372 µs |
| cscs_session_explosion_10k_state_growth (10k/iter) | 24.531 ms | **25.545 ms** | 26.571 ms |

⚠️ `cscs_1000_unique_sessions_burst` had extreme variance (median 71 ms, CI 2 ms–209 ms)
under contention on the shared global detector — reported as-measured; treat as an
unstable upper bound, not a stable figure. See methodology notes.

### WC12 — AEGF governance stress
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| aegf_submit_only_100_no_complete_fills_state (100/iter) | 1.8954 ms | **1.9155 ms** | 1.9431 ms |
| aegf_submit_complete_100_pairs_per_iter (100/iter) | 297.65 µs | **300.45 µs** | 303.09 µs |
| aegf_single_agent_1000_submit_complete_per_iter (1000/iter) | 2.9479 ms | **2.9664 ms** | 2.9862 ms |

A balanced submit+complete pair ≈ **3.0 µs** (300 µs / 100); leaving requests
uncompleted (`submit_only`) is far costlier as unbounded state accumulates.

### WC13 — Session explosion
| Benchmark | low | median | high |
|-----------|----:|-------:|-----:|
| session_create_1000_sequential (1000/iter) | 1.3811 ms | **1.3835 ms** | 1.3859 ms |
| session_create_destroy_cycle_1000 (1000/iter) | 1.1600 ms | **1.1622 ms** | 1.1641 ms |
| session_16_threads_each_create_100 (1600 total/iter) | 2.9991 ms | **3.0127 ms** | 3.0246 ms |

Sequential session creation ≈ **1.38 µs/session** (1.38 ms / 1000).

---

## Reproducing

```sh
# from the repository root
cargo bench --bench benchmarks              # full suite (all 175 benchmarks)
cargo bench -- Gate_                        # per-gate latency only
cargo bench -- 'T[0-9]'                     # throughput only
cargo bench -- WC                           # worst-case only

# HTML reports with plots and per-benchmark distributions:
#   target/criterion/<group>/<bench>/report/index.html
```

Raw Criterion console output for this run is preserved in `bench_raw_output.txt` at the
repository root (1,803 lines), and the extracted name↔time pairs in `bench_parsed.txt`.

---

*Generated from a real `cargo bench` run on the hardware listed above. Figures are
Criterion 95%-CI estimates; reproduce locally for your own platform — absolute numbers
will vary by CPU, memory, and system load.*
