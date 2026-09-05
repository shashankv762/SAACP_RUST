# SAACP Auxiliary ML System — Architecture & Integration Plan

> **Status:** Draft for review
> **Date:** 2026-08-26
> **Scope:** Auxiliary (offline) ML for trust analysis, anomaly detection, and operator assistance. NOT a hot-path replacement for the deterministic `TrustDecayEngine`.

---

## 1. Executive Verdict

**Building a custom 500M–1B parameter transformer for per-packet trust scoring is not recommended.** The existing `TrustDecayEngine` already implements the correct design: explicit, deterministic, auditable arithmetic with tuned penalty/reward weights. A neural network would be slower, non-deterministic, opaque to auditors, and impossible to regression-test at the packet rate SAACP demands.

**However, there is a genuine ML opportunity** — just not on the hot path. Three problems in SAACP's current design are genuinely hard for rule-based systems and tractable for ML:

1. **Gate 4.0 false positives / non-English bypass** (§2.2, §2.5 of the audit): a learned classifier could distinguish "the contract as agreed" from "ignore previous instructions" with word-boundary and semantic awareness that a literal denylist cannot.
2. **Fleet-wide behavioral anomaly**: detecting slow-burn compromise, collusion rings, or coordinated attacks that only become visible across hundreds of sessions and days of traffic — well beyond the per-packet `IntentDriftTracker` window.
3. **Audit-log triage**: helping a human operator find the signal in the noise of an immutable HMAC-chained audit log that grows by millions of entries per day.

The blueprint below targets those three use cases with a model that is **as small as possible, never in the packet path, and always advisory** (the deterministic engine has the final word).

---

## 2. Why Hot-Path ML Fails (Technical Reasons)

### 2.1 Latency budget

The full mandatory gate pipeline runs in ~2.0 µs per packet on an i7-14700K (`benchmark_results.md` §"Full-pipeline throughput"). A single forward pass of a 500M-parameter transformer, even on a modern GPU, takes **1–10 ms** (1,000–5,000× the entire gate pipeline). On CPU (the deployment target — SAACP runs on Raspberry Pi–class devices), it is 10–100× worse. There is no batching opportunity: the pipeline processes one packet at a time, and each decision blocks the receiving agent.

### 2.2 Determinism and auditability

SAACP is fail-closed and audit-everything by design. The `TrustDecayEngine` produces a trust score that is:

- **Reproducible**: the same agent history produces the same score on any node, any time.
- **Explainable**: every transition is a named event (`PenaltyKind::ReplaySuspicion`, `RewardKind::CleanPassage`) with a documented weight.
- **Auditable**: the score is reconstructed by replaying the event log through `penalty_weight()`.

A neural network gives slightly different outputs for the same input depending on GPU batch size, floating-point accumulation order, quantization, and framework version. This is fundamentally incompatible with a system where "the same attack must produce the same trust consequence on every node" is a safety property, not a nice-to-have.

### 2.3 Non-stationary adversarial distribution

The distribution of "compromised agent behavior" changes the moment an attacker learns the model exists and its decision boundary. With the deterministic engine, changing one weight is a one-line diff with a named comment. With a 500M-parameter model, you need a retraining pipeline, a canary deployment, a rollback plan, and a way to prove the new model doesn't regress on old attack patterns. SAACP's threat model explicitly assumes "potentially-compromised or manipulated peers" — the system must degrade gracefully when the attacker controls the input distribution. Deterministic rules degrade predictably; neural networks fail silently.

### 2.4 The actual problems are code, not ML

The audit identified Gate 4.0's weaknesses as:

- Whitespace removal destroying word boundaries → **fix: join with a sentinel** (one-line change)
- Non-Latin scripts dropped → **fix: transliterate instead of filter** (one crate)
- Paraphrase undetectable → **fix: word-boundary anchoring + scored signal** (code change)

None of these require a neural network. They are tokenizer bugs.

---

## 3. Where ML Actually Helps

### 3.1 Use Case A — Semantic Injection Classifier (Gate 4.0 replacement)

**Problem:** The current 56-literal Aho-Corasick scanner has a measurable false-positive rate on ordinary English and zero coverage for non-English injection. A learned classifier can understand word boundaries, context, and semantic intent.

**Why ML works here:** This is a fixed-vocabulary classification task (injection / not-injection) with abundant training data (public prompt-injection datasets + SAACP's own red-team corpus in `tests/breakit/scanner/`). The model needs to understand natural language, which is what transformers are good at.

**Model:** A small transformer encoder (not generative) — see §4.1.

### 3.2 Use Case B — Fleet-Wide Behavioral Anomaly Detection

**Problem:** The `TrustDecayEngine` and `IntentDriftTracker` operate per-session. They cannot detect an agent that behaves correctly in every individual session but is coordinating with other agents across sessions (a slow-burn Sybil/collusion ring). The `MACE` engine does cosine-similarity on per-session feature vectors but has no temporal model.

**Why ML works here:** Fleet-wide anomaly detection is a time-series graph problem across thousands of agents and millions of packets. The feature space is high-dimensional (gate rejection rates, trust trajectories, delegation graph topology, temporal patterns). This is exactly where learned models outperform hand-tuned thresholds.

**Model:** A graph-neural-network or temporal convolutional network — see §4.2.

### 3.3 Use Case C — Audit-Log Triage and Summarization

**Problem:** The immutable audit log (`security.rs`) grows by ~250k–360k entries/second at peak. A human operator cannot read it. Currently the only tooling is `verify_chain` / `verify_chain_disk` (tamper detection) and the Command Center's `/api/alerts` ring buffer (last N alerts). There is no "summarize what happened in the last hour" or "find me the session where agent-X first showed anomalous behavior."

**Why ML works here:** This is a summarization and retrieval task over a large corpus. A small generative model can produce natural-language summaries of audit windows, answer operator questions ("show me all Gate 2.5 escalations in the last hour where the agent recovered within 5 minutes"), and surface patterns a human would miss.

**Model:** A small encoder-decoder or LLM — see §4.3.

---

## 4. Architecture Guidelines

### 4.1 Injection Classifier (Use Case A) — Recommended Architecture

**Do NOT use a generative transformer.** Use a **classification head on a frozen transformer encoder**. This gives you the language understanding of a transformer with the latency and determinism of a classifier.

#### Architecture: `SaacpInjectionEncoder`

```
Input: normalized text string (post-normalize_window, pre-Aho-Corasick)
  │
  ▼
Tokenizer: sentencepiece unigram, vocab_size=8192, trained on SAACP task corpus
  │       + public prompt-injection datasets (gcg, dan, aim, etc.)
  │
  ▼
Embedding: token_embed(8192, 128) + position_embed(max_len=512, 128) → [B, 512, 256]
  │
  ▼
Transformer Encoder Blocks (×4):
  │  ├─ Multi-Head Attention (4 heads, head_dim=64, causal=False, bidirectional)
  │  ├─ LayerNorm → FFN(256 → 512 → 256, GELU) → Residual
  │  └─ Dropout(0.1)
  │
  ▼
Pooling: mean over sequence dimension → [B, 256]
  │
  ▼
Classification Head:
  │  ├─ Linear(256 → 64) → GELU → Dropout(0.1)
  │  └─ Linear(64 → 2) → Softmax → [injection_prob, clean_prob]
  │
  Output: f64 in [0.0, 1.0] — "probability this text contains a prompt injection"
```

**Parameter count:** ~3.2M (embedding: 8192×128 + 512×128 ≈ 1.1M; attention blocks: 4 × ~500K ≈ 2M; head: ~2K). This is **50–150× smaller** than the 500M–1B range and sufficient because:

- The classification vocabulary is fixed and small (injection signatures are a known set).
- The model never generates text — it classifies.
- A frozen encoder means the inference cost is one forward pass with no KV-cache, no sampling, no temperature.

**Why not bigger?** A larger model (even 100M) gives diminishing returns on a 2-class classification task with a constrained input distribution (normalized, whitespace-stripped ASCII text). The 3.2M figure comes from the rule of thumb: ~1M parameters per class per input modality, ×2 classes, ×1.5 for the encoder backbone.

#### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | Encoder-only (BERT-style) | Classification doesn't need autoregressive generation. Bidirectional attention sees the full context at once. |
| Max sequence length | 512 tokens | Covers `MAX_SCAN_LENGTH` (16 KB of normalized text ≈ 2–4K tokens at subword granularity). Truncate beyond that — the current scanner already bounds at 16 KB. |
| Vocabulary | sentencepiece unigram, 8K | Small enough to fit in L2 cache on an edge device. Trained on the actual SAACP normalization output (lowercase ASCII-folded, confusables-mapped text). |
| Precision | f32 inference, bf16 training | f32 is fast enough on CPU via `tract` or `onnxruntime`. bf16 training halves GPU memory. |
| Determinism | Fixed seed, no sampling | Inference is deterministic by construction (softmax over fixed weights, no temperature, no top-k). Same input → same output, always. |
| Calibration | Temperature scaling on validation set | Ensures output probabilities are well-calibrated (0.95 means 95% precision at that threshold). Required so the downstream threshold has a meaningful interpretation. |

#### Latency Budget

Target: **< 50 µs per classify call** on the i7-14700K. This fits within the current Gate 4.0 budget (~3–5 µs for the Aho-Corasick path, ~50–100 µs for the worst-case full-scan path) while replacing the denylist with a semantic classifier.

At 3.2M parameters and 512 max length:
- Embedding lookup: ~0.5 µs
- 4 × (attention + FFN): ~30 µs (dominated by matmuls on a [B=1, 512, 256] tensor)
- Pooling + head: ~1 µs
- **Total: ~32 µs** (leaves headroom for tokenization)

On an edge device (Raspberry Pi 4, CPU), this will be ~200–500 µs — acceptable for Gate 4.0 because the current scanner already takes 100+ µs on large payloads.

#### Integration Point

Replace `PromptInjectionScanner::scan_string_patterns` at `handler.rs:754-779` with a two-stage pipeline:

1. **Stage 1 (fast path, <1 µs):** Aho-Corasick on the existing 56 patterns — catches the obvious attacks with zero ambiguity.
2. **Stage 2 (semantic, <50 µs):** Only if Stage 1 is clean, run the encoder classifier on the normalized text. If the classifier score exceeds the threshold (e.g., 0.95), emit `InjectionSuspected` (not `PromptInjectionDetected` — this is a softer signal).

The Aho-Corasick baseline remains the byte-exact, regression-locked behavior. The ML stage is strictly additive — it can only *reduce* false negatives (catch paraphrases the literals miss), never increase them.

### 4.2 Fleet Anomaly Detector (Use Case B) — Recommended Architecture

This model runs **offline** (batch processing of audit windows, not per-packet). Latency is not a constraint; throughput is.

#### Architecture: `SaacpTemporalGraphNet`

```
Input: Feature matrix for one audit window (e.g., 1 hour of fleet activity)
  │
  ▼
Feature Construction (offline, in Rust, not the model):
  │  For each agent in the window:
  │  - trust_score trajectory: [s(t-N), ..., s(t)] sampled at N=60 points
  │  - gate rejection histogram: 12-dim vector (one per gate)
  │  - delegation graph centrality: PageRank score over the session's delegation subgraph
  │  - temporal inter-arrival: mean/std of packet gaps
  │  - intent drift cumulative: IntentDriftTracker's chain-wide cumulative
  │  → Flatten to a feature vector per agent: ~100 dims
  │
  ▼
Temporal Convolutional Network (TCN):
  │  ├─ Input: [num_agents, 100] padded to max_agents=4096
  │  ├─ Dilated conv blocks (kernel=3, dilation=1,2,4,8,16,32) with causal masking
  │  ├─ GELU → LayerNorm → Dropout(0.1) between blocks
  │  └─ Output: [num_agents, 64] — learned behavioral embedding per agent
  │
  ▼
Graph Attention Layer:
  │  ├─ Edge features: delegation depth, trust differential, gate co-occurrence
  │  ├─ Multi-head attention (4 heads) over the delegation graph adjacency
  │  └─ Output: [num_agents, 64] — graph-aware embedding
  │
  ▼
Anomaly Scoring Head:
  │  ├─ Reconstruction: decode the temporal+graph representation back to the feature space
  │  ├─ Anomaly score = MSE(input_features, reconstructed_features)
  │  └─ Threshold: calibrated to 99.9th percentile on clean fleet data
  │
  Output: Vec<(agent_id, anomaly_score)> — sorted by score descending
```

**Parameter count:** ~2.8M (TCN: ~1.5M, GAT: ~1M, head: ~0.3M). Training is unsupervised — the model learns to reconstruct normal behavior and flags high-reconstruction-error agents. No labeled "compromised agent" data needed.

#### Training Data Source

The immutable audit log (`security.rs`) is already an append-only JSONL with `chain_hash`-linked entries. Build a daily ETL job that:

1. Reads the audit log for the last 24h.
2. Groups entries by `agent_id`.
3. Constructs the feature vector per agent above.
4. Writes `[features_json, window_id]` as a training sample.

No manual labeling required. The model trains on clean fleet traffic (which is the vast majority of data). Anomalous windows are excluded from training via the reconstruction-error threshold itself (iterative self-training: train → score → exclude top 0.1% → retrain).

#### Integration Point

This model does **not** connect to the gate pipeline. It produces a daily (or hourly) anomaly report that:

- Is posted to the `SecurityAlertFeed` (which already feeds the Command Center dashboard).
- Can optionally trigger a `penalize(agent, PenaltyKind::AnomalySuspected, weight=0.10)` via the existing trust engine API — but only with human approval (the model is advisory, not authoritative).
- Is logged to a new `AnomalyReport` table in the audit log, itself HMAC-chained for tamper-evidence.

### 4.3 Audit Summarizer (Use Case C) — Recommended Architecture

#### Architecture: `SaacpAuditSummarizer`

A small encoder-decoder or decoder-only LLM fine-tuned on (audit_window, natural_language_summary) pairs. This is the one place where a 500M–1B model might actually be warranted, because text generation requires representational capacity that a 3M classifier does not have.

```
Encoder: same frozen SaacpInjectionEncoder backbone (§4.1) — reuses the trained weights
Decoder: 4-layer causal transformer, cross-attending to encoder output
Vocab: sentencepiece unigram, vocab_size=4096, trained on SAACP audit schema + English
Max output tokens: 256
Training: supervised fine-tuning on operator-written summaries of historical audit windows
```

**Parameter count:** ~3.2M (encoder) + ~8M (decoder) ≈ **11M total**. Still well under 500M, but enough for coherent single-paragraph summarization.

#### Integration Point

Exposed as a new Command Center endpoint `POST /api/audit/summarize` that accepts a time range and returns a markdown summary. The operator reads the summary; the model has no write path to the trust engine.

---

## 5. Training Rules

### 5.1 Injection Classifier — Training Protocol

**Rule 1 — Data provenance:**
All training data must be traceable. Every sample must record its source dataset, generation method (human-written / red-team-tool-generated / synthetic), and any augmentation applied. Stored alongside the training data in a `provenance.jsonl` file.

**Rule 2 — Train/val/test split:**
- 70% train, 15% validation, 15% test.
- Stratified by attack category (prompt hijacking, LLM special tokens, SQLi, code injection, tool-call injection, confusable Unicode, multi-encode, clean English, clean code, clean multilingual).
- The test set must include a held-out set of attack patterns never seen in training (reserved from the red-team corpus).

**Rule 3 — Data balance:**
- Minimum 40% clean samples (ordinary English, code, multilingual text from non-agent sources — Wikipedia, StackOverflow, GitHub).
- Minimum 30% injection samples across all categories.
- The remaining 30% can be adversarial examples (GCG suffixes, multi-language injections, token smuggling).

**Rule 4 — Clean-text false-positive suite:**
A fixed corpus of 10,000+ ordinary English phrases that must classify as clean with probability < 0.05. This includes the specific false positives identified in the audit ("the contract as agreed", "contact assistant for scheduling", "perform retrieval (top-k)", "move the backdrop table") and thousands more drawn from general English corpora. This suite is run after every training epoch; any regression blocks promotion.

**Rule 5 — Training hyperparameters:**
- Optimizer: AdamW (lr=3e-4, weight_decay=0.01, β1=0.9, β2=0.999)
- Schedule: linear warmup for 1K steps, cosine decay to 1e-6
- Batch size: 256 (training), 1 (inference)
- Early stopping: patience=5 epochs on validation loss
- Max epochs: 50
- Mixed precision: bf16

**Rule 6 — Evaluation metrics (must all pass before deployment):**
- F1 > 0.95 on the injection class
- False positive rate < 0.01 on the clean-text suite
- AUC-ROC > 0.99
- Latency p99 < 50 µs on target hardware (measured via `criterion`)

**Rule 7 — Calibration:**
After training, apply temperature scaling on the validation set. A well-calibrated model means that when it says "95% probability of injection", at least 95% of those samples are actually injections. Without calibration, the threshold is meaningless.

**Rule 8 — No data leakage:**
The clean-text suite must not overlap with training data. Red-team-generated attacks must be generated with a different random seed than any seed used for training augmentations. The held-out test set must be generated by a different process (ideally, a different team member).

### 5.2 Fleet Anomaly Detector — Training Protocol

**Rule 1 — Unsupervised only:**
No labeled "compromised" data. The model learns the distribution of normal behavior and flags outliers. This avoids the impossible task of collecting representative attack data for an ever-evolving threat model.

**Rule 2 — Iterative self-training:**
- Round 1: train on all available clean data.
- Score all training data with the model.
- Remove top 0.1% by reconstruction error.
- Round 2: retrain on the cleaned dataset.
- Repeat for 3 rounds maximum (beyond that, overfitting to the self-selected "clean" set).

**Rule 3 — Temporal consistency:**
The model must not flag an agent as anomalous in one window and perfectly normal in the next if nothing changed. Add a temporal-smoothing term to the loss: the anomaly score for the same agent in consecutive windows must not jump by more than 0.2 unless there was a corresponding spike in gate rejections.

**Rule 4 — Fleet-invariant calibration:**
The reconstruction-error threshold must be calibrated per-deployment, not globally. Different fleets have different baseline behavior. The threshold is set at the 99.9th percentile of the fleet's own reconstruction errors over a 7-day calibration window.

**Rule 5 — Evaluation:**
No standard accuracy metric (no labels). Instead:
- **Coverage**: on a held-out clean week, < 0.1% of agents should be flagged.
- **Responsiveness**: inject a synthetic anomaly (e.g., a sudden spike in Gate 2.5 rejections for one agent) and verify the model flags it within the same window.
- **Stability**: running the model twice on the same window produces identical scores (determinism check).

### 5.3 Audit Summarizer — Training Protocol

**Rule 1 — Supervised fine-tuning from operator-written summaries:**
The base model is a small LLM pre-trained on general English + code. Fine-tuning data is (audit_window_features, operator_written_summary) pairs. Operators write summaries for historical audit windows during their regular work; these pairs are collected over time.

**Rule 2 — Summary format:**
Each summary must follow a fixed template:
```
## Audit Window [start] → [end]
- **Total events**: N (M agents)
- **Alerts fired**: [list of SecurityAlert types and counts]
- **Top 3 agents by rejection rate**: [agent_id, gate, count]
- **Notable patterns**: [free text, ≤ 200 chars]
- **Trust score changes**: [agents that crossed a threshold]
```

**Rule 3 — No hallucination:**
The decoder is constrained to only emit data that is present in the encoder's input. Use a copy mechanism that attends to the feature matrix, not free generation. Post-process every summary by verifying each numerical claim against the audit window data; any unverifiable claim is replaced with "[data unavailable]".

**Rule 4 — Latency:**
Summary generation must complete in < 5 seconds for a 1-hour window of 100K events. This is achievable with an 11M-parameter model on CPU.

---

## 6. Integration Rules

### 6.1 Hard Rules (must never be violated)

1. **No model in the packet path without a deterministic fallback.** Every ML component must have a well-defined fallback that activates if the model is unavailable, errors out, or exceeds its latency budget. The fallback is always the current deterministic behavior (Aho-Corasick for injection, hand-tuned thresholds for anomaly, empty summary for audit).

2. **Model outputs are never the sole basis for a trust penalty.** The `TrustDecayEngine` is the sole authority on trust scores. The ML system can emit `InjectionSuspected` signals that *contribute* to a penalty, but `penalize()` is only called after the deterministic gate pipeline's own logic has fired first. The ML is a second opinion, not a replacement.

3. **No model update without a shadow-eval.** New model weights are first deployed in shadow mode: they score traffic but do not influence any penalty or gate decision. Shadow scores are logged alongside the deterministic engine's decisions. After 7 days of shadow evaluation showing no regression, the model can be promoted to active.

4. **All model inputs and outputs are logged to the audit chain.** Every ML inference (input hash, output score, model version, timestamp) is appended to the immutable audit log. This ensures the ML system itself is auditable and tamper-evident.

5. **Model versioning is strict.** Each model artifact has a semantic version (major.minor.patch) and a content hash. The version is logged alongside every inference. Mixing model versions in a single audit window is prohibited.

### 6.2 Soft Rules (recommended but not required)

1. **Prefer smaller models.** If a 3M model achieves F1 > 0.95, do not use a 10M model. Complexity is the enemy of auditability.

2. **Prefer classification over generation.** Every use case that can be framed as classification should be. Generation (Use Case C) is the only reason to use a decoder, and even then, the output is template-constrained.

3. **Train on normalized text.** The classifier should be trained on the *output* of `normalize_window`, not raw text. This means the tokenizer and embedding layer match the actual input distribution at inference time.

4. **One model per use case, not one model for all.** The three use cases have different inputs, outputs, latency requirements, and training regimes. A single multi-task model would be harder to debug, harder to regression-test, and harder to roll back.

---

## 7. Continuous Improvement Roadmap

### Phase 0 — Foundation (weeks 1–4)

- [ ] Build the training data pipeline: export SAACP audit logs → feature vectors → `training_data/` directory.
- [ ] Build the clean-text false-positive suite (10K+ ordinary English phrases, verified against the current scanner).
- [ ] Set up the evaluation harness: a `tests/test_ml_classifier_rs.rs` test file that loads the trained model and runs the full test suite on every `cargo test`.
- [ ] Implement shadow-mode plumbing: the model wrapper struct has an `enum Mode { Shadow, Active }` field; shadow mode logs but does not penalize.
- [ ] Freeze the encoder architecture and write the config schema (a `ModelConfig` TOML that records vocab size, max length, num heads, etc.).

### Phase 1 — Injection Classifier v1 (weeks 5–8)

- [ ] Train v1.0 on the initial dataset.
- [ ] Run the false-positive suite. Iterate until FPR < 0.01.
- [ ] Run the held-out test set. Iterate until F1 > 0.95.
- [ ] Latency-benchmark on target hardware (i7 + Raspberry Pi).
- [ ] Deploy in shadow mode for 7 days alongside the Aho-Corasick baseline.
- [ ] Compare shadow scores vs. Aho-Corasick decisions. Tune the threshold.
- [ ] Promote to active: the classifier becomes Stage 2 of Gate 4.0.

### Phase 2 — Anomaly Detector v1 (weeks 9–14)

- [ ] Build the fleet feature extraction pipeline (daily ETL from audit log).
- [ ] Train v1.0 (unsupervised) on 30 days of clean fleet data.
- [ ] Calibrate the threshold on the fleet's own 99.9th percentile.
- [ ] Deploy in shadow mode: flag agents, log to a separate `anomaly_shadow` log, but do not penalize.
- [ ] Manually review flagged agents: tune the feature set to reduce false positives.
- [ ] Promote to active with human-in-the-loop: anomaly flags generate a `SecurityAlert` but require operator acknowledgment before any trust penalty is applied.

### Phase 3 — Audit Summarizer v1 (weeks 15–20)

- [ ] Collect 200+ (audit_window, operator_summary) pairs.
- [ ] Pre-train the decoder on general English + JSON.
- [ ] Fine-tune on the operator summaries.
- [ ] Deploy as a read-only Command Center endpoint. No trust engine integration.
- [ ] Collect operator feedback and iterate on the summary template.

### Phase 4 — Feedback Loop (ongoing, week 21+)

- [ ] Every gate rejection that the ML system scored but the deterministic engine did not (or vice versa) is stored as a "disagreement" in a new audit-log entry type.
- [ ] Weekly: review disagreements. If the ML was right (false negative by the deterministic engine), add the sample to the next training round.
- [ ] Weekly: review false positives flagged by operators. If the ML was wrong, add the sample to the clean-text suite and retrain.
- [ ] Monthly: full retraining on the accumulated audit-log data.
- [ ] Per release: shadow-evaluate the new model against the current production model for 7 days before promotion.

---

## 8. What NOT to Do

1. **Do not replace `TrustDecayEngine` with a neural network.** The deterministic arithmetic is the system's audit backbone. Replacing it would make the entire `verify_chain` / `verify_chain_disk` tamper-evidence property meaningless.

2. **Do not run the model in the packet hot path without a proven < 10 µs budget.** If the model cannot meet the latency budget on the target hardware, it does not go in the pipeline. Period.

3. **Do not train on production traffic without a shadow mode first.** Unsupervised models can learn the wrong thing. Shadow mode is mandatory for at least 7 days before any production traffic is scored.

4. **Do not use a generative model where a classifier suffices.** The injection classifier must be encoder-only. The anomaly detector must be unsupervised reconstruction. Only the summarizer uses generation, and even there, it is template-constrained.

5. **Do not skip the calibration step.** Uncalibrated probabilities are worse than no probabilities because they give a false sense of precision. A model that says "this is 99% likely to be injection" must be right 99% of the time when it says that.

6. **Do not let the model be the sole arbiter of a security decision.** The deterministic engine always has the final word. The ML is advisory, supplementary, and overridable by an operator.

7. **Do not ignore the non-English problem.** The classifier must be trained on and evaluated against Chinese, Russian, Arabic, Hindi, and Japanese text. If it only works on English, it is worse than the current scanner (which at least does not claim to work on non-English).

---

## 9. Summary

| | Hot-path trust scoring (proposed) | Auxiliary ML (this plan) |
|---|---|---|
| Latency budget | < 2 µs | < 50 µs (classifier), batch (anomaly), < 5 s (summarizer) |
| Determinism required | Yes | No (advisory) |
| Model size | 500M–1B (overkill) | 3M (classifier) / 3M (anomaly) / 11M (summarizer) |
| Training data | Would need labeled "compromised" data | Unsupervised (anomaly) / public datasets (classifier) / operator-written (summarizer) |
| Replaces deterministic engine? | Yes (bad idea) | No (advisory only) |
| Audit compatible? | No (opaque) | Yes (all inferences logged) |
| Rollback complexity | Very high | Low (disable shadow mode) |
| **Verdict** | **Do not build** | **Build this** |

The protocol's strength is its deterministic, auditable, fail-closed design. The auxiliary ML system strengthens it without compromising those properties. That is the plan.
