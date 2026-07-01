#!/usr/bin/env bash
# BREAKIT Phase 5: Supply Chain and Operational Security Checks
#
# Run this from the saacp-rs crate root:
#   bash tests/breakit/supplychain/run_checks.sh
#
# Requires: cargo, cargo-audit (cargo install cargo-audit), grep, gdb (optional)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

LOG_DIR="tests/breakit/logs"
mkdir -p "$LOG_DIR"

echo "==================================================================="
echo "  BREAKIT PHASE 5 — SUPPLY CHAIN SECURITY CHECKS"
echo "==================================================================="
echo ""

# ── Check 1: Log leak (RUST_LOG=trace) ────────────────────────────────────────
echo "[1/5] Checking for key material in RUST_LOG=trace output..."
RUST_LOG=trace cargo test 2>&1 \
  | grep -iE 'psk|session_key|signing_key|secret[^s]|private.*key' \
  > "$LOG_DIR/log_leak.log" 2>&1 || true

if [ -s "$LOG_DIR/log_leak.log" ]; then
  echo "  [WARNING] Potential sensitive values in trace log:"
  head -20 "$LOG_DIR/log_leak.log"
  echo "  Full output: $LOG_DIR/log_leak.log"
else
  echo "  [OK] No sensitive values found in RUST_LOG=trace output."
fi
echo ""

# ── Check 2: Backtrace leak ───────────────────────────────────────────────────
echo "[2/5] Checking for sensitive values in backtraces..."
RUST_BACKTRACE=full cargo test 2>&1 \
  | grep -iE 'psk|session_key|private[^_]' \
  > "$LOG_DIR/backtrace_leak.log" 2>&1 || true

if [ -s "$LOG_DIR/backtrace_leak.log" ]; then
  echo "  [WARNING] Potential sensitive values in backtrace:"
  cat "$LOG_DIR/backtrace_leak.log"
else
  echo "  [OK] No sensitive values found in backtraces."
fi
echo ""

# ── Check 3: Duplicate dependency versions ────────────────────────────────────
echo "[3/5] Checking for duplicate dependency versions..."
cargo tree --duplicates 2>&1 | tee "$LOG_DIR/dep_duplicates.log"
echo ""

# ── Check 4: Dependency sources (crates.io vs git) ───────────────────────────
echo "[4/5] Checking dependency sources..."
grep -E 'source = ' Cargo.lock \
  | sort -u \
  | tee "$LOG_DIR/dep_sources.log"

GIT_DEPS=$(grep -E 'source = "git\+' Cargo.lock | grep -v '#' | wc -l || true)
if [ "$GIT_DEPS" -gt 0 ]; then
  echo ""
  echo "  [WARNING] $GIT_DEPS git dependencies WITHOUT pinned commit hash:"
  grep -E 'source = "git\+' Cargo.lock | grep -v '#'
else
  echo "  [OK] No unpinned git dependencies found."
fi
echo ""

# ── Check 5: cargo audit ─────────────────────────────────────────────────────
echo "[5/5] Running cargo audit for known CVEs..."
if command -v cargo-audit &>/dev/null; then
  cargo audit 2>&1 | tee "$LOG_DIR/cargo_audit.log"
else
  echo "  [SKIP] cargo-audit not installed. Run: cargo install cargo-audit"
  echo "  Then: cargo audit"
fi
echo ""

echo "==================================================================="
echo "  Supply chain check complete. Logs in: $LOG_DIR/"
echo "==================================================================="
