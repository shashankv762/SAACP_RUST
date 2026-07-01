#!/usr/bin/env python3
"""
Cross-language wire-format verification script.

Replicates the exact same operations as tests/test_cross_lang_vectors_rs.rs
using Python's `cryptography` library (the SAACP Python reference).

Usage:
    pip install cryptography ed25519
    python3 tests/cross_lang_verify.py

Each vector prints:
    PASS   — Python matches the Rust hardcoded value
    FAIL   — Python diverges (a cross-language bug)
    KNOWN  — documented divergence, listed separately

Known divergences:
    1. EPOCH_KEY_CHAINED: Rust and Python use different IKM / info strings.
       The Python algorithm is normative (CLAUDE.md). Rust must be fixed.
    2. EASI: Python build_frame writes plaintext context_ref_id at header[44..76].
       Rust encrypts it. Full frame bytes differ at that range.
"""

import sys
import struct
import json
from collections import OrderedDict

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    import cryptography
except ImportError:
    print("ERROR: pip install cryptography", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

PASS  = "\033[32mPASS\033[0m"
FAIL  = "\033[31mFAIL\033[0m"
KNOWN = "\033[33mKNOWN-DIVERGENCE\033[0m"

results = []

def check(name, rust_expected, python_got, known_divergence=False):
    tag = KNOWN if known_divergence else (PASS if python_got == rust_expected else FAIL)
    results.append((name, tag, python_got, rust_expected))
    print(f"{tag}  {name}")
    if python_got != rust_expected:
        print(f"       Rust expected : {rust_expected}")
        print(f"       Python produced: {python_got}")
        if known_divergence:
            print(f"       (This divergence is documented — fix Rust to match Python)")


# ── Vector 1: HKDF initial epoch key (epoch 0, no prev_key) ──────────────────
# HKDF-SHA256(ikm=[0xAA]*32, salt=[0x01]*16,
#             info=b"SAACP-MEASC-epoch-key-v1\x00\x00\x00\x00")
session_secret = bytes([0xAA] * 32)
session_id     = bytes([0x01] * 16)
info_v1 = b"SAACP-MEASC-epoch-key-v1" + (0).to_bytes(4, "big")
h = HKDF(algorithm=hashes.SHA256(), length=32, salt=session_id,
         info=info_v1, backend=default_backend())
key_initial = h.derive(session_secret)
check(
    "hkdf_epoch_key_initial",
    rust_expected="65b32ae4912b806927dfd2d9357e380caa229afb951fbd26745ae1f727acddeb",
    python_got=key_initial.hex(),
)

# ── Vector 2: HKDF chained epoch key — Rust now matches Python ──────────────
# Both use: ikm = session_secret XOR prev_key,
#           info = b"SAACP-MEASC-epoch-key-v1" + epoch_id_be4
prev_key = bytes([0xBB] * 32)
ikm_python = bytes(a ^ b for a, b in zip(session_secret, prev_key))
info_chain = b"SAACP-MEASC-epoch-key-v1" + (1).to_bytes(4, "big")
h2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=session_id,
          info=info_chain, backend=default_backend())
key_chained_python = h2.derive(ikm_python)
check(
    "hkdf_epoch_key_chained",
    rust_expected="62f34873a678aa43b916fc1ae6acd3df49cd73af250f723cdec0568d12c1e304",
    python_got=key_chained_python.hex(),
)

# ── Vector 3: AES-256-GCM NIST empty-plaintext known-answer ─────────────────
# key=00*32, iv=00*12, aad=[], plaintext=[] → tag = 530f8afbc74536b9a963b4f1c4cb738b
aesgcm = AESGCM(bytes(32))
ct_tag = aesgcm.encrypt(bytes(12), b"", b"")  # ciphertext(0) + tag(16)
check(
    "aes256gcm_nist_empty_plaintext",
    rust_expected="530f8afbc74536b9a963b4f1c4cb738b",
    python_got=ct_tag.hex(),
)

# ── Vector 4: IV derivation ───────────────────────────────────────────────────
# HKDF-Expand(PRK=traffic_key, info=b"SAACP-MEASC-iv-v1"+epoch_id_be4+psn_be8, length=12)
# Derive traffic_key first (initial epoch, session_secret=[0xCC]*32, session_id=[0x02]*16)
session_secret_3 = bytes([0xCC] * 32)
session_id_3     = bytes([0x02] * 16)
info_ek = b"SAACP-MEASC-epoch-key-v1" + (0).to_bytes(4, "big")
h3 = HKDF(algorithm=hashes.SHA256(), length=32, salt=session_id_3,
          info=info_ek, backend=default_backend())
traffic_key = h3.derive(session_secret_3)

# Now derive IV for epoch_id=0, psn=1
info_iv = b"SAACP-MEASC-iv-v1" + (0).to_bytes(4, "big") + (1).to_bytes(8, "big")
iv_expand = HKDFExpand(algorithm=hashes.SHA256(), length=12, info=info_iv,
                        backend=default_backend())
iv = iv_expand.derive(traffic_key)
# We don't have a standalone Rust vector for IV — this is embedded in the frame.
# Print it so the user can compare with Rust's internal computation.
print(f"[INFO]  iv_derivation (epoch=0, psn=1): {iv.hex()}")

# ── Vector 5: SignedCapabilityToken wire format ───────────────────────────────
# Requires the `cryptography` Ed25519 or `ed25519` package.
if Ed25519PrivateKey is not None:
    import base64 as b64
    seed = bytes([0xDD] * 32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    claims = OrderedDict(sorted({
        "exp":    1700003600,
        "iat":    1700000000,
        "iss":    "test-issuer",
        "scopes": ["read"],
        "sub":    "test-agent",
    }.items()))
    json_bytes = json.dumps(claims, separators=(",", ":")).encode()
    to_sign = len(json_bytes).to_bytes(4, "big") + json_bytes
    sig = private_key.sign(to_sign)

    payload = to_sign + sig
    wire_b64 = b64.b64encode(payload)
    wire_hex = wire_b64.hex()

    check(
        "token_wire_roundtrip",
        rust_expected="41414141584873695a586877496a6f784e7a41774d44417a4e6a41774c434a70"
                      "595851694f6a45334d4441774d4441774d444173496d6c7a63794936496e526c"
                      "6333517461584e7a645756794969776963324e766347567a496a7062496e4a6c"
                      "595751695853776963335669496a6f696447567a644331685a32567564434a39"
                      "583755646850314c7470687178532f314546493167386877303370636c6d6e39"
                      "75414d6769352b434c704e57446f4d59694e534f3377715248733054626a4c4f"
                      "6d4563312b6f55653058785079716b394f4c6f6f42413d3d",
        python_got=wire_hex,
    )
else:
    print(f"[SKIP]  token_wire_roundtrip (Ed25519PrivateKey not available)")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
passes   = sum(1 for _, t, _, _ in results if "PASS"  in t)
failures = sum(1 for _, t, _, _ in results if "FAIL"  in t)
known    = sum(1 for _, t, _, _ in results if "KNOWN" in t)
print(f"Results: {passes} PASS, {failures} FAIL, {known} KNOWN-DIVERGENCE")
if failures:
    print("CROSS-LANGUAGE BUGS FOUND — fix the Rust implementation.")
    sys.exit(1)
elif known:
    print("Known divergences require Rust fixes (see CLAUDE.md §KNOWN DIVERGENCES).")
