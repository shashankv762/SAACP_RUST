//! Guard against cp1252 double-encoding ("mojibake") regressions in `src/`.
//!
//! Background (longcat.md re-verification, Step 1): the Phase-4 clock
//! refactor was authored through an editor that wrote UTF-8 as cp1252, so
//! every non-ASCII character it emitted was double-encoded — an em dash
//! (U+2014) reached the files as the five-byte sequence `C3 A2 E2 82 AC E2
//! 80 9D` ("â€""), box-drawing separators as `â"€`, arrows as `â†'`, and so
//! on, including inside user-facing `SAACPHardDrop` message strings. The
//! corruption was repaired across the eight affected modules in 2026-09 by
//! the exact inverse transform (decode UTF-8, re-encode cp1252, decode
//! UTF-8).
//!
//! This guard fails if any artifact character reappears. The characters
//! listed below NEVER occur legitimately in this codebase's sources (its
//! non-ASCII vocabulary is intentionally limited to the box-drawing,
//! dash, arrow, section-sign, and ellipsis set — see the doc test at the
//! bottom), so each hit is a corruption, not style.

use std::fs;
use std::path::{Path, PathBuf};

/// Characters produced exclusively by cp1252 double-encoding artifacts.
/// Written as escapes so this test file itself stays pure-ASCII-safe.
const MOJIBAKE_ONLY_CHARS: &[char] = &[
    '\u{00E2}', // â  (cp1252 rendering of byte 0xE2 — leads â€/â†/â‡/â"/â"€ forms)
    '\u{00C2}', // Â  (cp1252 rendering of byte 0xC2 — leads Â§/Â  forms)
    '\u{20AC}', // €  (cp1252 rendering of byte 0x80)
    '\u{201C}', // "  (cp1252 rendering of byte 0x93)
    '\u{201D}', // "  (cp1252 rendering of byte 0x94)
    '\u{2018}', // '  (cp1252 rendering of byte 0x91)
    '\u{2019}', // '  (cp1252 rendering of byte 0x92)
    '\u{2020}', // †  (cp1252 rendering of byte 0x86)
    '\u{2021}', // ‡  (cp1252 rendering of byte 0x87)
    '\u{00A6}', // ¦  (cp1252 rendering of byte 0xA6 — â€¦ ellipsis tail)
    '\u{0153}', // œ  (cp1252 rendering of byte 0x9C)
    '\u{2039}', // ‹  (cp1252 rendering of byte 0x8B)
    '\u{203A}', // ›  (cp1252 rendering of byte 0x9B)
    '\u{02DC}', // ˜  (cp1252 rendering of byte 0x98)
    '\u{00BD}', // ½  (cp1252 rendering of byte 0xBD)
];

/// Characters legitimately used in comments/strings. If a future change
/// needs one of the guard characters for real, extend the vocabulary here
/// AND re-check the file is genuinely intended (never a paste artifact).
const LEGITIMATE_NON_ASCII: &[char] = &[
    '\u{2500}', // ─  box drawing
    '\u{2014}', // —  em dash
    '\u{2013}', // –  en dash
    '\u{2192}', // →  rightwards arrow
    '\u{21D2}', // ⇒  rightwards double arrow
    '\u{00A7}', // §  section sign
    '\u{2026}', // …  horizontal ellipsis
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_double_encoded_mojibake_in_sources() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(
        files.len() > 50,
        "expected to scan the full src tree, found {} files",
        files.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let content = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("failed to read {:?} as UTF-8: {e}", file));
        for (byte_idx, ch) in content.char_indices() {
            if MOJIBAKE_ONLY_CHARS.contains(&ch) {
                let line = content[..byte_idx].lines().count() + 1;
                offenders.push(format!(
                    "{:?}:{} contains mojibake artifact {:?} — repair with the cp1252 round-trip",
                    file, line, ch
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "double-encoded cp1252 artifacts found in sources:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn guard_vocabulary_is_disjoint_from_legitimate_set() {
    for ch in MOJIBAKE_ONLY_CHARS {
        assert!(
            !LEGITIMATE_NON_ASCII.contains(ch),
            "character {ch:?} is both a guard artifact and legitimate vocabulary — resolve"
        );
    }
}
