use std::fs;
use std::path::Path;

use rust_probe::core::{ClaimedIdentity, ObservedBehavior};
use rust_probe::engine::MismatchEngine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GoldenCase {
    name: String,
    claimed: ClaimedIdentity,
    observed: ObservedBehavior,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    spoofed: bool,
}

#[test]
fn golden_identity_mismatch_cases() {
    let dir = Path::new("tests/golden");
    let engine = MismatchEngine::new();

    let mut count = 0usize;
    for entry in fs::read_dir(dir).expect("read_dir tests/golden") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let raw = fs::read_to_string(&path).expect("read golden json");
        let case: GoldenCase = serde_json::from_str(&raw).expect("parse golden json");

        let mismatch = engine.detect_mismatches(&case.claimed, &case.observed);
        let spoofed = matches!(
            mismatch.severity,
            rust_probe::core::MismatchSeverity::Major | rust_probe::core::MismatchSeverity::Critical
        );
        assert_eq!(spoofed, case.expected.spoofed, "golden case failed: {}", case.name);
        count += 1;
    }

    assert!(count >= 4, "expected at least 4 golden cases, got {}", count);
}

