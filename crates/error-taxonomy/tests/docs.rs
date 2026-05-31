use std::fs;
use std::path::{Path, PathBuf};

use error_taxonomy::ErrorCode;

const REQUIRED_DOCS: &[&str] = &[
    "docs/mission.md",
    "docs/safety-model.md",
    "docs/user-guide.md",
    "docs/download-verify-signature.md",
    "docs/threat-model.md",
    "docs/architecture.md",
    "docs/developer-guide.md",
    "docs/descriptor-audit.md",
    "docs/scoring.md",
    "docs/wallet-compatibility.md",
    "docs/cli-reference.md",
    "docs/json-schemas.md",
    "docs/error-codes.md",
    "docs/heir-mode.md",
    "docs/practice-seeds.md",
    "docs/psbt-drills.md",
    "docs/hardware-wallet-drill.md",
    "docs/signet-practice.md",
    "docs/recovery-day.md",
    "docs/reproducible-builds.md",
    "docs/security-audit.md",
    "docs/acceptance-v0.1.md",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should resolve")
}

#[test]
fn required_docs_exist() {
    let root = repo_root();
    for relative in REQUIRED_DOCS {
        let path = root.join(relative);
        assert!(path.is_file(), "{relative} is missing");
    }
}

#[test]
fn error_code_docs_cover_every_shipping_code() {
    let root = repo_root();
    let body = fs::read_to_string(root.join("docs/error-codes.md"))
        .expect("docs/error-codes.md should be readable");

    for &code in ErrorCode::ALL {
        let meta = code.meta();
        assert!(
            body.contains(meta.code),
            "docs/error-codes.md is missing {}",
            meta.code
        );
        assert!(
            body.contains(meta.severity.as_str()),
            "docs/error-codes.md is missing severity for {}",
            meta.code
        );
        assert!(
            body.contains(meta.title),
            "docs/error-codes.md is missing title for {}",
            meta.code
        );
        assert!(
            body.contains(meta.description),
            "docs/error-codes.md is missing description for {}",
            meta.code
        );
        assert!(
            body.contains(meta.action),
            "docs/error-codes.md is missing action for {}",
            meta.code
        );
    }
}

#[test]
fn relative_markdown_doc_links_point_to_existing_files() {
    let root = repo_root();
    let docs_dir = root.join("docs");

    for entry in fs::read_dir(&docs_dir).expect("docs directory should be readable") {
        let path = entry.expect("docs entry should be readable").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }

        // The canonical PRD references future-version docs that are not part of
        // the MVP docs set. The shipped docs are checked below.
        if path.file_name().and_then(|name| name.to_str()) == Some("PRD-v2.md") {
            continue;
        }

        let body = fs::read_to_string(&path).expect("markdown doc should be readable");
        for (line_index, target) in markdown_link_targets(&body) {
            if !is_relative_markdown_doc_link(target) {
                continue;
            }

            let target_without_anchor = target.split('#').next().unwrap_or(target);
            let resolved = if let Some(stripped) = target_without_anchor.strip_prefix("docs/") {
                docs_dir.join(stripped)
            } else {
                path.parent()
                    .expect("doc should have a parent")
                    .join(target_without_anchor)
            };

            assert!(
                resolved.is_file(),
                "{}:{} links to missing doc `{}`",
                path.display(),
                line_index + 1,
                target
            );
        }
    }
}

fn markdown_link_targets(body: &str) -> Vec<(usize, &str)> {
    let mut targets = Vec::new();

    for (line_index, line) in body.lines().enumerate() {
        let mut cursor = 0usize;
        while let Some(start) = line[cursor..].find("](") {
            let target_start = cursor + start + 2;
            let Some(end) = line[target_start..].find(')') else {
                break;
            };
            let target = &line[target_start..target_start + end];
            targets.push((line_index, target));
            cursor = target_start + end + 1;
        }
    }

    targets
}

fn is_relative_markdown_doc_link(target: &str) -> bool {
    let target_without_anchor = target.split('#').next().unwrap_or(target);
    !target_without_anchor.is_empty()
        && !target_without_anchor.starts_with("http://")
        && !target_without_anchor.starts_with("https://")
        && !target_without_anchor.starts_with("mailto:")
        && !target_without_anchor.starts_with('#')
        && target_without_anchor.ends_with(".md")
}
