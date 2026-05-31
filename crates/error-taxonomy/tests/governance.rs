use std::fs;
use std::path::{Path, PathBuf};

const NOT_A_WALLET_PARAGRAPH: &str = "Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase manager, not an inheritance legal service, and not a recovery company. It is a free, open-source diagnostic tool that helps you test whether your recovery plan works.";

const FOUR_PROMISES: &[&str] = &[
    "We never ask for your real seed phrase.",
    "We never connect to the internet without your action.",
    "We never persist your wallet metadata.",
    "We never claim your funds are safe.",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should resolve")
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).expect("repo file should be readable")
}

#[derive(Debug)]
struct ProjectConfig {
    github_org: String,
    github_repo: String,
    github_url_base: String,
    site_domain: String,
    security_contact: String,
    pgp_fingerprint: String,
    pgp_key_block_file: String,
}

impl ProjectConfig {
    fn read() -> Self {
        let body = read_repo_file("project.config.toml");
        Self {
            github_org: toml_scalar(&body, "github", "org"),
            github_repo: toml_scalar(&body, "github", "repo"),
            github_url_base: toml_scalar(&body, "github", "url_base"),
            site_domain: toml_scalar(&body, "site", "domain"),
            security_contact: toml_scalar(&body, "site", "security_contact"),
            pgp_fingerprint: toml_scalar(&body, "maintainer", "pgp_fingerprint"),
            pgp_key_block_file: toml_scalar(&body, "maintainer", "pgp_key_block_file"),
        }
    }
}

#[test]
fn readme_contains_public_promises_and_configured_links() {
    let config = ProjectConfig::read();
    let readme = read_repo_file("README.md");
    let normalized = normalize_whitespace(&readme);

    assert!(
        normalized.contains(NOT_A_WALLET_PARAGRAPH),
        "README must include the canonical PRD §15.7 not-a-wallet paragraph"
    );

    for promise in FOUR_PROMISES {
        assert!(
            readme.contains(promise),
            "README is missing public promise `{promise}`"
        );
    }

    assert!(
        readme.contains(&format!("{}/releases", config.github_url_base)),
        "README release URL must come from project.config.toml"
    );
    assert!(
        readme.contains(&format!("https://{}/docs/", config.site_domain)),
        "README docs URL must come from project.config.toml"
    );
    assert!(
        readme.contains(&format!(
            "https://github.com/{}/{}",
            config.github_org, config.github_repo
        )),
        "README must reflect the configured GitHub org/repo"
    );
}

#[test]
fn security_policy_reflects_project_config() {
    let config = ProjectConfig::read();
    let security = read_repo_file("SECURITY.md");

    for promise in FOUR_PROMISES {
        assert!(
            security.contains(promise),
            "SECURITY.md is missing public promise `{promise}`"
        );
    }

    assert!(
        security.contains(&config.security_contact),
        "SECURITY.md must use the configured disclosure route"
    );
    assert!(
        security.contains(&config.pgp_fingerprint),
        "SECURITY.md must use the configured PGP fingerprint"
    );
    assert!(
        security.contains(&config.pgp_key_block_file),
        "SECURITY.md must mention the configured PGP key block file"
    );
    assert!(
        normalize_whitespace(&security).contains("90-day coordinated disclosure window"),
        "SECURITY.md must document the 90-day window"
    );

    let issue_template = read_repo_file(".github/ISSUE_TEMPLATE/security_report.md");
    assert!(
        issue_template.contains(&config.security_contact),
        "security issue template must use the configured disclosure route"
    );

    if config.pgp_fingerprint.contains("__") || config.pgp_key_block_file.contains("__") {
        assert!(
            security.contains("TODO: REPLACE BEFORE PUBLIC RELEASE — see docs/CONFIGURATION.md"),
            "placeholder PGP config must render the public-release TODO banner"
        );
    } else {
        let key_block = read_repo_file(&config.pgp_key_block_file);
        assert!(
            security.contains(&key_block),
            "SECURITY.md must embed the configured PGP key block"
        );
    }
}

#[test]
fn codeowners_requests_two_maintainer_groups_for_sensitive_paths() {
    let config = ProjectConfig::read();
    let codeowners = read_repo_file("CODEOWNERS");
    let maintainers = format!("@{}/maintainers", config.github_org);
    let security_maintainers = format!("@{}/security-maintainers", config.github_org);

    for path in [
        "/crates/descriptor-audit/",
        "/crates/sensitive-input-detector/",
        "/.github/workflows/release.yml",
        "/apps/desktop/src-tauri/capabilities/",
        "/apps/desktop/src-tauri/tauri.conf.json",
    ] {
        let line = codeowners
            .lines()
            .find(|line| line.starts_with(path))
            .unwrap_or_else(|| panic!("CODEOWNERS is missing {path}"));
        assert!(
            line.contains(&maintainers) && line.contains(&security_maintainers),
            "CODEOWNERS entry for {path} must request two configured maintainer groups"
        );
    }
}

fn toml_scalar(body: &str, section: &str, key: &str) -> String {
    let mut current_section = "";

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = &trimmed[1..trimmed.len() - 1];
            continue;
        }

        if current_section != section || !trimmed.starts_with(key) {
            continue;
        }

        let Some((found_key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if found_key.trim() != key {
            continue;
        }

        return value.trim().trim_matches('"').to_owned();
    }

    panic!("missing project.config.toml value [{section}].{key}");
}

fn normalize_whitespace(body: &str) -> String {
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}
