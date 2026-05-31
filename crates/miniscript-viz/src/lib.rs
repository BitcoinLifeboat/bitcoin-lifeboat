//! `miniscript-viz` - GraphViz DOT rendering for descriptor spending policies.
//!
//! This crate turns an already-validated output descriptor into a small,
//! deterministic DOT graph that the desktop UI can render for v0.5 Liana /
//! Miniscript visualization (PRD section 11.4). It uses rust-miniscript's
//! [`Liftable`](miniscript::policy::Liftable) trait so the graph represents the
//! semantic spending policy, not frontend-parsed descriptor text.
//!
//! # Safety
//! DOT labels intentionally do **not** include xpubs, fingerprints, addresses,
//! descriptors, or any other wallet metadata. Key leaves are rendered as
//! `key 1`, `key 2`, and so on in deterministic traversal order.

use descriptor_audit::{parse_descriptor, ParsedDescriptor};
use error_taxonomy::{ErrorCode, LifeboatError};
use miniscript::bitcoin::{absolute, relative};
use miniscript::descriptor::DescriptorPublicKey;
use miniscript::policy::{semantic::Policy, Liftable};
use miniscript::{AbsLockTime, Descriptor, MiniscriptKey, RelLockTime};
use serde::Serialize;

/// Render the spending policy for a raw descriptor string as GraphViz DOT.
///
/// Parsing is delegated to `descriptor-audit` so checksum validation, xprv
/// refusal, mixed-network checks, and all descriptor invariants stay in the
/// canonical parse layer.
pub fn descriptor_to_dot(input: &str) -> Result<String, LifeboatError> {
    let parsed = parse_descriptor(input)?;
    parsed_descriptor_to_dot(&parsed)
}

/// Extract and render a Liana-style recovery-path tree for a raw descriptor.
///
/// The returned tree is public-safe: it names paths, key counts, and timelocks,
/// but never includes descriptors, xpubs, fingerprints, addresses, or pubkeys.
pub fn liana_recovery_tree(input: &str) -> Result<LianaRecoveryTree, LifeboatError> {
    let parsed = parse_descriptor(input)?;
    parsed_liana_recovery_tree(&parsed)
}

/// Extract and render a Liana-style recovery-path tree with current-block
/// countdowns for block-height timelocks.
///
/// The current height is caller-supplied: this crate performs no chain lookup or
/// network IO.
pub fn liana_recovery_tree_at_block(
    input: &str,
    current_block_height: u32,
) -> Result<LianaRecoveryTree, LifeboatError> {
    let parsed = parse_descriptor(input)?;
    parsed_liana_recovery_tree_at_block(&parsed, current_block_height)
}

/// Render the spending policy for an already parsed descriptor as GraphViz DOT.
pub fn parsed_descriptor_to_dot(parsed: &ParsedDescriptor) -> Result<String, LifeboatError> {
    descriptor_policy_to_dot(parsed.descriptor())
}

/// Lift a rust-miniscript descriptor into its semantic policy and render it.
pub fn descriptor_policy_to_dot(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<String, LifeboatError> {
    let policy = lift_descriptor_policy(descriptor)?;
    Ok(policy_to_dot(&policy))
}

/// Extract and render a Liana-style recovery-path tree from a parsed descriptor.
///
/// This is intentionally based on rust-miniscript's lifted semantic policy. The
/// UI receives only the redacted path summaries and DOT tree, never raw policy
/// text or key material.
pub fn parsed_liana_recovery_tree(
    parsed: &ParsedDescriptor,
) -> Result<LianaRecoveryTree, LifeboatError> {
    let policy = lift_descriptor_policy(parsed.descriptor())?;
    recovery_tree_from_policy(&policy, None)
}

/// Extract and render a Liana-style recovery-path tree from a parsed descriptor,
/// adding countdown fields for block-height timelocks.
pub fn parsed_liana_recovery_tree_at_block(
    parsed: &ParsedDescriptor,
    current_block_height: u32,
) -> Result<LianaRecoveryTree, LifeboatError> {
    let policy = lift_descriptor_policy(parsed.descriptor())?;
    recovery_tree_from_policy(&policy, Some(current_block_height))
}

/// A public-safe visualization payload for Liana-style recovery policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LianaRecoveryTree {
    /// Redacted DOT tree for the desktop renderer.
    pub dot: String,
    /// One spend path per top-level policy alternative, in descriptor order.
    pub paths: Vec<LianaRecoveryPath>,
}

/// One Liana spend path: either the primary path or a timelocked recovery path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LianaRecoveryPath {
    /// One-based position in the lifted top-level policy alternatives.
    pub index: usize,
    /// UI-safe display label such as `"Primary path"` or `"Recovery path 1"`.
    pub label: String,
    /// Whether this path is immediate primary spending or timelocked recovery.
    pub kind: LianaRecoveryPathKind,
    /// Count of redacted key leaves required by this path.
    pub key_count: usize,
    /// Relative timelocks (`older`) that gate this path.
    pub relative_timelocks: Vec<RelativeTimelock>,
    /// Absolute timelocks (`after`) that gate this path.
    pub absolute_timelocks: Vec<AbsoluteTimelock>,
    /// Current-block countdown for block-height timelocks, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub countdown: Option<LianaRecoveryCountdown>,
}

/// The role of a Liana recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LianaRecoveryPathKind {
    /// A spend path without a timelock.
    Primary,
    /// A spend path gated by at least one timelock.
    Recovery,
}

/// A current-block countdown for one Liana recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LianaRecoveryCountdown {
    /// Caller-supplied current block height.
    pub current_block_height: u32,
    /// Remaining blocks until this path's block-height constraints are met.
    pub active_in_blocks: u64,
    /// The block height at which those block-height constraints are met.
    pub active_at_block: u64,
}

/// A relative timelock on a recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RelativeTimelock {
    /// Whether the lock is height-based or time-interval-based.
    pub unit: RelativeTimelockUnit,
    /// Blocks for `blocks`, 512-second intervals for `time`.
    pub value: u32,
    /// Approximate wall-clock minutes. Height locks use 10 minutes per block.
    pub estimated_minutes: u64,
    /// Approximate wall-clock days, rounded to the nearest whole day.
    pub estimated_days: u64,
}

/// The unit for a relative timelock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelativeTimelockUnit {
    /// BIP68 block-height relative lock.
    Blocks,
    /// BIP68 512-second interval relative lock.
    Time,
}

/// An absolute timelock on a recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AbsoluteTimelock {
    /// Whether the lock is a block height or Unix timestamp.
    pub unit: AbsoluteTimelockUnit,
    /// Block height or Unix timestamp, matching `unit`.
    pub value: u32,
}

/// The unit for an absolute timelock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsoluteTimelockUnit {
    /// Absolute block height.
    Height,
    /// Absolute Unix timestamp.
    Timestamp,
}

/// Render a semantic Miniscript policy as a deterministic GraphViz DOT graph.
///
/// This helper is generic over key type and never prints key contents.
#[must_use]
pub fn policy_to_dot<Pk: MiniscriptKey>(policy: &Policy<Pk>) -> String {
    let mut renderer = DotRenderer::default();
    renderer.render_graph(policy)
}

fn lift_descriptor_policy(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<Policy<DescriptorPublicKey>, LifeboatError> {
    descriptor.lift().map_err(|err| {
        LifeboatError::new(ErrorCode::ParseFailed)
            .with_context("descriptor spending policy could not be lifted for visualization")
            .with_source(err)
    })
}

fn recovery_tree_from_policy<Pk: MiniscriptKey>(
    policy: &Policy<Pk>,
    current_block_height: Option<u32>,
) -> Result<LianaRecoveryTree, LifeboatError> {
    let alternatives = policy_alternatives(policy);
    let mut paths = Vec::with_capacity(alternatives.len());
    let mut recovery_count = 0usize;

    for (index, alternative) in alternatives.iter().enumerate() {
        let summary = summarize_path(alternative);
        let countdown =
            current_block_height.and_then(|height| countdown_for_path(&summary, height));
        let kind = if summary.relative_timelocks.is_empty() && summary.absolute_timelocks.is_empty()
        {
            LianaRecoveryPathKind::Primary
        } else {
            LianaRecoveryPathKind::Recovery
        };
        let label = match kind {
            LianaRecoveryPathKind::Primary => "Primary path".to_owned(),
            LianaRecoveryPathKind::Recovery => {
                recovery_count += 1;
                format!("Recovery path {recovery_count}")
            }
        };
        paths.push(LianaRecoveryPath {
            index: index + 1,
            label,
            kind,
            key_count: summary.key_count,
            relative_timelocks: summary.relative_timelocks,
            absolute_timelocks: summary.absolute_timelocks,
            countdown,
        });
    }

    if recovery_count == 0 {
        return Err(LifeboatError::new(ErrorCode::ParseFailed)
            .with_context("descriptor does not contain a timelocked recovery path"));
    }

    let dot = liana_paths_to_dot(&paths);
    Ok(LianaRecoveryTree { dot, paths })
}

fn countdown_for_path(
    summary: &PathSummary,
    current_block_height: u32,
) -> Option<LianaRecoveryCountdown> {
    let mut active_in_blocks = None;

    for lock in &summary.relative_timelocks {
        if lock.unit == RelativeTimelockUnit::Blocks {
            active_in_blocks = max_remaining(active_in_blocks, u64::from(lock.value));
        }
    }

    for lock in &summary.absolute_timelocks {
        if lock.unit == AbsoluteTimelockUnit::Height {
            let remaining = lock.value.saturating_sub(current_block_height);
            active_in_blocks = max_remaining(active_in_blocks, u64::from(remaining));
        }
    }

    active_in_blocks.map(|remaining| LianaRecoveryCountdown {
        current_block_height,
        active_in_blocks: remaining,
        active_at_block: u64::from(current_block_height).saturating_add(remaining),
    })
}

fn max_remaining(current: Option<u64>, candidate: u64) -> Option<u64> {
    Some(current.map_or(candidate, |value| value.max(candidate)))
}

fn policy_alternatives<Pk: MiniscriptKey>(policy: &Policy<Pk>) -> Vec<&Policy<Pk>> {
    if let Policy::Thresh(threshold) = policy {
        if threshold.k() == 1 && threshold.n() > 1 {
            return threshold
                .data()
                .iter()
                .map(|child| child.as_ref())
                .collect();
        }
    }
    vec![policy]
}

#[derive(Debug, Default)]
struct PathSummary {
    key_count: usize,
    relative_timelocks: Vec<RelativeTimelock>,
    absolute_timelocks: Vec<AbsoluteTimelock>,
}

fn summarize_path<Pk: MiniscriptKey>(policy: &Policy<Pk>) -> PathSummary {
    let mut summary = PathSummary::default();
    collect_path_summary(policy, &mut summary);
    summary
        .relative_timelocks
        .sort_by_key(|lock| (lock.unit, lock.value));
    summary.relative_timelocks.dedup();
    summary
        .absolute_timelocks
        .sort_by_key(|lock| (lock.unit, lock.value));
    summary.absolute_timelocks.dedup();
    summary
}

fn collect_path_summary<Pk: MiniscriptKey>(policy: &Policy<Pk>, summary: &mut PathSummary) {
    match policy {
        Policy::Key(_) => summary.key_count += 1,
        Policy::Older(locktime) => summary
            .relative_timelocks
            .push(relative_timelock(*locktime)),
        Policy::After(locktime) => summary
            .absolute_timelocks
            .push(absolute_timelock(*locktime)),
        Policy::Thresh(threshold) => {
            for child in threshold.data() {
                collect_path_summary(child.as_ref(), summary);
            }
        }
        Policy::Unsatisfiable
        | Policy::Trivial
        | Policy::Sha256(_)
        | Policy::Hash256(_)
        | Policy::Ripemd160(_)
        | Policy::Hash160(_) => {}
    }
}

fn relative_timelock(locktime: RelLockTime) -> RelativeTimelock {
    let relative: relative::LockTime = locktime.into();
    match relative {
        relative::LockTime::Blocks(height) => {
            let value = u32::from(height.value());
            let estimated_minutes = u64::from(value) * 10;
            RelativeTimelock {
                unit: RelativeTimelockUnit::Blocks,
                value,
                estimated_minutes,
                estimated_days: rounded_days(estimated_minutes),
            }
        }
        relative::LockTime::Time(time) => {
            let value = u32::from(time.value());
            let estimated_minutes = (u64::from(value) * 512) / 60;
            RelativeTimelock {
                unit: RelativeTimelockUnit::Time,
                value,
                estimated_minutes,
                estimated_days: rounded_days(estimated_minutes),
            }
        }
    }
}

fn absolute_timelock(locktime: AbsLockTime) -> AbsoluteTimelock {
    let absolute: absolute::LockTime = locktime.into();
    let unit = if absolute.is_block_height() {
        AbsoluteTimelockUnit::Height
    } else {
        AbsoluteTimelockUnit::Timestamp
    };
    AbsoluteTimelock {
        unit,
        value: absolute.to_consensus_u32(),
    }
}

fn rounded_days(minutes: u64) -> u64 {
    (minutes + 720) / 1_440
}

fn liana_paths_to_dot(paths: &[LianaRecoveryPath]) -> String {
    let mut lines = vec![
        "digraph liana_recovery_tree {".to_owned(),
        "  graph [rankdir=TB];".to_owned(),
        "  node [shape=box, style=\"rounded\", fontname=\"monospace\"];".to_owned(),
        "  edge [fontname=\"monospace\"];".to_owned(),
        "  n0 [label=\"Liana recovery tree\"];".to_owned(),
    ];

    for (offset, path) in paths.iter().enumerate() {
        let node_id = offset + 1;
        let label = liana_path_label(path);
        lines.push(format!(
            "  n{node_id} [label=\"{}\"];",
            escape_dot_label(&label)
        ));
        lines.push(format!("  n0 -> n{node_id};"));
    }

    lines.push("}".to_owned());
    let mut dot = lines.join("\n");
    dot.push('\n');
    dot
}

fn liana_path_label(path: &LianaRecoveryPath) -> String {
    let key_line = match path.key_count {
        1 => "1 key".to_owned(),
        count => format!("{count} keys"),
    };
    format!(
        "{}\n{}\n{}",
        path.label,
        key_line,
        recovery_time_label(path)
    )
}

fn recovery_time_label(path: &LianaRecoveryPath) -> String {
    if let Some(lock) = path.relative_timelocks.first() {
        return match lock.unit {
            RelativeTimelockUnit::Blocks => format!(
                "after {} blocks (~{} days)",
                format_u32(lock.value),
                lock.estimated_days
            ),
            RelativeTimelockUnit::Time => format!(
                "after {} intervals (~{} days)",
                format_u32(lock.value),
                lock.estimated_days
            ),
        };
    }
    if let Some(lock) = path.absolute_timelocks.first() {
        return match lock.unit {
            AbsoluteTimelockUnit::Height => format!("after block {}", format_u32(lock.value)),
            AbsoluteTimelockUnit::Timestamp => {
                format!("after timestamp {}", format_u32(lock.value))
            }
        };
    }
    "available now".to_owned()
}

fn format_u32(value: u32) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[derive(Default)]
struct DotRenderer {
    next_node: usize,
    next_key: usize,
    lines: Vec<String>,
}

impl DotRenderer {
    fn render_graph<Pk: MiniscriptKey>(&mut self, policy: &Policy<Pk>) -> String {
        self.lines.push("digraph miniscript_policy {".to_owned());
        self.lines.push("  graph [rankdir=TB];".to_owned());
        self.lines
            .push("  node [shape=box, style=\"rounded\", fontname=\"monospace\"];".to_owned());
        self.lines
            .push("  edge [fontname=\"monospace\"];".to_owned());

        self.render_policy(policy);

        self.lines.push("}".to_owned());
        let mut dot = self.lines.join("\n");
        dot.push('\n');
        dot
    }

    fn render_policy<Pk: MiniscriptKey>(&mut self, policy: &Policy<Pk>) -> usize {
        let label = self.label_for(policy);
        let node_id = self.push_node(&label);

        if let Policy::Thresh(threshold) = policy {
            for child in threshold.data() {
                let child_id = self.render_policy(child.as_ref());
                self.lines.push(format!("  n{node_id} -> n{child_id};"));
            }
        }

        node_id
    }

    fn label_for<Pk: MiniscriptKey>(&mut self, policy: &Policy<Pk>) -> String {
        match policy {
            Policy::Unsatisfiable => "unsatisfiable".to_owned(),
            Policy::Trivial => "trivial".to_owned(),
            Policy::Key(_) => {
                self.next_key += 1;
                format!("key {}", self.next_key)
            }
            Policy::After(locktime) => format!("after({locktime})"),
            Policy::Older(locktime) => format!("older({locktime})"),
            Policy::Sha256(_) => "sha256".to_owned(),
            Policy::Hash256(_) => "hash256".to_owned(),
            Policy::Ripemd160(_) => "ripemd160".to_owned(),
            Policy::Hash160(_) => "hash160".to_owned(),
            Policy::Thresh(threshold) => {
                format!("thresh({} of {})", threshold.k(), threshold.n())
            }
        }
    }

    fn push_node(&mut self, label: &str) -> usize {
        let node_id = self.next_node;
        self.next_node += 1;
        self.lines.push(format!(
            "  n{node_id} [label=\"{}\"];",
            escape_dot_label(label)
        ));
        node_id
    }
}

fn escape_dot_label(label: &str) -> String {
    let mut escaped = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    const WPKH_VALID: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
    ));

    const WSH_2_OF_3: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt"
    ));

    const LIANA_BASIC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/timelock/liana_basic.txt"
    ));

    fn assert_valid_dot(dot: &str) {
        assert!(dot.starts_with("digraph miniscript_policy {\n"));
        assert!(dot.ends_with("}\n"));
        assert!(dot.contains("graph [rankdir=TB];"));
        assert!(dot.contains("node [shape=box"));
        assert!(
            !dot.contains("tpub") && !dot.contains("xpub"),
            "DOT output must not embed extended public keys"
        );
    }

    fn count_keys(dot: &str) -> usize {
        dot.matches("label=\"key ").count()
    }

    fn liana_after_descriptor(height: u32) -> String {
        let body = LIANA_BASIC
            .trim()
            .split('#')
            .next()
            .expect("fixture has a descriptor body");
        body.replace("older(65535)", &format!("after({height})"))
    }

    #[test]
    fn singlesig_descriptor_renders_key_policy_dot() {
        let dot = descriptor_to_dot(WPKH_VALID.trim()).expect("singlesig descriptor visualizes");

        assert_valid_dot(&dot);
        assert!(dot.contains("n0 [label=\"key 1\"];"));
        assert_eq!(count_keys(&dot), 1);
        assert!(!dot.contains("->"), "a singlesig key leaf has no edges");
    }

    #[test]
    fn multisig_descriptor_renders_threshold_policy_dot() {
        let dot = descriptor_to_dot(WSH_2_OF_3.trim()).expect("multisig descriptor visualizes");

        assert_valid_dot(&dot);
        assert!(dot.contains("n0 [label=\"thresh(2 of 3)\"];"));
        assert_eq!(count_keys(&dot), 3);
        assert!(dot.contains("n0 -> n1;"));
        assert!(dot.contains("n0 -> n2;"));
        assert!(dot.contains("n0 -> n3;"));
    }

    #[test]
    fn liana_timelock_descriptor_renders_recovery_policy_dot() {
        let dot = descriptor_to_dot(LIANA_BASIC.trim()).expect("timelock descriptor visualizes");

        assert_valid_dot(&dot);
        assert!(dot.contains("label=\"thresh(1 of 2)\""));
        assert!(dot.contains("label=\"thresh(2 of 2)\""));
        assert!(dot.contains("label=\"older(65535)\""));
        assert_eq!(count_keys(&dot), 2);
    }

    #[test]
    fn liana_recovery_tree_extracts_primary_and_timelocked_paths() {
        let tree = liana_recovery_tree(LIANA_BASIC.trim()).expect("Liana tree extracts");

        assert!(tree.dot.starts_with("digraph liana_recovery_tree {\n"));
        assert!(tree.dot.contains("label=\"Liana recovery tree\""));
        assert!(tree.dot.contains("Primary path\\n1 key\\navailable now"));
        assert!(tree
            .dot
            .contains("Recovery path 1\\n1 key\\nafter 65,535 blocks (~455 days)"));
        assert_eq!(tree.paths.len(), 2);

        let primary = &tree.paths[0];
        assert_eq!(primary.label, "Primary path");
        assert_eq!(primary.kind, LianaRecoveryPathKind::Primary);
        assert_eq!(primary.key_count, 1);
        assert!(primary.relative_timelocks.is_empty());
        assert_eq!(primary.countdown, None);

        let recovery = &tree.paths[1];
        assert_eq!(recovery.label, "Recovery path 1");
        assert_eq!(recovery.kind, LianaRecoveryPathKind::Recovery);
        assert_eq!(recovery.key_count, 1);
        assert_eq!(
            recovery.relative_timelocks,
            vec![RelativeTimelock {
                unit: RelativeTimelockUnit::Blocks,
                value: 65_535,
                estimated_minutes: 655_350,
                estimated_days: 455,
            }]
        );
        assert!(recovery.absolute_timelocks.is_empty());
        assert_eq!(recovery.countdown, None);
        assert!(!tree.dot.contains("tpub"));
    }

    #[test]
    fn liana_recovery_tree_adds_relative_countdown_from_current_block() {
        let tree =
            liana_recovery_tree_at_block(LIANA_BASIC.trim(), 840_000).expect("Liana tree extracts");

        let recovery = &tree.paths[1];
        assert_eq!(
            recovery.countdown,
            Some(LianaRecoveryCountdown {
                current_block_height: 840_000,
                active_in_blocks: 65_535,
                active_at_block: 905_535,
            })
        );
    }

    #[test]
    fn liana_recovery_tree_computes_absolute_height_delta_from_current_block() {
        let tree = liana_recovery_tree_at_block(&liana_after_descriptor(900_144), 900_000)
            .expect("absolute Liana tree extracts");

        let recovery = &tree.paths[1];
        assert_eq!(
            recovery.absolute_timelocks,
            vec![AbsoluteTimelock {
                unit: AbsoluteTimelockUnit::Height,
                value: 900_144,
            }]
        );
        assert_eq!(
            recovery.countdown,
            Some(LianaRecoveryCountdown {
                current_block_height: 900_000,
                active_in_blocks: 144,
                active_at_block: 900_144,
            })
        );
    }

    #[test]
    fn liana_recovery_tree_marks_elapsed_absolute_height_active_now() {
        let tree = liana_recovery_tree_at_block(&liana_after_descriptor(900_144), 900_200)
            .expect("absolute Liana tree extracts");

        assert_eq!(
            tree.paths[1].countdown,
            Some(LianaRecoveryCountdown {
                current_block_height: 900_200,
                active_in_blocks: 0,
                active_at_block: 900_200,
            })
        );
    }

    #[test]
    fn liana_recovery_tree_requires_a_timelocked_path() {
        let err = liana_recovery_tree(WSH_2_OF_3.trim()).unwrap_err();

        assert_eq!(err.code(), ErrorCode::ParseFailed);
    }

    #[test]
    fn dot_label_escaping_handles_graphviz_special_characters() {
        assert_eq!(
            escape_dot_label("a \"quoted\" \\ label\nnext"),
            "a \\\"quoted\\\" \\\\ label\\nnext"
        );
    }

    #[test]
    fn liana_path_number_formatting_uses_commas() {
        assert_eq!(format_u32(65_535), "65,535");
        assert_eq!(format_u32(100), "100");
        assert_eq!(format_u32(1_000_000), "1,000,000");
    }
}
