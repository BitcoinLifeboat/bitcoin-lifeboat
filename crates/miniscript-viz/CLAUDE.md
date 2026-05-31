# miniscript-viz - notes for future iterations

Renders descriptor spending policies as GraphViz DOT for the v0.5 Liana /
Miniscript UI.

## Policy rendering
- Parse raw descriptors through `descriptor-audit::parse_descriptor`; do not add a
  parallel parser here.
- `descriptor_policy_to_dot` must use rust-miniscript's `Liftable::lift()` and
  render the semantic `policy::semantic::Policy`, not frontend-parsed descriptor
  strings.
- DOT labels intentionally redact wallet metadata. Key leaves are `key 1`,
  `key 2`, etc.; do not print xpubs, descriptors, fingerprints, or addresses in
  the graph.
- The root workspace gate includes this crate under Rust 1.78. Keep it GUI-free:
  no Tauri, GraphViz binary dependency, or frontend QR/canvas library belongs
  here.

## Liana recovery paths (since US-091)
- `liana_recovery_tree` is the Rust-owned extraction surface for Liana/timelock
  path visualization. It lifts the descriptor to semantic `Policy`, treats a
  top-level `thresh(1 of N)` as alternative spend paths, and labels any path with
  `older`/`after` as recovery.
- The returned `LianaRecoveryTree` is public-safe: DOT labels and path metadata
  may include path labels, key counts, and timelock values/estimates, but never
  descriptors, xpubs, fingerprints, addresses, or pubkeys.
- Relative `older` block locks use the UI estimate `blocks * 10 minutes`, rounded
  to whole days.
- Current-block countdowns (US-092) are still computed here, not in React. The
  caller supplies the current block height; this crate never performs chain-state
  or network lookup. Block-based `older(N)` reports `active_in_blocks = N` and
  `active_at_block = current + N`; absolute `after(height)` reports
  `height.saturating_sub(current)` and is active now when the delta is zero.
  Time-based `older` and timestamp `after` values remain estimates/labels, not
  block countdowns.
