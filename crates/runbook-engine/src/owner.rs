//! Owner recovery runbook templates (US-032).
//!
//! Four printable **owner** runbooks — `singlesig-basic`,
//! `singlesig-passphrase`, `multisig-2of3`, `multisig-3of5` — each carrying the
//! sixteen §9.5 required sections with labeled blank fields, in the §17.7
//! `public-safe` (default) and `private` export modes.
//!
//! The content is built **once** here (the single source of truth) as a list of
//! [`RunbookSection`]s and rendered three ways:
//!
//! - [`render_markdown`] — the Markdown form (snapshot-tested);
//! - [`pdf_body_lines`] — the body for the pure-Rust printpdf fall-back
//!   (hash-tested for byte-determinism);
//! - [`sections_json`] — the `sections` data the bundled Typst templates in
//!   `templates/runbooks/*.typ` render.
//!
//! Every form is deterministic: all dates, the report hash, and the version are
//! caller-supplied ([`RunbookData`]).
//!
//! ## Safety — §9.5 forbidden content
//! The API has **no field** for a seed phrase, a passphrase value, a private
//! key, or a free-text storage location. A passphrase is recorded only as a
//! boolean "exists" ([`RunbookData::has_passphrase`]); storage locations are
//! always rendered as labeled blank fields the user fills in by hand. The
//! `public-safe` mode additionally hides the full descriptor (replaced by
//! [`DESCRIPTOR_REDACTED_PLACEHOLDER`]) and the hardware-wallet model.

use report_engine::{RedactionMode, DISCLAIMER_LONG, XPUB_PRIVACY_WARNING};

/// The §9.5 public-safe descriptor placeholder. Runbook-specific: the *report*
/// shows an xpub-redacted descriptor (§19.1), but a runbook hides the descriptor
/// text entirely in `public-safe` mode.
pub const DESCRIPTOR_REDACTED_PLACEHOLDER: &str = "[descriptor redacted, see private export]";

/// The underscore run rendered for a labeled blank field (§17.8
/// "Signer A location: __________________").
pub(crate) const BLANK_FIELD: &str = "______________________";

/// Which owner runbook to render. Each variant maps to a `templates/runbooks/`
/// `.typ` file by [`OwnerTemplate::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerTemplate {
    /// Single-signature wallet, no passphrase.
    SinglesigBasic,
    /// Single-signature wallet protected by a BIP39 passphrase.
    SinglesigPassphrase,
    /// 2-of-3 multisignature wallet.
    Multisig2of3,
    /// 3-of-5 multisignature wallet.
    Multisig3of5,
}

impl OwnerTemplate {
    /// All four owner templates, in a fixed order (test/iteration helper).
    pub const ALL: [OwnerTemplate; 4] = [
        OwnerTemplate::SinglesigBasic,
        OwnerTemplate::SinglesigPassphrase,
        OwnerTemplate::Multisig2of3,
        OwnerTemplate::Multisig3of5,
    ];

    /// The template's stable name — also the `templates/runbooks/<name>.typ`
    /// filename stem.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            OwnerTemplate::SinglesigBasic => "singlesig-basic",
            OwnerTemplate::SinglesigPassphrase => "singlesig-passphrase",
            OwnerTemplate::Multisig2of3 => "multisig-2of3",
            OwnerTemplate::Multisig3of5 => "multisig-3of5",
        }
    }

    /// The human-readable runbook title (also the PDF document title).
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            OwnerTemplate::SinglesigBasic => "Bitcoin Lifeboat - Singlesig Recovery Runbook",
            OwnerTemplate::SinglesigPassphrase => {
                "Bitcoin Lifeboat - Singlesig + Passphrase Recovery Runbook"
            }
            OwnerTemplate::Multisig2of3 => "Bitcoin Lifeboat - 2-of-3 Multisig Recovery Runbook",
            OwnerTemplate::Multisig3of5 => "Bitcoin Lifeboat - 3-of-5 Multisig Recovery Runbook",
        }
    }

    /// True for the multisig templates.
    #[must_use]
    pub fn is_multisig(self) -> bool {
        matches!(
            self,
            OwnerTemplate::Multisig2of3 | OwnerTemplate::Multisig3of5
        )
    }

    /// The expected `(M, N)` quorum for a multisig template; `None` for
    /// singlesig.
    #[must_use]
    pub fn quorum(self) -> Option<(u32, u32)> {
        match self {
            OwnerTemplate::Multisig2of3 => Some((2, 3)),
            OwnerTemplate::Multisig3of5 => Some((3, 5)),
            _ => None,
        }
    }
}

/// The §17.8 `wallet_summary`: script type, threshold, and key count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunbookWalletSummary {
    /// Script-type string, e.g. `"wpkh"`, `"wsh(sortedmulti)"`, `"tr"`.
    pub script_type: String,
    /// Multisig threshold *M*, or `None` for singlesig.
    pub threshold: Option<u32>,
    /// Number of keys *N* (1 for singlesig).
    pub key_count: u32,
}

impl RunbookWalletSummary {
    /// Construct a summary.
    #[must_use]
    pub fn new(script_type: impl Into<String>, threshold: Option<u32>, key_count: u32) -> Self {
        Self {
            script_type: script_type.into(),
            threshold,
            key_count,
        }
    }

    /// A human label like `"2-of-3 multisig"` or `"singlesig"`.
    #[must_use]
    pub fn wallet_type_label(&self) -> String {
        match self.threshold {
            Some(m) => format!("{m}-of-{} multisig", self.key_count),
            None => "singlesig".to_string(),
        }
    }
}

/// One signer in the §17.8 `signer_list` (a fingerprint + derivation path, plus
/// an optional hardware-wallet model shown only in `private` mode). Carries **no**
/// xpub and **no** location — locations are blank fields the user fills in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// A short label, e.g. `"Signer A"`.
    pub label: String,
    /// Master fingerprint (8 lowercase hex).
    pub fingerprint: String,
    /// Origin derivation path (`m/48h/0h/0h/2h` form).
    pub derivation_path: String,
    /// Hardware-wallet model — shown in `private` mode, hidden in `public-safe`
    /// (§9.5 item 15). `None` when unknown.
    pub device_model: Option<String>,
}

impl Signer {
    /// A signer with no device model.
    #[must_use]
    pub fn new(
        label: impl Into<String>,
        fingerprint: impl Into<String>,
        derivation_path: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            fingerprint: fingerprint.into(),
            derivation_path: derivation_path.into(),
            device_model: None,
        }
    }

    /// Set the hardware-wallet model (private mode only).
    #[must_use]
    pub fn with_device_model(mut self, model: impl Into<String>) -> Self {
        self.device_model = Some(model.into());
        self
    }
}

/// The §17.8 runbook template variables, all caller-supplied so rendering stays
/// deterministic (PRD §19/§27). There is intentionally no field for any secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunbookData {
    /// `{{wallet_summary}}`.
    pub wallet_summary: RunbookWalletSummary,
    /// `{{descriptor}}` — the full descriptor (rendered only in `private` mode).
    pub descriptor: String,
    /// `{{signer_list}}`.
    pub signers: Vec<Signer>,
    /// `{{drill_date}}` — last successful drill date, or `None` (blank field).
    pub drill_date: Option<String>,
    /// `{{next_drill}}` — recommended next drill date (drill_date + 12 months,
    /// computed by the caller).
    pub next_drill: String,
    /// `{{report_hash}}` — the accompanying report's hash.
    pub report_hash: String,
    /// `{{lifeboat_version}}`.
    pub lifeboat_version: String,
    /// Whether a passphrase exists (§9.5 §8 — existence only, never the value).
    pub has_passphrase: bool,
    /// Wallet-software dependency list (§9.5 §10); empty renders a blank field.
    pub wallet_software: Vec<String>,
}

impl RunbookData {
    /// A runbook data bag with the required fields; optionals default to empty.
    #[must_use]
    pub fn new(
        wallet_summary: RunbookWalletSummary,
        descriptor: impl Into<String>,
        next_drill: impl Into<String>,
        report_hash: impl Into<String>,
        lifeboat_version: impl Into<String>,
    ) -> Self {
        Self {
            wallet_summary,
            descriptor: descriptor.into(),
            signers: Vec::new(),
            drill_date: None,
            next_drill: next_drill.into(),
            report_hash: report_hash.into(),
            lifeboat_version: lifeboat_version.into(),
            has_passphrase: false,
            wallet_software: Vec::new(),
        }
    }

    /// Set the signer list.
    #[must_use]
    pub fn with_signers(mut self, signers: Vec<Signer>) -> Self {
        self.signers = signers;
        self
    }

    /// Set the last successful drill date.
    #[must_use]
    pub fn with_drill_date(mut self, drill_date: impl Into<String>) -> Self {
        self.drill_date = Some(drill_date.into());
        self
    }

    /// Record whether a passphrase exists.
    #[must_use]
    pub fn with_passphrase(mut self, has_passphrase: bool) -> Self {
        self.has_passphrase = has_passphrase;
        self
    }

    /// Set the wallet-software dependency list.
    #[must_use]
    pub fn with_wallet_software(mut self, wallet_software: Vec<String>) -> Self {
        self.wallet_software = wallet_software;
        self
    }
}

/// A single rendered block within a [`RunbookSection`]. The renderers map each
/// variant to the right Markdown / PDF / Typst form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A paragraph or labeled blank line.
    Para(String),
    /// A bullet-list item.
    Bullet(String),
    /// A checkbox item (a checklist entry).
    Check(String),
    /// A numbered step (ordered list).
    Step(String),
    /// Verbatim / preformatted text rendered inside a code fence — preserves
    /// exact bytes (the descriptor, the §15.6 disclaimer).
    Code(String),
}

impl Block {
    /// The block's serde `kind` tag (for the Typst `sections` data).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Block::Para(_) => "para",
            Block::Bullet(_) => "bullet",
            Block::Check(_) => "check",
            Block::Step(_) => "step",
            Block::Code(_) => "code",
        }
    }

    /// The block's text content.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Block::Para(s)
            | Block::Bullet(s)
            | Block::Check(s)
            | Block::Step(s)
            | Block::Code(s) => s,
        }
    }
}

/// One of the §9.5 runbook sections: a heading and its blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunbookSection {
    /// The section heading (without its number).
    pub heading: String,
    /// The section's content blocks, in render order.
    pub blocks: Vec<Block>,
}

impl RunbookSection {
    fn new(heading: impl Into<String>, blocks: Vec<Block>) -> Self {
        Self {
            heading: heading.into(),
            blocks,
        }
    }
}

/// Build the sixteen §9.5 sections for `template` from `data` at export `mode`.
///
/// The order is the §9.5 list (1..16). Mode affects only section 6 (the
/// descriptor: full vs placeholder) and section 7 (the device model: shown vs
/// hidden).
#[must_use]
pub fn build_sections(
    template: OwnerTemplate,
    data: &RunbookData,
    mode: RedactionMode,
) -> Vec<RunbookSection> {
    let mut sections = Vec::with_capacity(16);

    // 1. Safety warning.
    sections.push(RunbookSection::new(
        "Safety warning",
        vec![
            Block::Para(
                "Never type your seed words into a website, an app, or a search box.".into(),
            ),
            Block::Para(
                "Bitcoin Lifeboat never asks for your seed phrase. Anyone who does is trying to \
                 steal from you."
                    .into(),
            ),
            Block::Para(
                "This runbook holds no secrets. Keep your seed words on paper or metal only, \
                 never on a phone or computer."
                    .into(),
            ),
        ],
    ));

    // 2. Do not panic.
    sections.push(RunbookSection::new(
        "Do not panic",
        vec![
            Block::Para("If you are reading this during an emergency, slow down.".into()),
            Block::Para(
                "Recovering a Bitcoin wallet is a careful, step-by-step process. Most mistakes \
                 come from rushing."
                    .into(),
            ),
            Block::Para(
                "Take a break before each major step. Nothing in this runbook needs to be done in \
                 a hurry."
                    .into(),
            ),
        ],
    ));

    // 3. Stop and call a trusted helper.
    sections.push(RunbookSection::new(
        "Stop and call a trusted helper",
        vec![
            Block::Para(
                "If any step is unclear, stop and ask a person you trust before continuing.".into(),
            ),
            Block::Para(
                "Do not let anyone watch you type your seed words or photograph your backups."
                    .into(),
            ),
            Block::Para(
                "A trusted helper can be a family member, a friend, or a Bitcoin-literate advisor. \
                 Record who to call in section 9."
                    .into(),
            ),
        ],
    ));

    // 4. Required materials checklist.
    {
        let mut blocks = vec![
            Block::Check("This runbook, printed on paper.".into()),
            Block::Check("Your written or stamped descriptor backup.".into()),
        ];
        if template.is_multisig() {
            blocks.push(Block::Check(
                "Each cosigner device or seed backup listed in section 7.".into(),
            ));
        } else {
            blocks.push(Block::Check(
                "Your hardware wallet, or your seed backup.".into(),
            ));
        }
        if data.has_passphrase {
            blocks.push(Block::Check(
                "Your passphrase, from memory or from its separate backup (never stored with the \
                 seed)."
                    .into(),
            ));
        }
        blocks.push(Block::Check(
            "A computer with the wallet software listed in section 10.".into(),
        ));
        sections.push(RunbookSection::new("Required materials checklist", blocks));
    }

    // 5. Wallet type summary.
    {
        let ws = &data.wallet_summary;
        let mut blocks = vec![
            Block::Para(format!("Wallet type: {}.", ws.wallet_type_label())),
            Block::Bullet(format!("Script type: {}", ws.script_type)),
            Block::Bullet(format!("Number of keys: {}", ws.key_count)),
        ];
        if let Some(m) = ws.threshold {
            blocks.push(Block::Bullet(format!(
                "Signatures required: {m} of {}",
                ws.key_count
            )));
            let losable = ws.key_count.saturating_sub(m);
            blocks.push(Block::Para(format!(
                "To spend, you must sign with {m} of the {} keys. Losing more than {losable} of \
                 them means the funds cannot be moved.",
                ws.key_count
            )));
        }
        sections.push(RunbookSection::new("Wallet type summary", blocks));
    }

    // 6. Descriptor backup reminder.
    {
        let mut blocks = vec![
            Block::Para(
                "Your descriptor is the map to your wallet. Without it, recovery is much harder \
                 and sometimes impossible."
                    .into(),
            ),
            Block::Para(
                "Keep a written or stamped copy of the descriptor with each seed backup. It \
                 contains no secrets, but it reveals your balance history, so store it as \
                 privately as your seed."
                    .into(),
            ),
        ];
        match mode {
            RedactionMode::Private => {
                blocks.push(Block::Para("Descriptor (full):".into()));
                blocks.push(Block::Code(data.descriptor.clone()));
            }
            RedactionMode::PublicSafe => {
                blocks.push(Block::Para(format!(
                    "Descriptor: {DESCRIPTOR_REDACTED_PLACEHOLDER}"
                )));
            }
        }
        sections.push(RunbookSection::new("Descriptor backup reminder", blocks));
    }

    // 7. Signer and device checklist.
    {
        let mut blocks = Vec::new();
        if template.is_multisig() {
            blocks.push(Block::Para(
                "Each cosigner below must be reachable to meet the signing threshold. Confirm \
                 every device powers on and that you hold its seed backup."
                    .into(),
            ));
        } else {
            blocks.push(Block::Para(
                "Confirm your signing device powers on and that you hold its seed backup.".into(),
            ));
        }
        if data.signers.is_empty() {
            blocks.push(Block::Bullet(
                "Signer A: fingerprint ________, path ________".into(),
            ));
            blocks.push(Block::Para(format!("Signer A location: {BLANK_FIELD}")));
        } else {
            for s in &data.signers {
                let mut line = format!(
                    "{}: fingerprint {}, path {}",
                    s.label, s.fingerprint, s.derivation_path
                );
                if mode == RedactionMode::Private {
                    if let Some(model) = &s.device_model {
                        line.push_str(&format!(", device {model}"));
                    }
                }
                blocks.push(Block::Bullet(line));
                blocks.push(Block::Para(format!("{} location: {BLANK_FIELD}", s.label)));
            }
        }
        sections.push(RunbookSection::new("Signer and device checklist", blocks));
    }

    // 8. Passphrase reminder.
    {
        let blocks = if data.has_passphrase {
            vec![
                Block::Para(
                    "This wallet uses a passphrase (sometimes called a 25th word or BIP39 \
                     passphrase)."
                        .into(),
                ),
                Block::Para(
                    "The passphrase is NOT written in this runbook, and it never will be. You must \
                     remember it or keep it in a separate backup, stored apart from the seed words."
                        .into(),
                ),
                Block::Para(
                    "Without the exact passphrase - including capitalisation and spaces - the seed \
                     words alone will not reach this wallet."
                        .into(),
                ),
            ]
        } else {
            vec![
                Block::Para("No passphrase was recorded for this wallet.".into()),
                Block::Para(
                    "If you believe a passphrase was set, do not continue without it. A passphrase \
                     changes which wallet the seed words reach."
                        .into(),
                ),
            ]
        };
        sections.push(RunbookSection::new("Passphrase reminder", blocks));
    }

    // 9. Emergency contacts (blank fields).
    sections.push(RunbookSection::new(
        "Emergency contacts",
        vec![
            Block::Para(
                "Fill these in by hand. Do not store the contact details of strangers or \
                 so-called recovery services here."
                    .into(),
            ),
            Block::Para(format!("Trusted helper name: {BLANK_FIELD}")),
            Block::Para(format!("Trusted helper phone: {BLANK_FIELD}")),
            Block::Para(format!("Person who inherits this wallet: {BLANK_FIELD}")),
            Block::Para(format!("Attorney or executor: {BLANK_FIELD}")),
        ],
    ));

    // 10. Wallet software dependencies.
    {
        let mut blocks = vec![Block::Para(
            "Recovery may need specific wallet software. Record what this wallet depends on:"
                .into(),
        )];
        if data.wallet_software.is_empty() {
            blocks.push(Block::Para(format!(
                "Wallet software you use: {BLANK_FIELD}"
            )));
        } else {
            for sw in &data.wallet_software {
                blocks.push(Block::Bullet(sw.clone()));
            }
        }
        blocks.push(Block::Para(
            "If that software stops working, your descriptor and seed still allow recovery with \
             other BIP380-compatible wallet software."
                .into(),
        ));
        sections.push(RunbookSection::new("Wallet software dependencies", blocks));
    }

    // 11. Verification steps.
    {
        let mut blocks = vec![
            Block::Step(
                "Load this descriptor into your wallet software in WATCH-ONLY mode (no seed \
                 entered)."
                    .into(),
            ),
            Block::Step(
                "Confirm the first receive address shown matches an address you already have on \
                 record."
                    .into(),
            ),
            Block::Step(
                "On a test network (signet or testnet), rehearse signing and broadcasting a small \
                 transaction with your device."
                    .into(),
            ),
        ];
        if let Some((m, n)) = template.quorum() {
            blocks.push(Block::Step(format!(
                "Confirm you hold at least {m} of the {n} signing devices and can sign with each."
            )));
        }
        blocks.push(Block::Step(
            "Record today's date in section 13 once the drill succeeds.".into(),
        ));
        blocks.push(Block::Para(
            "Rehearse this drill at least once every twelve months.".into(),
        ));
        sections.push(RunbookSection::new("Verification steps", blocks));
    }

    // 12. Stop conditions.
    sections.push(RunbookSection::new(
        "Stop conditions",
        vec![
            Block::Para("Stop immediately and seek help if any of these happen:".into()),
            Block::Bullet("A website, app, or person asks you to type your seed words.".into()),
            Block::Bullet("A derived address does not match the address you expected.".into()),
            Block::Bullet(
                "Anyone pressures you to hurry, to share your screen, or to send a test payment."
                    .into(),
            ),
            Block::Bullet(
                "The wallet software shows a balance or history you do not recognise.".into(),
            ),
            Block::Para(
                "When in doubt, stop and call the trusted helper recorded in section 9.".into(),
            ),
        ],
    ));

    // 13. Date of last successful drill.
    {
        let line = match &data.drill_date {
            Some(d) => format!("Last successful drill: {d}"),
            None => format!("Last successful drill: {BLANK_FIELD} (none recorded yet)"),
        };
        sections.push(RunbookSection::new(
            "Date of last successful drill",
            vec![
                Block::Para(line),
                Block::Para(
                    "Write the date here each time you complete the verification steps above."
                        .into(),
                ),
            ],
        ));
    }

    // 14. Next recommended drill date.
    sections.push(RunbookSection::new(
        "Next recommended drill date",
        vec![
            Block::Para(format!("Next recommended drill: {}", data.next_drill)),
            Block::Para(
                "This is twelve months after the last successful drill. Sooner is better if your \
                 hardware or software has changed."
                    .into(),
            ),
        ],
    ));

    // 15. Lifeboat version and report hash.
    sections.push(RunbookSection::new(
        "Version and report hash",
        vec![
            Block::Bullet(format!(
                "Bitcoin Lifeboat version: {}",
                data.lifeboat_version
            )),
            Block::Bullet(format!("Report hash: {}", data.report_hash)),
            Block::Para(
                "These identify the exact report this runbook was generated from, so you can \
                 reproduce it."
                    .into(),
            ),
        ],
    ));

    // 16. Mandatory disclaimer (§15.6).
    sections.push(RunbookSection::new(
        "Disclaimer",
        vec![Block::Code(DISCLAIMER_LONG.to_string())],
    ));

    sections
}

/// The §14.3 xpub-privacy banner, shown at the top of a `private`-mode runbook
/// whose descriptor carries an extended public key. `None` otherwise (a
/// `public-safe` runbook hides the descriptor; a raw-pubkey descriptor reveals
/// no xpub).
#[must_use]
pub fn privacy_banner(data: &RunbookData, mode: RedactionMode) -> Option<&'static str> {
    if mode == RedactionMode::Private && descriptor_has_xpub(&data.descriptor) {
        Some(XPUB_PRIVACY_WARNING)
    } else {
        None
    }
}

/// True when `descriptor` contains an extended public key of any standard or
/// SLIP-132 flavour.
fn descriptor_has_xpub(descriptor: &str) -> bool {
    const PREFIXES: [&str; 10] = [
        "xpub", "ypub", "zpub", "tpub", "upub", "vpub", "Ypub", "Zpub", "Upub", "Vpub",
    ];
    PREFIXES.iter().any(|p| descriptor.contains(p))
}

/// Render the runbook as Markdown (§17.8 Markdown source). Deterministic: a pure
/// function of the already-deterministic [`build_sections`] output.
#[must_use]
pub fn render_markdown(template: OwnerTemplate, data: &RunbookData, mode: RedactionMode) -> String {
    let sections = build_sections(template, data, mode);
    let mut out = String::new();
    out.push_str("# ");
    out.push_str(template.title());
    out.push_str("\n\n");

    if let Some(banner) = privacy_banner(data, mode) {
        for line in banner.lines() {
            out.push_str("> ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }

    for (i, section) in sections.iter().enumerate() {
        out.push_str(&format!("## {}. {}\n\n", i + 1, section.heading));
        let mut step_no = 0u32;
        let rendered: Vec<String> = section
            .blocks
            .iter()
            .map(|b| match b {
                Block::Para(s) => s.clone(),
                Block::Bullet(s) => format!("- {s}"),
                Block::Check(s) => format!("- [ ] {s}"),
                Block::Step(s) => {
                    step_no += 1;
                    format!("{step_no}. {s}")
                }
                Block::Code(s) => format!("```\n{s}\n```"),
            })
            .collect();
        out.push_str(&rendered.join("\n\n"));
        out.push_str("\n\n");
    }

    let mut out = out.trim_end().to_string();
    out.push('\n');
    out
}

/// Flatten the runbook into printpdf body lines (the pure-Rust fall-back renders
/// `&[&str]`). Non-ASCII is folded because the base-14 fonts cannot encode it;
/// the Typst path renders full Unicode.
#[must_use]
pub(crate) fn pdf_body_lines(
    template: OwnerTemplate,
    data: &RunbookData,
    mode: RedactionMode,
) -> Vec<String> {
    let sections = build_sections(template, data, mode);
    let mut lines: Vec<String> = Vec::new();

    if let Some(banner) = privacy_banner(data, mode) {
        for line in ascii_fold(banner).lines() {
            lines.push(line.to_string());
        }
        lines.push(String::new());
    }

    for (i, section) in sections.iter().enumerate() {
        lines.push(format!("{}. {}", i + 1, section.heading));
        let mut step_no = 0u32;
        for b in &section.blocks {
            match b {
                Block::Para(s) => lines.push(ascii_fold(s)),
                Block::Bullet(s) => lines.push(format!("- {}", ascii_fold(s))),
                Block::Check(s) => lines.push(format!("[ ] {}", ascii_fold(s))),
                Block::Step(s) => {
                    step_no += 1;
                    lines.push(format!("{step_no}. {}", ascii_fold(s)));
                }
                Block::Code(s) => {
                    for cl in s.lines() {
                        lines.push(ascii_fold(cl));
                    }
                }
            }
        }
        lines.push(String::new());
    }

    lines
}

/// The `sections` array the Typst owner templates render. Each block carries its
/// `kind`, `text`, and (for steps) the running step number `n`.
#[must_use]
pub(crate) fn sections_json(
    template: OwnerTemplate,
    data: &RunbookData,
    mode: RedactionMode,
) -> serde_json::Value {
    let sections = build_sections(template, data, mode);
    let arr: Vec<serde_json::Value> = sections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut step_no = 0u32;
            let blocks: Vec<serde_json::Value> = s
                .blocks
                .iter()
                .map(|b| {
                    let n = if matches!(b, Block::Step(_)) {
                        step_no += 1;
                        step_no
                    } else {
                        0
                    };
                    serde_json::json!({ "kind": b.kind(), "text": b.text(), "n": n })
                })
                .collect();
            serde_json::json!({ "index": i + 1, "heading": s.heading, "blocks": blocks })
        })
        .collect();
    serde_json::Value::Array(arr)
}

/// Fold a string to ASCII for the base-14 printpdf fonts: the §14.3 banner's
/// leading ⚠️ emoji becomes an ASCII marker, the emoji variation selector is
/// dropped, and any other non-ASCII char becomes `?`. Deterministic.
pub(crate) fn ascii_fold(s: &str) -> String {
    s.replace('\u{26A0}', "WARNING:")
        .replace('\u{FE0F}', "")
        .chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use report_engine::passes_anti_overclaim_lint;

    // Fixed, ASCII, never-mainnet sample data (PRD §27). The runbook engine does
    // not parse these descriptors — it only displays them — so representative
    // fixed strings keep the snapshots deterministic.
    const SS_DESCRIPTOR: &str =
        "wpkh([f0f0f0f0/84h/1h/0h]tpubD6NzVbExampleSinglesigKey000000000000000000000000000000000000000000000000000000000000/0/*)#aaaaaaaa";
    const MS_DESCRIPTOR: &str =
        "wsh(sortedmulti(2,[a1a1a1a1/48h/1h/0h/2h]tpubD6NzVbExampleCosignerA00000000000000000000000000000000000000000000000000000000000/0/*,[b2b2b2b2/48h/1h/0h/2h]tpubD6NzVbExampleCosignerB00000000000000000000000000000000000000000000000000000000000/0/*,[c3c3c3c3/48h/1h/0h/2h]tpubD6NzVbExampleCosignerC00000000000000000000000000000000000000000000000000000000000/0/*))#bbbbbbbb";
    const SAMPLE_HASH: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn singlesig_data(has_passphrase: bool) -> RunbookData {
        RunbookData::new(
            RunbookWalletSummary::new("wpkh", None, 1),
            SS_DESCRIPTOR,
            "2027-05-01",
            SAMPLE_HASH,
            "0.1.0",
        )
        .with_signers(vec![
            Signer::new("Signer A", "f0f0f0f0", "m/84h/1h/0h").with_device_model("Coldcard Mk4")
        ])
        .with_drill_date("2026-05-01")
        .with_passphrase(has_passphrase)
        .with_wallet_software(vec!["Sparrow".to_string(), "Bitcoin Core".to_string()])
    }

    fn multisig_data(m: u32, n: u32) -> RunbookData {
        let models = [
            "Coldcard Mk4",
            "Ledger Nano",
            "Trezor Model T",
            "BitBox02",
            "Jade",
        ];
        let signers: Vec<Signer> = (0..n)
            .map(|i| {
                let label = format!("Signer {}", (b'A' + i as u8) as char);
                let fp = format!("{:02x}{:02x}{:02x}{:02x}", i + 1, i + 1, i + 1, i + 1);
                Signer::new(label, fp, "m/48h/1h/0h/2h")
                    .with_device_model(models[i as usize % models.len()])
            })
            .collect();
        RunbookData::new(
            RunbookWalletSummary::new("wsh(sortedmulti)", Some(m), n),
            MS_DESCRIPTOR,
            "2027-05-01",
            SAMPLE_HASH,
            "0.1.0",
        )
        .with_signers(signers)
        .with_drill_date("2026-05-01")
        .with_wallet_software(vec!["Sparrow".to_string()])
    }

    fn data_for(template: OwnerTemplate) -> RunbookData {
        match template {
            OwnerTemplate::SinglesigBasic => singlesig_data(false),
            OwnerTemplate::SinglesigPassphrase => singlesig_data(true),
            OwnerTemplate::Multisig2of3 => multisig_data(2, 3),
            OwnerTemplate::Multisig3of5 => multisig_data(3, 5),
        }
    }

    fn mode_label(mode: RedactionMode) -> &'static str {
        match mode {
            RedactionMode::PublicSafe => "public_safe",
            RedactionMode::Private => "private",
        }
    }

    #[test]
    fn every_template_has_the_sixteen_required_sections() {
        for template in OwnerTemplate::ALL {
            let data = data_for(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let sections = build_sections(template, &data, mode);
                assert_eq!(
                    sections.len(),
                    16,
                    "{} ({:?}) must have all 16 §9.5 sections",
                    template.name(),
                    mode
                );
                // Headings are non-empty and each section has at least one block.
                for s in &sections {
                    assert!(!s.heading.trim().is_empty());
                    assert!(!s.blocks.is_empty());
                }
            }
        }
    }

    #[test]
    fn public_safe_hides_the_descriptor_private_shows_it() {
        let template = OwnerTemplate::SinglesigBasic;
        let data = singlesig_data(false);

        let public = render_markdown(template, &data, RedactionMode::PublicSafe);
        assert!(public.contains(DESCRIPTOR_REDACTED_PLACEHOLDER));
        assert!(
            !public.contains(SS_DESCRIPTOR),
            "the full descriptor must never appear in a public-safe runbook"
        );

        let private = render_markdown(template, &data, RedactionMode::Private);
        assert!(private.contains(SS_DESCRIPTOR));
        assert!(!private.contains(DESCRIPTOR_REDACTED_PLACEHOLDER));
    }

    #[test]
    fn hardware_model_shown_only_in_private_mode() {
        let template = OwnerTemplate::Multisig2of3;
        let data = multisig_data(2, 3);

        let private = render_markdown(template, &data, RedactionMode::Private);
        assert!(private.contains("Coldcard Mk4"), "model shown in private");

        let public = render_markdown(template, &data, RedactionMode::PublicSafe);
        assert!(
            !public.contains("Coldcard Mk4"),
            "§9.5 item 15: the hardware-wallet model is redacted in public-safe"
        );
        // Fingerprints and paths stay in both modes (they are not xpubs).
        assert!(public.contains("fingerprint 01010101"));
        assert!(public.contains("m/48h/1h/0h/2h"));
    }

    #[test]
    fn privacy_banner_appears_only_in_private_mode_with_an_xpub() {
        let template = OwnerTemplate::SinglesigBasic;
        let data = singlesig_data(false);

        let private = render_markdown(template, &data, RedactionMode::Private);
        assert!(
            private.contains("extended public key (xpub)"),
            "§14.3 banner present in private mode when the descriptor reveals an xpub"
        );

        let public = render_markdown(template, &data, RedactionMode::PublicSafe);
        assert!(!public.contains("extended public key (xpub)"));

        // A raw-pubkey descriptor reveals no xpub → no banner even in private.
        let raw = RunbookData::new(
            RunbookWalletSummary::new("wpkh", None, 1),
            "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#xxxxxxxx",
            "2027-05-01",
            SAMPLE_HASH,
            "0.1.0",
        );
        let raw_private = render_markdown(template, &raw, RedactionMode::Private);
        assert!(!raw_private.contains("extended public key (xpub)"));
    }

    #[test]
    fn passphrase_section_notes_existence_but_carries_no_value() {
        let with = render_markdown(
            OwnerTemplate::SinglesigPassphrase,
            &singlesig_data(true),
            RedactionMode::Private,
        );
        assert!(with.contains("This wallet uses a passphrase"));
        assert!(with.contains("is NOT written in this runbook"));

        let without = render_markdown(
            OwnerTemplate::SinglesigBasic,
            &singlesig_data(false),
            RedactionMode::Private,
        );
        assert!(without.contains("No passphrase was recorded"));
    }

    #[test]
    fn forbidden_content_is_never_emitted() {
        // The API exposes no field for a seed, a passphrase value, a private key,
        // or a free-text location — locations are always labeled blank fields.
        for template in OwnerTemplate::ALL {
            let data = data_for(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = render_markdown(template, &data, mode);
                // Every "location:" line is an unfilled blank field.
                for line in md.lines() {
                    if line.contains("location:") {
                        assert!(
                            line.contains(BLANK_FIELD),
                            "location lines must be blank fields, got: {line}"
                        );
                    }
                }
                // The public-safe export never leaks the descriptor.
                if mode == RedactionMode::PublicSafe {
                    assert!(!md.contains(SS_DESCRIPTOR));
                    assert!(!md.contains(MS_DESCRIPTOR));
                }
            }
        }
    }

    #[test]
    fn no_rendered_form_overclaims() {
        for template in OwnerTemplate::ALL {
            let data = data_for(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = render_markdown(template, &data, mode);
                assert!(
                    passes_anti_overclaim_lint(&md),
                    "{} ({:?}) Markdown must pass the §16.8 lint",
                    template.name(),
                    mode
                );
                // Also lint each heading and block individually.
                for s in build_sections(template, &data, mode) {
                    assert!(passes_anti_overclaim_lint(&s.heading));
                    for b in &s.blocks {
                        assert!(
                            passes_anti_overclaim_lint(b.text()),
                            "block overclaims: {}",
                            b.text()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn markdown_is_deterministic() {
        for template in OwnerTemplate::ALL {
            let data = data_for(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let a = render_markdown(template, &data, mode);
                let b = render_markdown(template, &data, mode);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn multisig_summary_reflects_the_quorum() {
        let md = render_markdown(
            OwnerTemplate::Multisig3of5,
            &multisig_data(3, 5),
            RedactionMode::PublicSafe,
        );
        assert!(md.contains("3-of-5 multisig"));
        assert!(md.contains("Signatures required: 3 of 5"));
        assert!(md.contains("at least 3 of the 5 signing devices"));
    }

    #[test]
    fn owner_markdown_snapshots() {
        // One Markdown snapshot per template × export mode (PRD §17.8 Markdown
        // source). Regenerate with `INSTA_UPDATE=always cargo +1.78.0 test -p
        // runbook-engine` then commit the .snap files.
        for template in OwnerTemplate::ALL {
            let data = data_for(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let name = format!(
                    "owner_md__{}__{}",
                    template.name().replace('-', "_"),
                    mode_label(mode)
                );
                insta::assert_snapshot!(name, render_markdown(template, &data, mode));
            }
        }
    }
}
