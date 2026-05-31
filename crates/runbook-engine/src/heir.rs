//! Heir, workshop, and business recovery runbook templates (US-033).
//!
//! Seven printable runbooks built on the same one-source-three-renderers design as
//! [`crate::owner`]:
//!
//! - the base **heir** runbooks (`heir-singlesig-basic`,
//!   `heir-singlesig-passphrase`, `heir-multisig-2of3`, `heir-multisig-3of5`) —
//!   written in plain English (US 8th-grade reading level, PRD §9.4), opening
//!   with the verbatim §15.6 [`DISCLAIMER_HEIR`] and an inline glossary so an
//!   heir never meets bare `xpub`/`PSBT` jargon;
//! - the **Liana timelock** inheritance runbook (`liana-timelock`), covering the
//!   primary and timelocked recovery paths;
//! - the **meetup workshop** kit (`meetup-workshop`, a 15-attendee hands-on
//!   class) and the **business treasury** runbook (`business-treasury`,
//!   corporate self-custody).
//!
//! Each renders the sixteen §9.5 required sections (including the verbatim
//! "Stop and call a trusted helper" section) with labeled blank fields, in the
//! §17.7 `public-safe` (default) and `private` export modes.
//!
//! Like [`crate::owner`], the content is built **once** as [`RunbookSection`]s
//! and rendered three ways ([`render_markdown`], [`pdf_body_lines`],
//! [`sections_json`]); every form is deterministic (all variable data is
//! caller-supplied via [`RunbookData`]).
//!
//! ## Safety — §9.5 forbidden content
//! As with the owner runbooks, there is **no field** for a seed phrase, a
//! passphrase value, a private key, or a free-text storage location. The heir
//! disclaimer and the long §15.6 disclaimer are fixed, verbatim strings; all
//! other heir-facing copy avoids bare jargon and never claims a wallet is recoverable.

use crate::owner::{ascii_fold, privacy_banner, Block, RunbookData, RunbookSection, BLANK_FIELD};
use report_engine::{RedactionMode, DISCLAIMER_LONG};

/// The PRD §15.6 heir runbook disclaimer, verbatim — shown on the first page of
/// every heir runbook. Written flush-left (a leading `\` swallows the opening
/// newline) so the two-space bullet indentation is preserved byte-for-byte; this
/// is the same style `report_engine::REPORT_CANNOT_TELL` uses. Owned here because
/// only runbooks (never reports) render it.
pub const DISCLAIMER_HEIR: &str = "\
You are reading a recovery plan written by someone who trusts you
to help. This document does not contain bitcoin. It does not contain
secret recovery words. It only contains instructions.

You will not be able to recover anything using only this document.
You will also need:
  - The wallet's hardware device(s) or backup card(s)
  - Any secret words the owner wrote down separately (if they did)
  - Patience: never let anyone rush you

If anyone tells you they can help you \"decrypt\" or \"unlock\" this
plan for a fee, hang up. They cannot. They are a scammer.

If you get stuck, stop. Take your time. Find a trusted person who
understands Bitcoin and ask for help. The owner has likely listed
a trusted helper on this page.";

/// Which heir/workshop/business runbook to render. Each variant maps to a
/// `templates/runbooks/` `.typ` file by [`HeirTemplate::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeirTemplate {
    /// Heir runbook for a single-signature wallet, no passphrase.
    HeirSinglesigBasic,
    /// Heir runbook for a single-signature wallet protected by a passphrase.
    HeirSinglesigPassphrase,
    /// Heir runbook for a 2-of-3 multisignature wallet.
    HeirMultisig2of3,
    /// Heir runbook for a 3-of-5 multisignature wallet.
    HeirMultisig3of5,
    /// Liana-style inheritance wallet with a primary path and timelocked
    /// recovery path.
    LianaTimelock,
    /// 15-attendee hands-on self-custody workshop kit (educator-facing).
    MeetupWorkshop,
    /// Corporate self-custody treasury runbook (business-facing).
    BusinessTreasury,
}

impl HeirTemplate {
    /// All seven templates, in a fixed order (test/iteration helper).
    pub const ALL: [HeirTemplate; 7] = [
        HeirTemplate::HeirSinglesigBasic,
        HeirTemplate::HeirSinglesigPassphrase,
        HeirTemplate::HeirMultisig2of3,
        HeirTemplate::HeirMultisig3of5,
        HeirTemplate::LianaTimelock,
        HeirTemplate::MeetupWorkshop,
        HeirTemplate::BusinessTreasury,
    ];

    /// The template's stable name — also the `templates/runbooks/<name>.typ`
    /// filename stem.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            HeirTemplate::HeirSinglesigBasic => "heir-singlesig-basic",
            HeirTemplate::HeirSinglesigPassphrase => "heir-singlesig-passphrase",
            HeirTemplate::HeirMultisig2of3 => "heir-multisig-2of3",
            HeirTemplate::HeirMultisig3of5 => "heir-multisig-3of5",
            HeirTemplate::LianaTimelock => "liana-timelock",
            HeirTemplate::MeetupWorkshop => "meetup-workshop",
            HeirTemplate::BusinessTreasury => "business-treasury",
        }
    }

    /// The human-readable runbook title (also the PDF document title).
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            HeirTemplate::HeirSinglesigBasic => "Bitcoin Lifeboat - Heir Recovery Plan (Singlesig)",
            HeirTemplate::HeirSinglesigPassphrase => {
                "Bitcoin Lifeboat - Heir Recovery Plan (Singlesig + Passphrase)"
            }
            HeirTemplate::HeirMultisig2of3 => "Bitcoin Lifeboat - Heir Recovery Plan (2-of-3)",
            HeirTemplate::HeirMultisig3of5 => "Bitcoin Lifeboat - Heir Recovery Plan (3-of-5)",
            HeirTemplate::LianaTimelock => "Bitcoin Lifeboat - Heir Recovery Plan (Liana Timelock)",
            HeirTemplate::MeetupWorkshop => "Bitcoin Lifeboat - Meetup Workshop Kit",
            HeirTemplate::BusinessTreasury => "Bitcoin Lifeboat - Business Treasury Runbook",
        }
    }

    /// The one-line subtitle the `.typ` template prints under the title.
    #[must_use]
    pub fn subtitle(self) -> &'static str {
        match self {
            HeirTemplate::HeirSinglesigBasic | HeirTemplate::HeirSinglesigPassphrase => {
                "A plain-language plan for recovering a single-device wallet."
            }
            HeirTemplate::HeirMultisig2of3 | HeirTemplate::HeirMultisig3of5 => {
                "A plain-language plan for recovering a wallet that needs several devices."
            }
            HeirTemplate::LianaTimelock => {
                "A plain-language plan for a Liana wallet with a timelocked recovery path."
            }
            HeirTemplate::MeetupWorkshop => {
                "A hands-on self-custody class for up to fifteen people."
            }
            HeirTemplate::BusinessTreasury => {
                "A recovery plan for a business that holds its own bitcoin."
            }
        }
    }

    /// True for the heir-facing runbooks (these open with [`DISCLAIMER_HEIR`]
    /// and a glossary, and are written at an 8th-grade reading level).
    #[must_use]
    pub fn is_heir(self) -> bool {
        matches!(
            self,
            HeirTemplate::HeirSinglesigBasic
                | HeirTemplate::HeirSinglesigPassphrase
                | HeirTemplate::HeirMultisig2of3
                | HeirTemplate::HeirMultisig3of5
                | HeirTemplate::LianaTimelock
        )
    }

    /// True for the multisig heir templates.
    #[must_use]
    pub fn is_multisig(self) -> bool {
        matches!(
            self,
            HeirTemplate::HeirMultisig2of3 | HeirTemplate::HeirMultisig3of5
        )
    }

    /// True for the Liana/timelock inheritance template.
    #[must_use]
    pub fn is_liana_timelock(self) -> bool {
        self == HeirTemplate::LianaTimelock
    }

    /// The expected `(M, N)` quorum for a multisig heir template; `None`
    /// otherwise.
    #[must_use]
    pub fn quorum(self) -> Option<(u32, u32)> {
        match self {
            HeirTemplate::HeirMultisig2of3 => Some((2, 3)),
            HeirTemplate::HeirMultisig3of5 => Some((3, 5)),
            _ => None,
        }
    }
}

/// The verbatim §15.6 heir disclaimer for the heir templates; `None` for the
/// workshop and business runbooks (which are not heir-facing and carry only the
/// long §15.6 disclaimer in their final section).
#[must_use]
pub fn heir_disclaimer(template: HeirTemplate) -> Option<&'static str> {
    template.is_heir().then_some(DISCLAIMER_HEIR)
}

/// The inline glossary (PRD §9.4: "Glossary inline") shown after the disclaimer
/// on every heir runbook. Each entry expands a term so an heir never meets bare
/// jargon. Empty for the workshop and business runbooks.
#[must_use]
pub fn glossary(template: HeirTemplate) -> Vec<String> {
    if !template.is_heir() {
        return Vec::new();
    }
    let mut entries = vec![
        "Recovery words: the list of words (usually 12 or 24) the owner wrote \
         down by hand. Sometimes called a seed phrase. They are the real key to \
         the money. Never type them into a website."
            .to_string(),
        "Hardware device: a small gadget that holds the recovery words offline \
         and approves payments. Sometimes called a hardware wallet or a signing \
         device."
            .to_string(),
        "Recovery details: a long line of text (often starting with letters like \
         \"wpkh\" or \"wsh\", and known to experts as a descriptor) that tells \
         wallet software how to find this wallet. It is not a secret key, but \
         keep it private."
            .to_string(),
        "Wallet software: a free app (for example Sparrow or Bitcoin Core) that \
         shows the wallet and helps approve a payment."
            .to_string(),
    ];
    if template.is_multisig() {
        entries.push(
            "Several-key wallet: a wallet that needs more than one device to \
             approve a payment (experts call this multisig). You will need \
             several of the devices listed in this plan."
                .to_string(),
        );
    }
    if template == HeirTemplate::HeirSinglesigPassphrase {
        entries.push(
            "Extra word (passphrase): a secret word or phrase, separate from the \
             recovery words, that some owners add. Without the exact extra word, \
             the recovery words alone reach a different, empty wallet."
                .to_string(),
        );
    }
    if template.is_liana_timelock() {
        entries.push(
            "Timelock: a waiting period measured in Bitcoin blocks or time. The \
             recovery path should be tried only after the wallet software says the \
             waiting period has passed."
                .to_string(),
        );
        entries.push(
            "Primary path and recovery path: the primary path is the owner's normal \
             way to spend. The recovery path is the backup route for the heir after \
             the timelock."
                .to_string(),
        );
    }
    entries
}

/// Build the sixteen §9.5 sections for `template` from `data` at export `mode`.
#[must_use]
pub fn build_sections(
    template: HeirTemplate,
    data: &RunbookData,
    mode: RedactionMode,
) -> Vec<RunbookSection> {
    match template {
        HeirTemplate::LianaTimelock => build_liana_sections(data, mode),
        HeirTemplate::MeetupWorkshop => build_workshop_sections(data, mode),
        HeirTemplate::BusinessTreasury => build_business_sections(data, mode),
        _ => build_heir_sections(template, data, mode),
    }
}

/// Convenience constructor for a section (the owner module's `new` is private).
fn section(heading: &str, blocks: Vec<Block>) -> RunbookSection {
    RunbookSection {
        heading: heading.to_string(),
        blocks,
    }
}

/// The §9.5 section 6 descriptor block, shared by every template: the full
/// descriptor in `private` mode, the redacted placeholder in `public-safe`.
fn descriptor_blocks(data: &RunbookData, mode: RedactionMode, lead: Vec<Block>) -> Vec<Block> {
    let mut blocks = lead;
    match mode {
        RedactionMode::Private => {
            blocks.push(Block::Para("Recovery details (full):".into()));
            blocks.push(Block::Code(data.descriptor.clone()));
        }
        RedactionMode::PublicSafe => {
            blocks.push(Block::Para(format!(
                "Recovery details: {}",
                crate::owner::DESCRIPTOR_REDACTED_PLACEHOLDER
            )));
        }
    }
    blocks
}

/// The base heir runbooks (singlesig / +passphrase / 2-of-3 / 3-of-5).
fn build_heir_sections(
    template: HeirTemplate,
    data: &RunbookData,
    mode: RedactionMode,
) -> Vec<RunbookSection> {
    let multisig = template.is_multisig();
    let has_passphrase = template == HeirTemplate::HeirSinglesigPassphrase || data.has_passphrase;
    let mut sections = Vec::with_capacity(16);

    // 1. Safety warning.
    sections.push(section(
        "Safety warning",
        vec![
            Block::Para(
                "Never type the recovery words into a website, an app, or a search box.".into(),
            ),
            Block::Para(
                "Bitcoin Lifeboat will never call you, message you, or ask for the recovery \
                 words. Anyone who does is trying to steal the money."
                    .into(),
            ),
            Block::Para(
                "This document holds no secrets. The recovery words stay on paper or metal, \
                 never on a phone or computer."
                    .into(),
            ),
        ],
    ));

    // 2. Do not panic.
    sections.push(section(
        "Do not panic",
        vec![
            Block::Para("If you are reading this during a hard time, slow down.".into()),
            Block::Para(
                "Recovering a wallet is a careful, step-by-step job. Most mistakes come from \
                 rushing. There is no deadline here."
                    .into(),
            ),
            Block::Para(
                "Take a break before each big step. You can do this one piece at a time.".into(),
            ),
        ],
    ));

    // 3. Stop and call a trusted helper.
    sections.push(section(
        "Stop and call a trusted helper",
        vec![
            Block::Para(
                "If any step is confusing, stop and ask a person you trust before you go on."
                    .into(),
            ),
            Block::Para(
                "A trusted helper can be a family member, a friend, or an advisor who knows \
                 Bitcoin. The owner may have written one below."
                    .into(),
            ),
            Block::Para(format!("Trusted helper to call: {BLANK_FIELD}")),
            Block::Para(
                "Never let anyone watch you handle the recovery words, and never let anyone \
                 take a photo of them."
                    .into(),
            ),
        ],
    ));

    // 4. Required materials checklist.
    {
        let mut blocks = vec![
            Block::Check("This plan, printed on paper.".into()),
            Block::Check("The written or stamped copy of the recovery details.".into()),
        ];
        if multisig {
            blocks.push(Block::Check(
                "Several of the devices or backups listed in section 7.".into(),
            ));
        } else {
            blocks.push(Block::Check(
                "The hardware device, or the paper or metal backup of the recovery words.".into(),
            ));
        }
        if has_passphrase {
            blocks.push(Block::Check(
                "The extra word (passphrase), if the owner kept one. It is stored apart from \
                 the recovery words."
                    .into(),
            ));
        }
        blocks.push(Block::Check(
            "A computer with the wallet software listed in section 10.".into(),
        ));
        sections.push(section("What you will need", blocks));
    }

    // 5. Wallet type summary.
    {
        let mut blocks = vec![Block::Para(
            "This page explains what kind of wallet you are recovering.".into(),
        )];
        if let Some((m, n)) = template.quorum() {
            blocks.push(Block::Bullet(format!(
                "This wallet needs {m} of {n} devices to approve a payment."
            )));
            blocks.push(Block::Para(format!(
                "You must gather at least {m} of the {n} devices. If you can find {m}, you can \
                 try to move the money. If too many are lost, the money cannot be moved."
            )));
        } else {
            blocks.push(Block::Bullet(
                "This wallet needs one device (or the recovery words) to approve a payment.".into(),
            ));
            blocks.push(Block::Para(
                "You need the one hardware device, or the recovery words written down.".into(),
            ));
        }
        sections.push(section("What kind of wallet this is", blocks));
    }

    // 6. Descriptor backup reminder.
    let lead = vec![
        Block::Para(
            "The recovery details are like a map to the wallet. Without them, recovery is much \
             harder and can be impossible."
                .into(),
        ),
        Block::Para(
            "Keep a written or stamped copy with each backup. The recovery details hold no \
             secret words, but they reveal the wallet's history, so keep them private."
                .into(),
        ),
    ];
    sections.push(section(
        "The wallet's recovery details",
        descriptor_blocks(data, mode, lead),
    ));

    // 7. Signer/device checklist.
    {
        let mut blocks = Vec::new();
        if multisig {
            blocks.push(Block::Para(
                "Each device below helps approve a payment. You need enough of them to meet the \
                 number in section 5. Check that each one powers on."
                    .into(),
            ));
        } else {
            blocks.push(Block::Para(
                "Check that the device below powers on, and that you hold its backup.".into(),
            ));
        }
        if data.signers.is_empty() {
            blocks.push(Block::Bullet("Device A: short code ________".into()));
            blocks.push(Block::Para(format!("Device A is kept at: {BLANK_FIELD}")));
        } else {
            for s in &data.signers {
                let mut line = format!("{}: short code {}", s.label, s.fingerprint);
                if mode == RedactionMode::Private {
                    if let Some(model) = &s.device_model {
                        line.push_str(&format!(", device {model}"));
                    }
                }
                blocks.push(Block::Bullet(line));
                blocks.push(Block::Para(format!(
                    "{} is kept at: {BLANK_FIELD}",
                    s.label
                )));
            }
        }
        sections.push(section("The devices and backups you need", blocks));
    }

    // 8. Passphrase existence reminder.
    {
        let blocks = if has_passphrase {
            vec![
                Block::Para(
                    "This wallet uses an extra word, also called a passphrase. It is separate \
                     from the recovery words."
                        .into(),
                ),
                Block::Para(
                    "The extra word is NOT written here, and it never will be. You must find it \
                     where the owner kept it, apart from the recovery words."
                        .into(),
                ),
                Block::Para(
                    "Without the exact extra word, including capital letters and spaces, the \
                     recovery words reach a different, empty wallet."
                        .into(),
                ),
            ]
        } else {
            vec![
                Block::Para(
                    "The owner did not record an extra word (passphrase) for this wallet.".into(),
                ),
                Block::Para(
                    "If you think there is one, stop. Do not go on without it. An extra word \
                     changes which wallet the recovery words reach."
                        .into(),
                ),
            ]
        };
        sections.push(section("Is there an extra word (passphrase)?", blocks));
    }

    // 9. Emergency contacts (blank fields).
    sections.push(section(
        "People to contact",
        vec![
            Block::Para(
                "Fill these in by hand. Do not write the details of strangers or so-called \
                 recovery services here."
                    .into(),
            ),
            Block::Para(format!("Trusted helper name: {BLANK_FIELD}")),
            Block::Para(format!("Trusted helper phone: {BLANK_FIELD}")),
            Block::Para(format!("Lawyer or executor: {BLANK_FIELD}")),
        ],
    ));

    // 10. Wallet software dependency list.
    {
        let mut blocks = vec![Block::Para(
            "You will need a free app on a computer to see the wallet and approve a payment."
                .into(),
        )];
        if data.wallet_software.is_empty() {
            blocks.push(Block::Para(format!("App to use: {BLANK_FIELD}")));
        } else {
            for sw in &data.wallet_software {
                blocks.push(Block::Bullet(sw.clone()));
            }
        }
        blocks.push(Block::Para(
            "If that app stops working, the recovery details and recovery words still work with \
             other Bitcoin apps that follow the same standard."
                .into(),
        ));
        sections.push(section("The app you will need", blocks));
    }

    // 11. Verification steps.
    {
        let mut blocks = vec![
            Block::Step(
                "Open the wallet app and load the recovery details in WATCH-ONLY mode. Do not \
                 type any recovery words yet."
                    .into(),
            ),
            Block::Step(
                "Check that the first address shown matches an address the owner left on record."
                    .into(),
            ),
        ];
        if let Some((m, n)) = template.quorum() {
            blocks.push(Block::Step(format!(
                "Gather at least {m} of the {n} devices and check you can approve a test payment \
                 with each."
            )));
        } else {
            blocks.push(Block::Step(
                "Practice approving a test payment on a test network with the device.".into(),
            ));
        }
        blocks.push(Block::Step(
            "Write today's date in section 13 once the practice run works.".into(),
        ));
        sections.push(section("How to check the plan works", blocks));
    }

    // 12. Stop conditions.
    sections.push(section(
        "When to stop right away",
        vec![
            Block::Para("Stop and get help if any of these happen:".into()),
            Block::Bullet("A website, app, or person asks you to type the recovery words.".into()),
            Block::Bullet("An address does not match the one the owner left.".into()),
            Block::Bullet(
                "Anyone pushes you to hurry, to share your screen, or to pay a fee.".into(),
            ),
            Block::Bullet("The app shows an amount or history you do not expect.".into()),
            Block::Para("When in doubt, stop and call the trusted helper in section 9.".into()),
        ],
    ));

    // 13. Date of last successful drill.
    {
        let line = match &data.drill_date {
            Some(d) => format!("Last successful practice run: {d}"),
            None => format!("Last successful practice run: {BLANK_FIELD} (none yet)"),
        };
        sections.push(section(
            "Date of the last practice run",
            vec![
                Block::Para(line),
                Block::Para("Write the date here each time a practice run works.".into()),
            ],
        ));
    }

    // 14. Next recommended drill date.
    sections.push(section(
        "When to practice next",
        vec![
            Block::Para(format!("Try again by: {}", data.next_drill)),
            Block::Para(
                "A practice run about once a year keeps the plan fresh. Sooner is better if a \
                 device or app has changed."
                    .into(),
            ),
        ],
    ));

    // 15. Lifeboat version + report hash.
    sections.push(section(
        "Version and report code",
        vec![
            Block::Bullet(format!(
                "Bitcoin Lifeboat version: {}",
                data.lifeboat_version
            )),
            Block::Bullet(format!("Report code: {}", data.report_hash)),
            Block::Para("These let an expert make the same report again.".into()),
        ],
    ));

    // 16. Mandatory disclaimer (§15.6 long).
    sections.push(section(
        "Important notice",
        vec![Block::Code(DISCLAIMER_LONG.to_string())],
    ));

    sections
}

/// Liana inheritance-style wallet with normal-owner and timelocked recovery paths.
fn build_liana_sections(data: &RunbookData, mode: RedactionMode) -> Vec<RunbookSection> {
    let mut sections = Vec::with_capacity(16);

    sections.push(section(
        "Safety warning",
        vec![
            Block::Para(
                "Never type recovery words into a website, chat, email, or a tool that is not the \
                 wallet software named by the owner."
                    .into(),
            ),
            Block::Para(
                "This plan does not contain recovery words or private keys. It explains which \
                 materials to gather and when the recovery path may be used."
                    .into(),
            ),
            Block::Para(
                "Anyone who asks to \"unlock\" this plan for a fee is trying to steal from the \
                 wallet."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "Do not panic",
        vec![
            Block::Para(
                "A timelocked recovery cannot be rushed. Read the whole plan before using any \
                 signing device."
                    .into(),
            ),
            Block::Para(
                "If the recovery path is not active yet, wait. Trying early can create confusing \
                 errors and wasted work."
                    .into(),
            ),
            Block::Para(
                "Take a break before each signing step. The goal is a correct rehearsal, not a fast \
                 one."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "Stop and call a trusted helper",
        vec![
            Block::Para(
                "If any path, block height, or wallet message is unclear, stop before signing."
                    .into(),
            ),
            Block::Para(
                "Ask a trusted helper who understands Liana or Bitcoin recovery to review the plan \
                 with you."
                    .into(),
            ),
            Block::Para(format!("Trusted helper to call: {BLANK_FIELD}")),
            Block::Para(format!("Second reviewer, if required: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section(
        "What you will need",
        vec![
            Block::Check("This plan, printed on paper.".into()),
            Block::Check("The Liana backup file or written recovery details.".into()),
            Block::Check("The primary-path signing device, if it is still available.".into()),
            Block::Check("The recovery-path device or backup named by the owner.".into()),
            Block::Check("The wallet software listed in section 10.".into()),
            Block::Check("A current block height from a trusted source, written by hand.".into()),
        ],
    ));

    sections.push(section(
        "What kind of wallet this is",
        vec![
            Block::Para(
                "This is a Liana-style timelock wallet. It has a normal owner path and at least one \
                 recovery path that waits for a timelock."
                    .into(),
            ),
            Block::Bullet(format!("Script type: {}", data.wallet_summary.script_type)),
            Block::Bullet(format!("Number of keys listed: {}", data.wallet_summary.key_count)),
            Block::Para(
                "Use the primary path first if the owner is available and the primary device still \
                 works. Use the recovery path only when the owner planned for it and the waiting \
                 period has passed."
                    .into(),
            ),
        ],
    ));

    let lead = vec![
        Block::Para(
            "The recovery details describe both the primary path and the recovery path. Without \
             them, Liana may not be able to show when recovery is available."
                .into(),
        ),
        Block::Para(
            "Keep a written or stamped copy with the Liana backup package. The details are not \
             recovery words, but they reveal wallet structure, so keep them private."
                .into(),
        ),
    ];
    sections.push(section(
        "The wallet's recovery details",
        descriptor_blocks(data, mode, lead),
    ));

    sections.push(section("Primary and recovery paths", {
        let mut blocks = vec![
            Block::Para(
                "Fill in the path roles by hand after printing. Do not write recovery words, private \
                 keys, or passphrases here."
                    .into(),
            ),
            Block::Para(format!(
                "Primary path signer or device: {BLANK_FIELD}"
            )),
            Block::Para(format!("Primary path material is kept at: {BLANK_FIELD}")),
            Block::Para(format!(
                "Recovery path signer or device: {BLANK_FIELD}"
            )),
            Block::Para(format!("Recovery path material is kept at: {BLANK_FIELD}")),
        ];
        if data.signers.is_empty() {
            blocks.push(Block::Bullet(
                "Listed key A: short code ________, path ________".into(),
            ));
            blocks.push(Block::Bullet(
                "Listed key B: short code ________, path ________".into(),
            ));
        } else {
            for s in &data.signers {
                let mut line = format!(
                    "{}: short code {}, path {}",
                    s.label, s.fingerprint, s.derivation_path
                );
                if mode == RedactionMode::Private {
                    if let Some(model) = &s.device_model {
                        line.push_str(&format!(", device {model}"));
                    }
                }
                blocks.push(Block::Bullet(line));
            }
        }
        blocks
    }));

    sections.push(section(
        "Passphrase reminder",
        vec![
            Block::Para(
                "If the owner used an extra word (passphrase), it is not written here and never \
                 should be."
                    .into(),
            ),
            Block::Para(
                "Find any extra word only where the owner stored it separately. Without the exact \
                 extra word, the recovery words can point to a different wallet."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "People to contact",
        vec![
            Block::Para(
                "Fill these in by hand. Avoid strangers, paid recovery services, and anyone who \
                 contacts you first."
                    .into(),
            ),
            Block::Para(format!("Trusted helper name: {BLANK_FIELD}")),
            Block::Para(format!("Trusted helper phone: {BLANK_FIELD}")),
            Block::Para(format!("Executor or attorney: {BLANK_FIELD}")),
            Block::Para(format!("Second family reviewer: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section("The app you will need", {
        let mut blocks = vec![Block::Para(
            "Use Liana or another wallet that can understand this timelock policy. Open the wallet \
             in watch-only mode before using any recovery words."
                .into(),
        )];
        if data.wallet_software.is_empty() {
            blocks.push(Block::Para(format!(
                "Wallet software to use: {BLANK_FIELD}"
            )));
        } else {
            for sw in &data.wallet_software {
                blocks.push(Block::Bullet(sw.clone()));
            }
        }
        blocks.push(Block::Para(format!(
            "Liana backup file name or paper reference: {BLANK_FIELD}"
        )));
        blocks
    }));

    sections.push(section(
        "How to check the timelock",
        vec![
            Block::Step(
                "Open the recovery details in watch-only mode and find the policy or recovery tree."
                    .into(),
            ),
            Block::Step(
                "Find the primary path and the recovery path. Confirm which signer belongs to each."
                    .into(),
            ),
            Block::Step(
                "Write down the current block height from a trusted source, then compare it with \
                 the recovery-path countdown."
                    .into(),
            ),
            Block::Step(
                "If the wallet says the recovery path is not active yet, stop and wait until the \
                 printed or wallet-shown date or block height."
                    .into(),
            ),
            Block::Step(
                "Practice with a test wallet before attempting any real recovery.".into(),
            ),
        ],
    ));

    sections.push(section(
        "When to stop right away",
        vec![
            Block::Para("Stop and get help if any of these happen:".into()),
            Block::Bullet("A website, app, or person asks you to type recovery words.".into()),
            Block::Bullet("The wallet app shows no recovery path or a different policy.".into()),
            Block::Bullet(
                "The current block height is below the recovery-path block height.".into(),
            ),
            Block::Bullet(
                "An address or wallet history does not match the owner's records.".into(),
            ),
            Block::Bullet("Anyone pressures you to hurry, share your screen, or pay a fee.".into()),
        ],
    ));

    sections.push(section(
        "Date of the last practice run",
        vec![
            Block::Para(match &data.drill_date {
                Some(d) => format!("Last successful Liana practice run: {d}"),
                None => format!("Last successful Liana practice run: {BLANK_FIELD} (none yet)"),
            }),
            Block::Para(format!(
                "Current block height during the last drill: {BLANK_FIELD}"
            )),
            Block::Para(format!(
                "Recovery path active at block or date: {BLANK_FIELD}"
            )),
        ],
    ));

    sections.push(section(
        "When to practice next",
        vec![
            Block::Para(format!("Try again by: {}", data.next_drill)),
            Block::Para(
                "Run a new drill after changing a device, updating Liana, moving the backup file, or \
                 changing who will help with recovery."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "Version and report code",
        vec![
            Block::Bullet(format!(
                "Bitcoin Lifeboat version: {}",
                data.lifeboat_version
            )),
            Block::Bullet(format!("Report code: {}", data.report_hash)),
            Block::Para(
                "These let a helper reproduce the same runbook inputs and check which Lifeboat \
                 version created it."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "Important notice",
        vec![Block::Code(DISCLAIMER_LONG.to_string())],
    ));

    sections
}

/// The meetup workshop kit (15-attendee hands-on class, educator-facing).
fn build_workshop_sections(data: &RunbookData, mode: RedactionMode) -> Vec<RunbookSection> {
    let mut sections = Vec::with_capacity(16);

    sections.push(section(
        "Safety warning",
        vec![
            Block::Para(
                "Never enter a real seed phrase into a website or this workshop's software. \
                 This class uses test wallets only."
                    .into(),
            ),
            Block::Para(
                "Bitcoin Lifeboat never asks for a seed phrase. Teach attendees that anyone who \
                 does is a scammer."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "Do not panic",
        vec![
            Block::Para(
                "Remind attendees that recovery is a slow, careful process and that this class is \
                 a safe place to make and discuss mistakes."
                    .into(),
            ),
            Block::Para("Keep the pace relaxed. Allow time for questions after each step.".into()),
        ],
    ));

    sections.push(section(
        "Stop and call a trusted helper",
        vec![
            Block::Para(
                "Teach the habit: when a step is unclear, stop and ask. In real recovery the \
                 helper is a trusted person; in this class it is the instructor."
                    .into(),
            ),
            Block::Para(format!("Instructor / helper on the day: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section(
        "Required materials checklist",
        vec![
            Block::Check("Up to 15 printed copies of this kit.".into()),
            Block::Check("A projector or large screen for the live demo.".into()),
            Block::Check("Test (Signet or regtest) descriptors and sample wallet files.".into()),
            Block::Check(
                "A computer per small group with the wallet software in section 10.".into(),
            ),
            Block::Check("Spare paper and pens for blank fields.".into()),
        ],
    ));

    sections.push(section(
        "Wallet type summary",
        vec![
            Block::Para(
                "Run the class with a simple single-signature test wallet first, then a 2-of-3 \
                 multisig if time allows."
                    .into(),
            ),
            Block::Bullet(format!(
                "Script type used today: {}",
                data.wallet_summary.script_type
            )),
            Block::Bullet(format!("Number of keys: {}", data.wallet_summary.key_count)),
        ],
    ));

    let lead = vec![Block::Para(
        "Walk attendees through reading a descriptor and explaining each part. Use only test \
         descriptors in class."
            .into(),
    )];
    sections.push(section(
        "Descriptor backup reminder",
        descriptor_blocks(data, mode, lead),
    ));

    sections.push(section(
        "Signer/device checklist",
        vec![
            Block::Para(
                "For the multisig demo, show how each signer device contributes one signature."
                    .into(),
            ),
            Block::Bullet("Demo signer A: short code ________".into()),
            Block::Para(format!("Demo device location / owner: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section(
        "Passphrase existence reminder",
        vec![Block::Para(
            "Explain that a passphrase (a 25th word) is optional and, if used, must be stored \
                 apart from the seed. Never demonstrate with a real passphrase."
                .into(),
        )],
    ));

    sections.push(section(
        "Emergency contacts",
        vec![
            Block::Para("Attendees fill these in for their own real setup after class.".into()),
            Block::Para(format!("My trusted helper: {BLANK_FIELD}")),
            Block::Para(format!("My attorney or executor: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section("Wallet software dependency list", {
        let mut blocks = vec![Block::Para(
            "Install these before class so attendees can follow along:".into(),
        )];
        if data.wallet_software.is_empty() {
            blocks.push(Block::Para(format!("Workshop software: {BLANK_FIELD}")));
        } else {
            for sw in &data.wallet_software {
                blocks.push(Block::Bullet(sw.clone()));
            }
        }
        blocks
    }));

    sections.push(section(
        "Verification steps",
        vec![
            Block::Step("Load a test descriptor in watch-only mode and read it together.".into()),
            Block::Step("Derive the first address and confirm everyone sees the same one.".into()),
            Block::Step("Sign and broadcast a Signet transaction as a group.".into()),
            Block::Step("Have each attendee write their own next-step plan.".into()),
        ],
    ));

    sections.push(section(
        "Stop conditions",
        vec![
            Block::Para("Pause the class and reset if:".into()),
            Block::Bullet("Anyone is about to use a real seed phrase or real funds.".into()),
            Block::Bullet("An attendee feels lost; slow down and review.".into()),
        ],
    ));

    sections.push(section(
        "Date of last successful drill",
        vec![Block::Para(match &data.drill_date {
            Some(d) => format!("Workshop last run: {d}"),
            None => format!("Workshop last run: {BLANK_FIELD}"),
        })],
    ));

    sections.push(section(
        "Next recommended drill date",
        vec![Block::Para(format!("Next workshop: {}", data.next_drill))],
    ));

    sections.push(section(
        "Version and report hash",
        vec![
            Block::Bullet(format!(
                "Bitcoin Lifeboat version: {}",
                data.lifeboat_version
            )),
            Block::Bullet(format!("Report hash: {}", data.report_hash)),
        ],
    ));

    sections.push(section(
        "Disclaimer",
        vec![Block::Code(DISCLAIMER_LONG.to_string())],
    ));

    sections
}

/// The business treasury runbook (corporate self-custody).
fn build_business_sections(data: &RunbookData, mode: RedactionMode) -> Vec<RunbookSection> {
    let mut sections = Vec::with_capacity(16);

    sections.push(section(
        "Safety warning",
        vec![
            Block::Para(
                "No employee or officer should ever enter a seed phrase into a website or send \
                 it over chat or email."
                    .into(),
            ),
            Block::Para(
                "Bitcoin Lifeboat never asks for seed phrases. Treat any such request as fraud \
                 and report it through your security process."
                    .into(),
            ),
        ],
    ));

    sections.push(section(
        "Do not panic",
        vec![
            Block::Para(
                "In an incident, follow this runbook step by step. Rushing causes errors that can \
                 lock funds."
                    .into(),
            ),
            Block::Para(
                "Convene the authorized signers calmly and confirm roles before acting.".into(),
            ),
        ],
    ));

    sections.push(section(
        "Stop and call a trusted helper",
        vec![
            Block::Para(
                "If a step is unclear or a signer is unavailable, stop and escalate to the \
                 treasury owner or your security advisor."
                    .into(),
            ),
            Block::Para(format!("Escalation contact: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section(
        "Required materials checklist",
        vec![
            Block::Check("This runbook, stored with corporate continuity documents.".into()),
            Block::Check("The descriptor backup held in company records.".into()),
            Block::Check("Access to a quorum of officer signing devices.".into()),
            Block::Check("A company computer with the wallet software in section 10.".into()),
            Block::Check("The treasury policy and authorized-signer list.".into()),
        ],
    ));

    sections.push(section("Wallet type summary", {
        let ws = &data.wallet_summary;
        let mut blocks = vec![
            Block::Bullet(format!("Script type: {}", ws.script_type)),
            Block::Bullet(format!("Number of keys: {}", ws.key_count)),
        ];
        if let Some(m) = ws.threshold {
            blocks.push(Block::Bullet(format!(
                "Signatures required: {m} of {}",
                ws.key_count
            )));
            blocks.push(Block::Para(format!(
                "Treasury policy requires {m} of {} authorized officers to approve any \
                     movement of funds.",
                ws.key_count
            )));
        } else {
            blocks.push(Block::Para(
                "This is a single-key treasury. Consider moving to multisig for separation of \
                     duties."
                    .into(),
            ));
        }
        blocks
    }));

    let lead = vec![Block::Para(
        "The descriptor is the company's record of how to find and rebuild this wallet. Store it \
         with the same controls as other critical records."
            .into(),
    )];
    sections.push(section(
        "Descriptor backup reminder",
        descriptor_blocks(data, mode, lead),
    ));

    sections.push(section("Signer/device checklist", {
        let mut blocks = vec![Block::Para(
            "Record each authorized signer, their device, and where it is held under custody."
                .into(),
        )];
        if data.signers.is_empty() {
            blocks.push(Block::Bullet(
                "Officer A: fingerprint ________, path ________".into(),
            ));
            blocks.push(Block::Para(format!(
                "Officer A custody location: {BLANK_FIELD}"
            )));
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
                blocks.push(Block::Para(format!(
                    "{} custody location: {BLANK_FIELD}",
                    s.label
                )));
            }
        }
        blocks
    }));

    sections.push(section(
        "Passphrase existence reminder",
        vec![Block::Para(
            "If treasury policy uses a passphrase, store it under dual control, apart from the \
             seed backups. Never record the passphrase value in this runbook."
                .into(),
        )],
    ));

    sections.push(section(
        "Emergency contacts",
        vec![
            Block::Para("Maintain current contacts; review whenever an officer changes.".into()),
            Block::Para(format!("Treasury owner: {BLANK_FIELD}")),
            Block::Para(format!("Legal / general counsel: {BLANK_FIELD}")),
            Block::Para(format!("Security advisor: {BLANK_FIELD}")),
        ],
    ));

    sections.push(section("Wallet software dependency list", {
        let mut blocks = vec![Block::Para(
            "Document the approved wallet software for treasury operations:".into(),
        )];
        if data.wallet_software.is_empty() {
            blocks.push(Block::Para(format!("Approved software: {BLANK_FIELD}")));
        } else {
            for sw in &data.wallet_software {
                blocks.push(Block::Bullet(sw.clone()));
            }
        }
        blocks
    }));

    sections.push(section(
        "Verification steps",
        vec![
            Block::Step("Load the descriptor in watch-only mode and reconcile the balance.".into()),
            Block::Step("Confirm a known receive address matches treasury records.".into()),
            Block::Step(
                "Run a Signet drill: assemble a quorum and sign a test transaction.".into(),
            ),
            Block::Step("Record the drill outcome in the treasury log and in section 13.".into()),
        ],
    ));

    sections.push(section(
        "Stop conditions",
        vec![
            Block::Para("Halt and escalate if:".into()),
            Block::Bullet("A quorum of signers cannot be assembled.".into()),
            Block::Bullet("A derived address does not match treasury records.".into()),
            Block::Bullet("Anyone requests an out-of-policy or urgent transfer.".into()),
        ],
    ));

    sections.push(section(
        "Date of last successful drill",
        vec![Block::Para(match &data.drill_date {
            Some(d) => format!("Last treasury drill: {d}"),
            None => format!("Last treasury drill: {BLANK_FIELD}"),
        })],
    ));

    sections.push(section(
        "Next recommended drill date",
        vec![Block::Para(format!(
            "Next treasury drill: {}",
            data.next_drill
        ))],
    ));

    sections.push(section(
        "Version and report hash",
        vec![
            Block::Bullet(format!(
                "Bitcoin Lifeboat version: {}",
                data.lifeboat_version
            )),
            Block::Bullet(format!("Report hash: {}", data.report_hash)),
        ],
    ));

    sections.push(section(
        "Disclaimer",
        vec![Block::Code(DISCLAIMER_LONG.to_string())],
    ));

    sections
}

/// Render the runbook as Markdown (§17.8). Heir templates open with the verbatim
/// §15.6 [`DISCLAIMER_HEIR`] (a fenced block, so the bytes are preserved exactly)
/// and the inline glossary, before the §14.3 privacy banner and the sections.
#[must_use]
pub fn render_markdown(template: HeirTemplate, data: &RunbookData, mode: RedactionMode) -> String {
    let sections = build_sections(template, data, mode);
    let mut out = String::new();
    out.push_str("# ");
    out.push_str(template.title());
    out.push_str("\n\n");
    out.push_str(&format!("_{}_\n\n", template.subtitle()));

    if let Some(disclaimer) = heir_disclaimer(template) {
        out.push_str("```\n");
        out.push_str(disclaimer);
        out.push_str("\n```\n\n");
    }

    let glossary = glossary(template);
    if !glossary.is_empty() {
        out.push_str("## Words to know\n\n");
        for entry in &glossary {
            out.push_str(&format!("- {entry}\n"));
        }
        out.push('\n');
    }

    if let Some(banner) = privacy_banner(data, mode) {
        for line in banner.lines() {
            out.push_str("> ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }

    for (i, sec) in sections.iter().enumerate() {
        out.push_str(&format!("## {}. {}\n\n", i + 1, sec.heading));
        let mut step_no = 0u32;
        let rendered: Vec<String> = sec
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

/// Flatten the runbook into printpdf body lines (ASCII-folded for the base-14
/// fonts). Mirrors [`crate::owner::pdf_body_lines`] but prepends the heir
/// disclaimer and glossary.
#[must_use]
pub(crate) fn pdf_body_lines(
    template: HeirTemplate,
    data: &RunbookData,
    mode: RedactionMode,
) -> Vec<String> {
    let sections = build_sections(template, data, mode);
    let mut lines: Vec<String> = Vec::new();

    lines.push(ascii_fold(template.subtitle()));
    lines.push(String::new());

    if let Some(disclaimer) = heir_disclaimer(template) {
        for line in disclaimer.lines() {
            lines.push(ascii_fold(line));
        }
        lines.push(String::new());
    }

    let glossary = glossary(template);
    if !glossary.is_empty() {
        lines.push("Words to know".to_string());
        for entry in &glossary {
            lines.push(format!("- {}", ascii_fold(entry)));
        }
        lines.push(String::new());
    }

    if let Some(banner) = privacy_banner(data, mode) {
        for line in ascii_fold(banner).lines() {
            lines.push(line.to_string());
        }
        lines.push(String::new());
    }

    for (i, sec) in sections.iter().enumerate() {
        lines.push(format!("{}. {}", i + 1, sec.heading));
        let mut step_no = 0u32;
        for b in &sec.blocks {
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

/// The `sections` / preamble data the heir Typst templates render.
#[must_use]
pub(crate) fn sections_json(
    template: HeirTemplate,
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

#[cfg(test)]
mod tests {
    use super::*;
    use report_engine::passes_anti_overclaim_lint;

    const DESCRIPTOR: &str =
        "wsh(sortedmulti(2,[11111111/48h/1h/0h/2h]tpubD6NzVbExampleHeirRunbookKey0000000000000000000000000000000000000000000000000000000/0/*))#cccccccc";
    const SAMPLE_HASH: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn sample_data(template: HeirTemplate) -> RunbookData {
        let (script, threshold, n): (&str, Option<u32>, u32) = match template {
            HeirTemplate::HeirSinglesigBasic | HeirTemplate::HeirSinglesigPassphrase => {
                ("wpkh", None, 1)
            }
            HeirTemplate::HeirMultisig2of3 => ("wsh(sortedmulti)", Some(2), 3),
            HeirTemplate::HeirMultisig3of5 => ("wsh(sortedmulti)", Some(3), 5),
            HeirTemplate::LianaTimelock => ("wsh(or_d timelock)", None, 2),
            HeirTemplate::MeetupWorkshop => ("wpkh", None, 1),
            HeirTemplate::BusinessTreasury => ("wsh(sortedmulti)", Some(2), 3),
        };
        let count = if template.is_liana_timelock() {
            n
        } else {
            threshold.map_or(1, |_| n)
        };
        let signers: Vec<Signer> = (0..count)
            .map(|i| {
                let label = format!("Signer {}", (b'A' + i as u8) as char);
                let fp = format!("{:08x}", 0x1111_1111_u32.wrapping_mul(i + 1));
                Signer::new(label, fp, "m/48h/1h/0h/2h").with_device_model("Coldcard Mk4")
            })
            .collect();
        let descriptor = if template.is_liana_timelock() {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/descriptors/timelock/liana_basic.txt"
            ))
            .trim()
        } else {
            DESCRIPTOR
        };
        let software = if template.is_liana_timelock() {
            "Liana"
        } else {
            "Sparrow"
        };
        RunbookData::new(
            RunbookWalletSummary::new(script, threshold, n),
            descriptor,
            "2027-05-01",
            SAMPLE_HASH,
            "0.1.0",
        )
        .with_signers(signers)
        .with_drill_date("2026-05-01")
        .with_passphrase(template == HeirTemplate::HeirSinglesigPassphrase)
        .with_wallet_software(vec![software.to_string()])
    }

    use crate::owner::{RunbookWalletSummary, Signer};

    fn mode_label(mode: RedactionMode) -> &'static str {
        match mode {
            RedactionMode::PublicSafe => "public_safe",
            RedactionMode::Private => "private",
        }
    }

    #[test]
    fn every_template_has_the_sixteen_required_sections() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let sections = build_sections(template, &data, mode);
                assert_eq!(
                    sections.len(),
                    16,
                    "{} ({:?}) must have all 16 §9.5 sections",
                    template.name(),
                    mode
                );
                for s in &sections {
                    assert!(!s.heading.trim().is_empty());
                    assert!(!s.blocks.is_empty(), "section '{}' is empty", s.heading);
                }
            }
        }
    }

    #[test]
    fn heir_disclaimer_is_present_verbatim_in_heir_templates() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = render_markdown(template, &data, mode);
                if template.is_heir() {
                    assert!(
                        md.contains(DISCLAIMER_HEIR),
                        "{} ({:?}) must open with the verbatim §15.6 heir disclaimer",
                        template.name(),
                        mode
                    );
                } else {
                    assert!(
                        !md.contains(DISCLAIMER_HEIR),
                        "{} is not heir-facing and must not carry the heir disclaimer",
                        template.name()
                    );
                }
            }
        }
    }

    #[test]
    fn every_template_renders_markdown_in_both_modes() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = render_markdown(template, &data, mode);
                assert!(md.starts_with("# "));
                assert!(md.contains(template.title()));
                // The §15.6 long disclaimer (section 16) is verbatim in every runbook.
                assert!(md.contains(DISCLAIMER_LONG));
            }
        }
    }

    #[test]
    fn stop_and_call_a_trusted_helper_section_is_present() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            let sections = build_sections(template, &data, RedactionMode::PublicSafe);
            assert!(
                sections
                    .iter()
                    .any(|s| s.heading == "Stop and call a trusted helper"),
                "{} must include the 'Stop and call a trusted helper' section",
                template.name()
            );
        }
    }

    #[test]
    fn heir_templates_carry_an_inline_glossary() {
        for template in HeirTemplate::ALL {
            let glossary = glossary(template);
            if template.is_heir() {
                assert!(!glossary.is_empty(), "{} needs a glossary", template.name());
                let md = render_markdown(template, &sample_data(template), RedactionMode::Private);
                assert!(md.contains("Words to know"));
            } else {
                assert!(glossary.is_empty());
            }
        }
    }

    #[test]
    fn heir_facing_copy_avoids_bare_jargon() {
        // Heir-facing copy must not use bare "xpub"/"PSBT" (PRD §9.4). "descriptor"
        // is allowed only inside the glossary, where it is expanded inline.
        for template in HeirTemplate::ALL {
            if !template.is_heir() {
                continue;
            }
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let mut authored: Vec<String> = glossary(template);
                for s in build_sections(template, &data, mode) {
                    authored.push(s.heading.clone());
                    for b in &s.blocks {
                        if !matches!(b, Block::Code(_)) {
                            authored.push(b.text().to_string());
                        }
                    }
                }
                for t in &authored {
                    assert!(!t.contains("xpub"), "{} bare xpub: {t}", template.name());
                    assert!(!t.contains("PSBT"), "{} bare PSBT: {t}", template.name());
                }
            }
        }
    }

    #[test]
    fn public_safe_hides_the_descriptor_private_shows_it() {
        let template = HeirTemplate::HeirMultisig2of3;
        let data = sample_data(template);

        let public = render_markdown(template, &data, RedactionMode::PublicSafe);
        assert!(public.contains(crate::owner::DESCRIPTOR_REDACTED_PLACEHOLDER));
        assert!(!public.contains(DESCRIPTOR));

        let private = render_markdown(template, &data, RedactionMode::Private);
        assert!(private.contains(DESCRIPTOR));
    }

    #[test]
    fn liana_template_covers_timelock_paths_and_blank_fields() {
        let data = sample_data(HeirTemplate::LianaTimelock);
        let public = render_markdown(
            HeirTemplate::LianaTimelock,
            &data,
            RedactionMode::PublicSafe,
        );

        assert!(public.contains("Liana-style timelock wallet"));
        assert!(public.contains("Primary path signer or device"));
        assert!(public.contains("Recovery path signer or device"));
        assert!(public.contains("How to check the timelock"));
        assert!(public.contains("Current block height during the last drill"));
        assert!(public.contains(BLANK_FIELD));
        assert!(public.contains(crate::owner::DESCRIPTOR_REDACTED_PLACEHOLDER));
        assert!(!public.contains(data.descriptor.as_str()));

        let private = render_markdown(HeirTemplate::LianaTimelock, &data, RedactionMode::Private);
        assert!(private.contains(data.descriptor.as_str()));
    }

    #[test]
    fn forbidden_content_is_never_emitted() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = render_markdown(template, &data, mode);
                for line in md.lines() {
                    let lower = line.to_lowercase();
                    if (lower.contains("location:")
                        || lower.contains("kept at:")
                        || lower.contains("custody location:"))
                        && !line.contains("Do not")
                    {
                        assert!(
                            line.contains(BLANK_FIELD),
                            "location-style line must be a blank field, got: {line}"
                        );
                    }
                }
                if mode == RedactionMode::PublicSafe {
                    assert!(
                        !md.contains(DESCRIPTOR),
                        "{} leaked the descriptor",
                        template.name()
                    );
                }
            }
        }
    }

    #[test]
    fn no_rendered_form_overclaims() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = render_markdown(template, &data, mode);
                assert!(
                    passes_anti_overclaim_lint(&md),
                    "{} ({:?}) must pass the §16.8 anti-overclaim lint",
                    template.name(),
                    mode
                );
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
                for entry in glossary(template) {
                    assert!(passes_anti_overclaim_lint(&entry));
                }
            }
        }
    }

    #[test]
    fn markdown_is_deterministic() {
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                assert_eq!(
                    render_markdown(template, &data, mode),
                    render_markdown(template, &data, mode)
                );
            }
        }
    }

    #[test]
    fn sections_json_shape_is_stable() {
        let template = HeirTemplate::HeirMultisig2of3;
        let data = sample_data(template);
        let v = sections_json(template, &data, RedactionMode::Private);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 16);
        assert_eq!(arr[0]["index"], 1);
        assert!(!arr[0]["heading"].as_str().unwrap().is_empty());
        assert!(arr[0]["blocks"].is_array());
    }

    #[test]
    fn heir_markdown_snapshots() {
        // One Markdown snapshot per template × export mode. Regenerate with
        // `INSTA_UPDATE=always cargo +1.78.0 test -p runbook-engine`, then commit
        // the .snap files.
        for template in HeirTemplate::ALL {
            let data = sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let name = format!(
                    "heir_md__{}__{}",
                    template.name().replace('-', "_"),
                    mode_label(mode)
                );
                insta::assert_snapshot!(name, render_markdown(template, &data, mode));
            }
        }
    }
}
