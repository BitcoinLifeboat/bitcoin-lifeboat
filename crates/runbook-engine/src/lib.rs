//! `runbook-engine` — recovery and inheritance runbooks (PDF).
//!
//! US-031 establishes the base PDF pipeline that the owner, heir, workshop, and
//! business templates (US-032/033) build on. There are two backends:
//!
//! - **Typst** ([`typst_cli`]) — the preferred path. Renders the bundled
//!   [`templates/base.typ`](../templates/base.typ) template by invoking a
//!   bundled `typst` binary as a subprocess, embedding the Inter / JetBrains
//!   Mono fonts. A missing binary is reported as
//!   [`ErrorCode::TypstNotBundled`](error_taxonomy::ErrorCode::TypstNotBundled)
//!   (`E-DEP-001`).
//! - **printpdf** ([`printpdf_backend`]) — the pure-Rust fall-back. Needs no
//!   external binary or font files (it uses the standard PDF base-14 fonts), so
//!   it always works. [`PdfBackend::Auto`] uses Typst when available and falls
//!   back to printpdf on `E-DEP-001`.
//!
//! Every page footer carries the verbatim §15.6 disclaimer
//! ([`report_engine::DISCLAIMER_SHORT`]), the Lifeboat version, and the report
//! hash. A4 and US Letter are both supported ([`PageSize`]).
//!
//! ## Determinism
//! The PRD §19/§27 invariant is "same input → byte-identical output". The
//! version and report hash are **caller-supplied** (this crate never reads the
//! clock or environment for content), and the printpdf path pins every
//! non-deterministic field (see [`printpdf_backend`]). The Typst path sets
//! `SOURCE_DATE_EPOCH=0` for the child. The `cargo test` gate locks the printpdf
//! output by SHA256 and by twice-rendered equality.

mod heir;
mod owner;
mod printpdf_backend;
mod typst_cli;

pub use heir::{
    glossary, heir_disclaimer, render_markdown as render_heir_markdown, HeirTemplate,
    DISCLAIMER_HEIR,
};
pub use owner::{
    build_sections, privacy_banner, render_markdown as render_owner_markdown, Block, OwnerTemplate,
    RunbookData, RunbookSection, RunbookWalletSummary, Signer, DESCRIPTOR_REDACTED_PLACEHOLDER,
};
pub use report_engine::RedactionMode;
pub use typst_cli::TypstBackend;

use std::path::PathBuf;
use std::time::Duration;

use error_taxonomy::{ErrorCode, LifeboatError};

/// The base Typst template rendered by the [`TypstBackend`]. The owner/heir/etc.
/// templates (US-032/033) are added as sibling `.typ` files.
const BASE_TEMPLATE_TYP: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/base.typ"));

/// The four owner Typst templates (US-032), paired with their
/// [`OwnerTemplate::name`]. Each renders the same `sections` data shape produced
/// by [`owner::sections_json`]; the engine selects one by template name.
const OWNER_TEMPLATES_TYP: [(&str, &str); 4] = [
    (
        "singlesig-basic",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/singlesig-basic.typ"
        )),
    ),
    (
        "singlesig-passphrase",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/singlesig-passphrase.typ"
        )),
    ),
    (
        "multisig-2of3",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/multisig-2of3.typ"
        )),
    ),
    (
        "multisig-3of5",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/multisig-3of5.typ"
        )),
    ),
];

/// The Typst source for `template`'s owner runbook.
fn owner_typ_source(template: OwnerTemplate) -> &'static str {
    let name = template.name();
    OWNER_TEMPLATES_TYP
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(BASE_TEMPLATE_TYP, |(_, src)| *src)
}

/// The seven heir/workshop/business Typst templates (US-033/US-093), paired with their
/// [`HeirTemplate::name`]. Each renders the `sections` data shape produced by
/// [`heir::sections_json`] plus the heir disclaimer / glossary preamble.
const HEIR_TEMPLATES_TYP: [(&str, &str); 7] = [
    (
        "heir-singlesig-basic",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/heir-singlesig-basic.typ"
        )),
    ),
    (
        "heir-singlesig-passphrase",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/heir-singlesig-passphrase.typ"
        )),
    ),
    (
        "heir-multisig-2of3",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/heir-multisig-2of3.typ"
        )),
    ),
    (
        "heir-multisig-3of5",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/heir-multisig-3of5.typ"
        )),
    ),
    (
        "liana-timelock",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/liana-timelock.typ"
        )),
    ),
    (
        "meetup-workshop",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/meetup-workshop.typ"
        )),
    ),
    (
        "business-treasury",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/runbooks/business-treasury.typ"
        )),
    ),
];

/// The v0.5 Liana timelock runbook Typst source (US-093).
/// `include_str!` forces it to exist at compile time.
pub const LIANA_TIMELOCK_TYP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/templates/runbooks/liana-timelock.typ"
));

/// The Typst source for `template`'s heir/workshop/business runbook.
fn heir_typ_source(template: HeirTemplate) -> &'static str {
    let name = template.name();
    HEIR_TEMPLATES_TYP
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(BASE_TEMPLATE_TYP, |(_, src)| *src)
}

/// Page size for a rendered runbook (PRD US-031: support A4 and US Letter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageSize {
    /// ISO A4 (210 × 297 mm).
    #[default]
    A4,
    /// US Letter (8.5 × 11 in = 215.9 × 279.4 mm).
    UsLetter,
}

impl PageSize {
    /// The portrait `(width, height)` in millimetres.
    #[must_use]
    pub fn dimensions_mm(self) -> (f32, f32) {
        match self {
            PageSize::A4 => (210.0, 297.0),
            PageSize::UsLetter => (215.9, 279.4),
        }
    }

    /// The Typst `page(paper: ...)` name for this size.
    #[must_use]
    pub fn typst_paper(self) -> &'static str {
        match self {
            PageSize::A4 => "a4",
            PageSize::UsLetter => "us-letter",
        }
    }
}

/// Which backend renders the runbook PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PdfBackend {
    /// Prefer the bundled Typst binary; fall back to printpdf on `E-DEP-001`.
    #[default]
    Auto,
    /// Force the Typst subprocess path (errors `E-DEP-001` when unavailable).
    Typst,
    /// Force the pure-Rust printpdf fall-back.
    Printpdf,
}

/// Footer content stamped on every page: the Lifeboat version and the report
/// hash. Both are caller-supplied so rendering stays deterministic (the §15.6
/// disclaimer text is fixed and pulled from `report-engine`).
#[derive(Debug, Clone, Copy)]
pub struct RunbookFooter<'a> {
    /// The Lifeboat application version (e.g. `report_engine::APP_VERSION`).
    pub lifeboat_version: &'a str,
    /// The `sha256:` report hash this runbook accompanies.
    pub report_hash: &'a str,
}

/// The base runbook template (US-031): a title, body lines, and a footer. The
/// richer owner/heir templates (US-032/033) extend this same shape.
#[derive(Debug, Clone, Copy)]
pub struct BaseTemplate<'a> {
    /// The runbook title (also the PDF document title).
    pub title: &'a str,
    /// Body paragraphs/lines, rendered top-to-bottom with pagination.
    pub body: &'a [&'a str],
    /// The per-page footer.
    pub footer: RunbookFooter<'a>,
}

/// Renders runbook templates to PDF, choosing between the Typst and printpdf
/// backends.
#[derive(Debug, Clone)]
pub struct RunbookEngine {
    typst_binary: Option<PathBuf>,
    fonts_dir: Option<PathBuf>,
    timeout: Duration,
}

impl Default for RunbookEngine {
    fn default() -> Self {
        Self {
            typst_binary: None,
            fonts_dir: default_fonts_dir(),
            timeout: typst_cli::DEFAULT_TIMEOUT,
        }
    }
}

impl RunbookEngine {
    /// A default engine: Typst resolved automatically, fonts taken from the
    /// bundle directory next to the running executable (if present), and the
    /// default render timeout.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use exactly `path` as the Typst binary (explicit configuration / tests).
    #[must_use]
    pub fn with_typst_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.typst_binary = Some(path.into());
        self
    }

    /// Look for embedded fonts (Inter / JetBrains Mono) in `dir`.
    #[must_use]
    pub fn with_fonts_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.fonts_dir = Some(dir.into());
        self
    }

    /// Override the Typst render timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Render `template` to PDF bytes using `backend` at `page_size` and `mode`.
    ///
    /// # Errors
    /// - [`ErrorCode::TypstNotBundled`] (`E-DEP-001`) with [`PdfBackend::Typst`]
    ///   when no Typst binary can be found.
    /// - [`ErrorCode::Internal`] / [`ErrorCode::CannotWrite`] on a backend
    ///   failure (see the backend docs).
    pub fn render_pdf(
        &self,
        template: &BaseTemplate,
        backend: PdfBackend,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        match backend {
            PdfBackend::Printpdf => printpdf_backend::render(template, page_size, mode),
            PdfBackend::Typst => self.render_typst(template, page_size, mode),
            PdfBackend::Auto => match self.render_typst(template, page_size, mode) {
                Err(e) if e.code() == ErrorCode::TypstNotBundled => {
                    printpdf_backend::render(template, page_size, mode)
                }
                result => result,
            },
        }
    }

    /// Render via the Typst subprocess backend.
    fn render_typst(
        &self,
        template: &BaseTemplate,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        let backend = match &self.typst_binary {
            Some(path) => TypstBackend::with_binary(path.clone()),
            None => TypstBackend::auto(),
        };
        let data = template_data_json(template, page_size, mode);
        backend.render(
            BASE_TEMPLATE_TYP,
            &data,
            self.fonts_dir.as_deref(),
            self.timeout,
        )
    }

    /// Render an owner runbook ([`OwnerTemplate`]) to PDF bytes from its §17.8
    /// [`RunbookData`] at `page_size` and `mode`, choosing `backend`.
    ///
    /// The output carries the sixteen §9.5 sections with labeled blank fields.
    /// `public-safe` (the default mode) hides the descriptor and the
    /// hardware-wallet model; `private` shows them and prepends the §14.3
    /// xpub-privacy banner when the descriptor reveals an xpub.
    ///
    /// # Errors
    /// See [`RunbookEngine::render_pdf`].
    pub fn render_owner_pdf(
        &self,
        template: OwnerTemplate,
        data: &RunbookData,
        backend: PdfBackend,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        match backend {
            PdfBackend::Printpdf => self.render_owner_printpdf(template, data, page_size, mode),
            PdfBackend::Typst => self.render_owner_typst(template, data, page_size, mode),
            PdfBackend::Auto => match self.render_owner_typst(template, data, page_size, mode) {
                Err(e) if e.code() == ErrorCode::TypstNotBundled => {
                    self.render_owner_printpdf(template, data, page_size, mode)
                }
                result => result,
            },
        }
    }

    /// Render an owner runbook via the pure-Rust printpdf fall-back. This is the
    /// deterministic, always-available path the tests exercise.
    fn render_owner_printpdf(
        &self,
        template: OwnerTemplate,
        data: &RunbookData,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        let lines = owner::pdf_body_lines(template, data, mode);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let base = BaseTemplate {
            title: template.title(),
            body: &refs,
            footer: RunbookFooter {
                lifeboat_version: &data.lifeboat_version,
                report_hash: &data.report_hash,
            },
        };
        printpdf_backend::render(&base, page_size, mode)
    }

    /// Render an owner runbook via the Typst subprocess backend (the preferred
    /// path when a `typst` binary is bundled).
    fn render_owner_typst(
        &self,
        template: OwnerTemplate,
        data: &RunbookData,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        let backend = match &self.typst_binary {
            Some(path) => TypstBackend::with_binary(path.clone()),
            None => TypstBackend::auto(),
        };
        let json = owner_template_data_json(template, data, page_size, mode);
        backend.render(
            owner_typ_source(template),
            &json,
            self.fonts_dir.as_deref(),
            self.timeout,
        )
    }

    /// Render a heir/workshop/business runbook ([`HeirTemplate`]) to PDF bytes
    /// from its §17.8 [`RunbookData`] at `page_size` and `mode`, choosing
    /// `backend`. Heir runbooks open with the verbatim §15.6 heir disclaimer and
    /// an inline glossary; `public-safe` hides the descriptor and device model.
    ///
    /// # Errors
    /// See [`RunbookEngine::render_pdf`].
    pub fn render_heir_pdf(
        &self,
        template: HeirTemplate,
        data: &RunbookData,
        backend: PdfBackend,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        match backend {
            PdfBackend::Printpdf => self.render_heir_printpdf(template, data, page_size, mode),
            PdfBackend::Typst => self.render_heir_typst(template, data, page_size, mode),
            PdfBackend::Auto => match self.render_heir_typst(template, data, page_size, mode) {
                Err(e) if e.code() == ErrorCode::TypstNotBundled => {
                    self.render_heir_printpdf(template, data, page_size, mode)
                }
                result => result,
            },
        }
    }

    /// Render a heir runbook via the deterministic printpdf fall-back (the tested
    /// path).
    fn render_heir_printpdf(
        &self,
        template: HeirTemplate,
        data: &RunbookData,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        let lines = heir::pdf_body_lines(template, data, mode);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let base = BaseTemplate {
            title: template.title(),
            body: &refs,
            footer: RunbookFooter {
                lifeboat_version: &data.lifeboat_version,
                report_hash: &data.report_hash,
            },
        };
        printpdf_backend::render(&base, page_size, mode)
    }

    /// Render a heir runbook via the Typst subprocess backend.
    fn render_heir_typst(
        &self,
        template: HeirTemplate,
        data: &RunbookData,
        page_size: PageSize,
        mode: RedactionMode,
    ) -> Result<Vec<u8>, LifeboatError> {
        let backend = match &self.typst_binary {
            Some(path) => TypstBackend::with_binary(path.clone()),
            None => TypstBackend::auto(),
        };
        let json = heir_template_data_json(template, data, page_size, mode);
        backend.render(
            heir_typ_source(template),
            &json,
            self.fonts_dir.as_deref(),
            self.timeout,
        )
    }
}

/// Convenience: render `template` with a default [`RunbookEngine`].
///
/// # Errors
/// See [`RunbookEngine::render_pdf`].
pub fn render_base_pdf(
    template: &BaseTemplate,
    backend: PdfBackend,
    page_size: PageSize,
    mode: RedactionMode,
) -> Result<Vec<u8>, LifeboatError> {
    RunbookEngine::new().render_pdf(template, backend, page_size, mode)
}

/// The §17.7 export-mode label matching `RedactionMode`'s kebab-case serde.
pub(crate) fn redaction_label(mode: RedactionMode) -> &'static str {
    match mode {
        RedactionMode::PublicSafe => "public-safe",
        RedactionMode::Private => "private",
    }
}

/// The `data.json` payload the Typst template reads (`#json("data.json")`).
fn template_data_json(template: &BaseTemplate, page_size: PageSize, mode: RedactionMode) -> String {
    serde_json::json!({
        "title": template.title,
        "body": template.body,
        "page_size": page_size.typst_paper(),
        "lifeboat_version": template.footer.lifeboat_version,
        "report_hash": template.footer.report_hash,
        "mode": redaction_label(mode),
        "disclaimer": report_engine::DISCLAIMER_SHORT,
    })
    .to_string()
}

/// The `data.json` payload an owner Typst template reads. Carries the title, the
/// footer fields, the optional §14.3 privacy banner, and the `sections` array
/// built by [`owner::sections_json`].
fn owner_template_data_json(
    template: OwnerTemplate,
    data: &RunbookData,
    page_size: PageSize,
    mode: RedactionMode,
) -> String {
    serde_json::json!({
        "title": template.title(),
        "template": template.name(),
        "page_size": page_size.typst_paper(),
        "lifeboat_version": data.lifeboat_version,
        "report_hash": data.report_hash,
        "mode": redaction_label(mode),
        "disclaimer": report_engine::DISCLAIMER_SHORT,
        "privacy_banner": owner::privacy_banner(data, mode),
        "sections": owner::sections_json(template, data, mode),
    })
    .to_string()
}

/// Convenience: render an owner runbook to PDF with a default [`RunbookEngine`].
///
/// # Errors
/// See [`RunbookEngine::render_owner_pdf`].
pub fn render_owner_pdf(
    template: OwnerTemplate,
    data: &RunbookData,
    backend: PdfBackend,
    page_size: PageSize,
    mode: RedactionMode,
) -> Result<Vec<u8>, LifeboatError> {
    RunbookEngine::new().render_owner_pdf(template, data, backend, page_size, mode)
}

/// The `data.json` payload a heir/workshop/business Typst template reads. Extends
/// the owner shape with the subtitle, the optional verbatim §15.6 heir
/// disclaimer, and the inline glossary.
fn heir_template_data_json(
    template: HeirTemplate,
    data: &RunbookData,
    page_size: PageSize,
    mode: RedactionMode,
) -> String {
    serde_json::json!({
        "title": template.title(),
        "subtitle": template.subtitle(),
        "template": template.name(),
        "page_size": page_size.typst_paper(),
        "lifeboat_version": data.lifeboat_version,
        "report_hash": data.report_hash,
        "mode": redaction_label(mode),
        "disclaimer": report_engine::DISCLAIMER_SHORT,
        "heir_disclaimer": heir::heir_disclaimer(template),
        "glossary": heir::glossary(template),
        "privacy_banner": owner::privacy_banner(data, mode),
        "sections": heir::sections_json(template, data, mode),
    })
    .to_string()
}

/// Convenience: render a heir/workshop/business runbook to PDF with a default
/// [`RunbookEngine`].
///
/// # Errors
/// See [`RunbookEngine::render_heir_pdf`].
pub fn render_heir_pdf(
    template: HeirTemplate,
    data: &RunbookData,
    backend: PdfBackend,
    page_size: PageSize,
    mode: RedactionMode,
) -> Result<Vec<u8>, LifeboatError> {
    RunbookEngine::new().render_heir_pdf(template, data, backend, page_size, mode)
}

/// The fonts directory next to the running executable (the packaged bundle), if
/// it exists. See `fonts/README.md`.
fn default_fonts_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.join("fonts");
    dir.is_dir().then_some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use report_engine::{passes_anti_overclaim_lint, APP_VERSION, DISCLAIMER_SHORT};
    use sha2::{Digest, Sha256};

    const SAMPLE_HASH: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    /// SHA256 of the canonical printpdf render of [`sample_template`] at A4 in
    /// public-safe mode. Pins the deterministic output (PRD §19/§27). Regenerate
    /// this only on a deliberate, reviewed change to the printpdf layout or a
    /// bump of the exact-pinned `printpdf`/`lopdf` versions.
    const PINNED_A4_PUBLIC_SHA256: &str =
        "2b59f1b9ece048ca9203955f852d1f12832289a457e72247dad0f27da3493561";

    fn sample_footer() -> RunbookFooter<'static> {
        RunbookFooter {
            lifeboat_version: "0.1.0",
            report_hash: SAMPLE_HASH,
        }
    }

    fn sample_body() -> &'static [&'static str] {
        &[
            "This is a base recovery runbook produced by Bitcoin Lifeboat.",
            "It is a diagnostic and rehearsal aid, not a guarantee.",
            "Print it, store it with your backups, and rehearse recovery.",
        ]
    }

    fn sample_template() -> BaseTemplate<'static> {
        BaseTemplate {
            title: "Recovery Runbook (Base Template)",
            body: sample_body(),
            footer: sample_footer(),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    fn assert_valid_pdf(bytes: &[u8]) {
        assert!(bytes.starts_with(b"%PDF"), "output is not a PDF");
        let tail_start = bytes.len().saturating_sub(16);
        assert!(
            bytes[tail_start..].windows(5).any(|w| w == b"%%EOF"),
            "PDF is not terminated by %%EOF"
        );
    }

    #[test]
    fn printpdf_fallback_produces_valid_pdf() {
        let pdf =
            printpdf_backend::render(&sample_template(), PageSize::A4, RedactionMode::PublicSafe)
                .expect("printpdf renders");
        assert_valid_pdf(&pdf);
    }

    #[test]
    fn printpdf_output_is_byte_deterministic() {
        let template = sample_template();
        let first =
            printpdf_backend::render(&template, PageSize::A4, RedactionMode::PublicSafe).unwrap();
        // Render again — printpdf's raw instance_id changes per render, so this
        // proves the deterministic post-process actually neutralizes it.
        let second =
            printpdf_backend::render(&template, PageSize::A4, RedactionMode::PublicSafe).unwrap();
        assert_eq!(first, second, "renders are not byte-identical");
    }

    #[test]
    fn pinned_pdf_sha256_is_stable() {
        let pdf =
            printpdf_backend::render(&sample_template(), PageSize::A4, RedactionMode::PublicSafe)
                .unwrap();
        assert_eq!(sha256_hex(&pdf), PINNED_A4_PUBLIC_SHA256);
    }

    #[test]
    fn a4_and_us_letter_both_render_and_differ() {
        let template = sample_template();
        let a4 =
            printpdf_backend::render(&template, PageSize::A4, RedactionMode::PublicSafe).unwrap();
        let letter =
            printpdf_backend::render(&template, PageSize::UsLetter, RedactionMode::PublicSafe)
                .unwrap();
        assert_valid_pdf(&a4);
        assert_valid_pdf(&letter);
        // Different page geometry → different bytes.
        assert_ne!(a4, letter);
    }

    #[test]
    fn private_and_public_modes_both_render() {
        let template = sample_template();
        let public =
            printpdf_backend::render(&template, PageSize::A4, RedactionMode::PublicSafe).unwrap();
        let private =
            printpdf_backend::render(&template, PageSize::A4, RedactionMode::Private).unwrap();
        assert_valid_pdf(&public);
        assert_valid_pdf(&private);
        assert_ne!(public, private, "the footer mode label should differ");
    }

    #[test]
    fn missing_typst_binary_is_e_dep_001() {
        let engine = RunbookEngine::new().with_typst_binary("/nonexistent/lifeboat-typst-binary");
        let err = engine
            .render_pdf(
                &sample_template(),
                PdfBackend::Typst,
                PageSize::A4,
                RedactionMode::PublicSafe,
            )
            .expect_err("a missing binary must error");
        assert_eq!(err.code(), ErrorCode::TypstNotBundled);
    }

    #[test]
    fn auto_backend_falls_back_to_printpdf_when_typst_missing() {
        let engine = RunbookEngine::new().with_typst_binary("/nonexistent/lifeboat-typst-binary");
        let pdf = engine
            .render_pdf(
                &sample_template(),
                PdfBackend::Auto,
                PageSize::A4,
                RedactionMode::PublicSafe,
            )
            .expect("auto falls back to printpdf");
        assert_valid_pdf(&pdf);
    }

    #[test]
    fn largest_template_renders_under_3s() {
        // A content-heavy multi-page template stands in for the "largest MVP
        // template" until US-032/033 add the real ones. The render budget is
        // <3 s (PRD US-031); printpdf does it in milliseconds.
        let lines: Vec<String> = (0..400)
            .map(|i| format!("Recovery step {i}: verify this item against your backup materials."))
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let template = BaseTemplate {
            title: "Largest MVP Runbook",
            body: &refs,
            footer: sample_footer(),
        };
        let start = std::time::Instant::now();
        let pdf =
            printpdf_backend::render(&template, PageSize::A4, RedactionMode::PublicSafe).unwrap();
        let elapsed = start.elapsed();
        assert_valid_pdf(&pdf);
        assert!(
            elapsed < Duration::from_secs(3),
            "render took {elapsed:?}, over the 3 s budget"
        );
    }

    #[test]
    fn footer_disclaimer_passes_anti_overclaim_lint() {
        // The footer reuses the §15.6 disclaimer verbatim; confirm it (and the
        // sample content) carry no §16.8 banned overclaim phrasing.
        assert!(passes_anti_overclaim_lint(DISCLAIMER_SHORT));
        assert!(passes_anti_overclaim_lint(sample_template().title));
        for line in sample_body() {
            assert!(passes_anti_overclaim_lint(line));
        }
    }

    #[test]
    fn template_data_json_carries_footer_and_paper() {
        let json = template_data_json(
            &sample_template(),
            PageSize::UsLetter,
            RedactionMode::Private,
        );
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["page_size"], "us-letter");
        assert_eq!(value["lifeboat_version"], "0.1.0");
        assert_eq!(value["report_hash"], SAMPLE_HASH);
        assert_eq!(value["mode"], "private");
        assert_eq!(value["disclaimer"], DISCLAIMER_SHORT);
        assert!(value["body"].as_array().unwrap().len() == sample_body().len());
    }

    #[test]
    fn app_version_const_is_usable_as_footer_version() {
        // Guards the report-engine re-export the CLI/UI will stamp (US-036/042).
        assert!(!APP_VERSION.is_empty());
    }

    // --- Owner runbook templates (US-032) -------------------------------------

    // Fixed, ASCII, never-mainnet sample data (PRD §27). The descriptors carry a
    // `tpub` so the §14.3 privacy banner fires in private mode.
    fn owner_sample_data(template: OwnerTemplate) -> RunbookData {
        let (script, threshold, n): (&str, Option<u32>, u32) = match template {
            OwnerTemplate::SinglesigBasic | OwnerTemplate::SinglesigPassphrase => ("wpkh", None, 1),
            OwnerTemplate::Multisig2of3 => ("wsh(sortedmulti)", Some(2), 3),
            OwnerTemplate::Multisig3of5 => ("wsh(sortedmulti)", Some(3), 5),
        };
        let signers: Vec<Signer> = (0..n)
            .map(|i| {
                let label = format!("Signer {}", (b'A' + i as u8) as char);
                let fp = format!("{:08x}", 0x1111_1111_u32.wrapping_mul(i + 1));
                Signer::new(label, fp, "m/48h/1h/0h/2h").with_device_model("Coldcard Mk4")
            })
            .collect();
        let descriptor =
            "wsh(sortedmulti(2,[11111111/48h/1h/0h/2h]tpubD6NzVbExampleOwnerRunbookKey0000000000000000000000000000000000000000000000000000000/0/*))#cccccccc";
        RunbookData::new(
            RunbookWalletSummary::new(script, threshold, n),
            descriptor,
            "2027-05-01",
            SAMPLE_HASH,
            "0.1.0",
        )
        .with_signers(signers)
        .with_drill_date("2026-05-01")
        .with_passphrase(template == OwnerTemplate::SinglesigPassphrase)
        .with_wallet_software(vec!["Sparrow".to_string()])
    }

    fn owner_mode_label(mode: RedactionMode) -> &'static str {
        match mode {
            RedactionMode::PublicSafe => "public-safe",
            RedactionMode::Private => "private",
        }
    }

    #[test]
    fn owner_pdf_sha256_table_is_stable() {
        // Renders every owner template in both modes via the deterministic
        // printpdf fall-back, asserts each is a valid, byte-reproducible PDF, and
        // pins each one BY HASH in the snapshot (PRD §19/§27; AC "PDF by hash").
        // Regenerate with `INSTA_UPDATE=always cargo +1.78.0 test -p
        // runbook-engine` after a deliberate layout change, then commit the .snap.
        let mut table = String::new();
        for template in OwnerTemplate::ALL {
            let data = owner_sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let pdf =
                    render_owner_pdf(template, &data, PdfBackend::Printpdf, PageSize::A4, mode)
                        .expect("printpdf renders the owner runbook");
                assert_valid_pdf(&pdf);
                let again =
                    render_owner_pdf(template, &data, PdfBackend::Printpdf, PageSize::A4, mode)
                        .unwrap();
                assert_eq!(pdf, again, "owner PDF render is not byte-deterministic");
                table.push_str(&format!(
                    "{:<22} {:<12} {}\n",
                    template.name(),
                    owner_mode_label(mode),
                    sha256_hex(&pdf)
                ));
            }
        }
        insta::assert_snapshot!("owner_pdf_sha256", table);
    }

    #[test]
    fn owner_pdf_modes_and_page_sizes_differ() {
        let template = OwnerTemplate::Multisig2of3;
        let data = owner_sample_data(template);
        let pub_a4 = render_owner_pdf(
            template,
            &data,
            PdfBackend::Printpdf,
            PageSize::A4,
            RedactionMode::PublicSafe,
        )
        .unwrap();
        let priv_a4 = render_owner_pdf(
            template,
            &data,
            PdfBackend::Printpdf,
            PageSize::A4,
            RedactionMode::Private,
        )
        .unwrap();
        let pub_letter = render_owner_pdf(
            template,
            &data,
            PdfBackend::Printpdf,
            PageSize::UsLetter,
            RedactionMode::PublicSafe,
        )
        .unwrap();
        assert_ne!(
            pub_a4, priv_a4,
            "private mode reveals the descriptor → differs"
        );
        assert_ne!(pub_a4, pub_letter, "page geometry differs");
    }

    #[test]
    fn largest_owner_template_renders_under_3s() {
        // The 3-of-5 owner runbook is the largest MVP template (PRD §9.5 "multisig
        // with 5 cosigners"), the real template US-031's placeholder stood in for.
        // The render is a few milliseconds; we take the BEST of three so a starved
        // scheduler slice (e.g. when the long fuzz-property test saturates CPUs in
        // a parallel `cargo test`) cannot flake the <3 s budget.
        let data = owner_sample_data(OwnerTemplate::Multisig3of5);
        let mut best = Duration::from_secs(u64::MAX);
        for _ in 0..3 {
            let start = std::time::Instant::now();
            let pdf = render_owner_pdf(
                OwnerTemplate::Multisig3of5,
                &data,
                PdfBackend::Printpdf,
                PageSize::A4,
                RedactionMode::Private,
            )
            .unwrap();
            best = best.min(start.elapsed());
            assert_valid_pdf(&pdf);
        }
        assert!(
            best < Duration::from_secs(3),
            "fastest of three renders took {best:?}, over the 3 s budget"
        );
    }

    #[test]
    fn owner_typst_data_json_carries_sections_and_banner() {
        let template = OwnerTemplate::SinglesigBasic;
        let data = owner_sample_data(template);

        let private =
            owner_template_data_json(template, &data, PageSize::A4, RedactionMode::Private);
        let v: serde_json::Value = serde_json::from_str(&private).unwrap();
        assert_eq!(v["template"], "singlesig-basic");
        assert_eq!(v["mode"], "private");
        assert_eq!(v["disclaimer"], DISCLAIMER_SHORT);
        let sections = v["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 16);
        assert_eq!(sections[0]["index"], 1);
        assert!(!sections[0]["heading"].as_str().unwrap().is_empty());
        assert!(v["privacy_banner"].is_string(), "private + xpub → banner");

        let public =
            owner_template_data_json(template, &data, PageSize::A4, RedactionMode::PublicSafe);
        let pv: serde_json::Value = serde_json::from_str(&public).unwrap();
        assert!(pv["privacy_banner"].is_null(), "public-safe → no banner");
    }

    #[test]
    fn owner_typ_source_selects_distinct_templates() {
        let single = owner_typ_source(OwnerTemplate::SinglesigBasic);
        let multi = owner_typ_source(OwnerTemplate::Multisig3of5);
        assert!(single.contains("single-signature wallet"));
        assert!(multi.contains("3-of-5 multisignature wallet"));
        assert_ne!(single, multi);
        // Every owner template resolves to its own non-empty source.
        for template in OwnerTemplate::ALL {
            assert!(owner_typ_source(template).contains("json(\"data.json\")"));
        }
    }

    #[test]
    fn owner_auto_backend_falls_back_to_printpdf_when_typst_missing() {
        let engine = RunbookEngine::new().with_typst_binary("/nonexistent/lifeboat-typst-binary");
        let data = owner_sample_data(OwnerTemplate::SinglesigBasic);
        let pdf = engine
            .render_owner_pdf(
                OwnerTemplate::SinglesigBasic,
                &data,
                PdfBackend::Auto,
                PageSize::A4,
                RedactionMode::PublicSafe,
            )
            .expect("auto falls back to printpdf");
        assert_valid_pdf(&pdf);
    }

    // --- Typst subprocess plumbing (Unix: drive a fake `typst` binary) --------

    #[cfg(unix)]
    fn write_fake_typst(dir: &std::path::Path, script_body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-typst.sh");
        std::fs::write(&path, script_body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[cfg(unix)]
    fn unique_test_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lifeboat-runbook-test-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn typst_subprocess_success_path_captures_output() {
        // A fake `typst` that writes a minimal PDF to its last argument (the
        // output path) proves the subprocess + output-file plumbing end to end.
        let dir = unique_test_dir("ok");
        let script = "#!/bin/sh\nout=\"$(eval echo \\${$#})\"\nprintf '%%PDF-1.7\\n1 0 obj<<>>endobj\\ntrailer<<>>\\n%%%%EOF' > \"$out\"\n";
        let fake = write_fake_typst(&dir, script);
        let engine = RunbookEngine::new().with_typst_binary(fake);
        let pdf = engine
            .render_pdf(
                &sample_template(),
                PdfBackend::Typst,
                PageSize::A4,
                RedactionMode::PublicSafe,
            )
            .expect("fake typst succeeds");
        assert!(pdf.starts_with(b"%PDF"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn typst_timeout_is_bounded_and_does_not_hang() {
        // A fake `typst` that sleeps far longer than the timeout must be killed
        // and surface an error promptly — never hang.
        let dir = unique_test_dir("timeout");
        let fake = write_fake_typst(&dir, "#!/bin/sh\nsleep 10\n");
        let engine = RunbookEngine::new()
            .with_typst_binary(fake)
            .with_timeout(Duration::from_millis(150));
        let start = std::time::Instant::now();
        let err = engine
            .render_pdf(
                &sample_template(),
                PdfBackend::Typst,
                PageSize::A4,
                RedactionMode::PublicSafe,
            )
            .expect_err("a timed-out render must error");
        let elapsed = start.elapsed();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(elapsed < Duration::from_secs(3), "timeout was not bounded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- US-033: heir / workshop / business templates ----------------------

    fn heir_sample_data(template: HeirTemplate) -> RunbookData {
        let (script, threshold, n): (&str, Option<u32>, u32) = match template {
            HeirTemplate::HeirMultisig2of3 | HeirTemplate::BusinessTreasury => {
                ("wsh(sortedmulti)", Some(2), 3)
            }
            HeirTemplate::HeirMultisig3of5 => ("wsh(sortedmulti)", Some(3), 5),
            HeirTemplate::LianaTimelock => ("wsh(or_d timelock)", None, 2),
            _ => ("wpkh", None, 1),
        };
        let count = if template.is_liana_timelock() {
            n
        } else {
            threshold.map_or(1, |_| n)
        };
        let signers: Vec<Signer> = (0..count)
            .map(|i| {
                let label = format!("Signer {}", (b'A' + i as u8) as char);
                let fp = format!("{:08x}", 0x2222_2222_u32.wrapping_mul(i + 1));
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
            "wsh(sortedmulti(2,[22222222/48h/1h/0h/2h]tpubD6NzVbExampleHeirPdfKey00000000000000000000000000000000000000000000000000000000000/0/*))#dddddddd"
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

    #[test]
    fn heir_pdf_sha256_table_is_stable() {
        // Render every heir/workshop/business template in both modes via the
        // deterministic printpdf fall-back; assert each is a valid, byte-stable
        // PDF and pin it BY HASH (PRD §19/§27; AC "compiles to PDF"). Regenerate
        // with `INSTA_UPDATE=always cargo +1.78.0 test -p runbook-engine`.
        let mut table = String::new();
        for template in HeirTemplate::ALL {
            let data = heir_sample_data(template);
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let pdf =
                    render_heir_pdf(template, &data, PdfBackend::Printpdf, PageSize::A4, mode)
                        .expect("printpdf renders the heir runbook");
                assert_valid_pdf(&pdf);
                let again =
                    render_heir_pdf(template, &data, PdfBackend::Printpdf, PageSize::A4, mode)
                        .unwrap();
                assert_eq!(pdf, again, "heir PDF render is not byte-deterministic");
                table.push_str(&format!(
                    "{:<26} {:<12} {}\n",
                    template.name(),
                    owner_mode_label(mode),
                    sha256_hex(&pdf)
                ));
            }
        }
        insta::assert_snapshot!("heir_pdf_sha256", table);
    }

    #[test]
    fn heir_typ_source_selects_distinct_templates() {
        let mut seen = std::collections::HashSet::new();
        for template in HeirTemplate::ALL {
            let src = heir_typ_source(template);
            assert!(src.contains("json(\"data.json\")"));
            assert!(
                src.contains(template.name()),
                "{} source missing its name",
                template.name()
            );
            assert!(
                seen.insert(src),
                "{} shares a source with another template",
                template.name()
            );
        }
    }

    #[test]
    fn heir_template_data_json_carries_disclaimer_and_sections() {
        let template = HeirTemplate::HeirSinglesigBasic;
        let data = heir_sample_data(template);
        let json = heir_template_data_json(template, &data, PageSize::A4, RedactionMode::Private);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["template"], "heir-singlesig-basic");
        assert_eq!(v["heir_disclaimer"], DISCLAIMER_HEIR);
        assert!(v["glossary"].as_array().unwrap().len() >= 4);
        assert_eq!(v["sections"].as_array().unwrap().len(), 16);

        let workshop = HeirTemplate::MeetupWorkshop;
        let wjson = heir_template_data_json(
            workshop,
            &heir_sample_data(workshop),
            PageSize::A4,
            RedactionMode::PublicSafe,
        );
        let wv: serde_json::Value = serde_json::from_str(&wjson).unwrap();
        assert!(
            wv["heir_disclaimer"].is_null(),
            "the workshop runbook is not heir-facing"
        );
        assert!(wv["glossary"].as_array().unwrap().is_empty());
    }

    #[test]
    fn liana_timelock_typst_template_is_complete() {
        assert!(LIANA_TIMELOCK_TYP.contains("json(\"data.json\")"));
        assert!(LIANA_TIMELOCK_TYP.contains("liana-timelock"));
        assert!(LIANA_TIMELOCK_TYP.to_lowercase().contains("liana"));
        assert!(!LIANA_TIMELOCK_TYP.to_lowercase().contains("stub"));
    }
}
