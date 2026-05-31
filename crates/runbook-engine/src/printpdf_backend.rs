//! Pure-Rust **printpdf** fall-back backend (US-031).
//!
//! Produces a byte-deterministic PDF with no external binary and no font files
//! (it uses the PDF base-14 fonts), so it always works — `cargo test` exercises
//! this path because `typst` is not installed in dev/CI.
//!
//! ## Determinism (PRD §19/§27: same input → byte-identical output)
//! printpdf emits three clock/random fields that must be neutralized:
//!
//! - `/CreationDate`, `/ModDate`, and the XMP metadata date all default to
//!   `OffsetDateTime::now_utc()` → pinned to the Unix epoch via
//!   [`with_creation_date`](printpdf::PdfDocumentReference::with_creation_date) /
//!   `with_mod_date` / `with_metadata_date`.
//! - the document uses [`PdfConformance::default`] (`requires_xmp_metadata =
//!   false`), so no XMP packet (which carries its own random ids) is written.
//! - the trailer `/ID` is `[document_id, instance_id]`, both
//!   `random_character_string_32()` with no public setter. After
//!   `save_to_bytes` the PDF is reloaded through printpdf's re-exported
//!   [`lopdf`](printpdf::lopdf) and `/ID` is rewritten to a fixed constant.
//!   lopdf serializes objects in id order, so the reparse + re-save is itself
//!   deterministic.
//!
//! The output is locked by SHA256 (`PINNED_A4_PUBLIC_SHA256`) and by
//! twice-rendered byte equality in the crate tests.

use error_taxonomy::{ErrorCode, LifeboatError};
use printpdf::{BuiltinFont, Mm, PdfConformance, PdfDocument};
use report_engine::{RedactionMode, DISCLAIMER_SHORT};
use time::OffsetDateTime;

use crate::{redaction_label, BaseTemplate, PageSize};

// Layout constants, in millimetres. printpdf's coordinate origin is the
// bottom-left corner and y increases upward.
const MARGIN_X: f32 = 20.0;
const TITLE_SIZE: f32 = 18.0;
const BODY_SIZE: f32 = 11.0;
const FOOTER_SIZE: f32 = 7.0;
const BODY_LINE_HEIGHT: f32 = 6.0;
const FOOTER_LINE_HEIGHT: f32 = 4.0;
/// Distance from the top edge down to the title / continuation baseline.
const TOP_OFFSET: f32 = 25.0;
/// Baseline of the version/hash footer line, measured up from the bottom edge.
const FOOTER_BASE: f32 = 12.0;

/// printpdf errors are structural (font/layout/serialization). They are **not**
/// chained into the `LifeboatError`: a private-mode runbook embeds confidential
/// descriptor/xpub text, and the §13 secret-hygiene rule forbids copying any
/// such material into an error message or a log.
fn pdf_error(_e: printpdf::Error) -> LifeboatError {
    LifeboatError::new(ErrorCode::Internal).with_context("printpdf PDF generation failed")
}

/// Render `template` to deterministic PDF bytes.
pub(crate) fn render(
    template: &BaseTemplate,
    page_size: PageSize,
    mode: RedactionMode,
) -> Result<Vec<u8>, LifeboatError> {
    let (w, h) = page_size.dimensions_mm();
    let (doc, first_page, first_layer) = PdfDocument::new(template.title, Mm(w), Mm(h), "Layer 1");

    // Pin every clock-derived field to a fixed instant (determinism).
    let epoch = OffsetDateTime::UNIX_EPOCH;
    let doc = doc
        .with_creation_date(epoch)
        .with_mod_date(epoch)
        .with_metadata_date(epoch)
        .with_producer(format!(
            "Bitcoin Lifeboat {}",
            template.footer.lifeboat_version
        ))
        .with_conformance(PdfConformance::default());

    let regular = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(pdf_error)?;
    let bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(pdf_error)?;
    let mono = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(pdf_error)?;

    // Word-wrap the body to the printable width so long lines never overflow.
    let max_chars = body_chars_per_line(w);
    let wrapped = wrap_body(template.body, max_chars);

    // Title on the first page.
    {
        let layer = doc.get_page(first_page).get_layer(first_layer);
        layer.use_text(
            template.title,
            TITLE_SIZE,
            Mm(MARGIN_X),
            Mm(h - TOP_OFFSET),
            &bold,
        );
    }

    // Body lines, paginating downward. The footer zone is reserved at the bottom.
    let body_top = h - TOP_OFFSET - 12.0;
    let body_bottom = FOOTER_BASE + FOOTER_LINE_HEIGHT * 4.0 + 6.0;
    let mut pages = vec![(first_page, first_layer)];
    let mut layer = doc.get_page(first_page).get_layer(first_layer);
    let mut y = body_top;
    for line in &wrapped {
        if y < body_bottom {
            let (p, l) = doc.add_page(Mm(w), Mm(h), "Layer 1");
            pages.push((p, l));
            layer = doc.get_page(p).get_layer(l);
            y = h - TOP_OFFSET;
        }
        layer.use_text(line.as_str(), BODY_SIZE, Mm(MARGIN_X), Mm(y), &regular);
        y -= BODY_LINE_HEIGHT;
    }

    // Footer on every page: the verbatim §15.6 short disclaimer, then a status
    // line carrying the version, export mode, and report hash. ASCII only — the
    // base-14 fonts and the determinism guarantee are simplest over ASCII.
    let footer_status = format!(
        "Bitcoin Lifeboat v{} - {} - Report hash: {}",
        template.footer.lifeboat_version,
        redaction_label(mode),
        template.footer.report_hash
    );
    let disclaimer_lines: Vec<&str> = DISCLAIMER_SHORT.lines().collect();
    for (p, l) in &pages {
        let layer = doc.get_page(*p).get_layer(*l);
        layer.use_text(
            footer_status.as_str(),
            FOOTER_SIZE,
            Mm(MARGIN_X),
            Mm(FOOTER_BASE),
            &mono,
        );
        for (i, dline) in disclaimer_lines.iter().enumerate() {
            let from_bottom =
                FOOTER_BASE + FOOTER_LINE_HEIGHT * (disclaimer_lines.len() - i) as f32;
            layer.use_text(*dline, FOOTER_SIZE, Mm(MARGIN_X), Mm(from_bottom), &regular);
        }
    }

    let bytes = doc.save_to_bytes().map_err(pdf_error)?;
    finalize_deterministic(bytes)
}

/// Reload the rendered PDF and overwrite the random trailer `/ID` with a fixed
/// constant, neutralizing the last source of per-render variation.
fn finalize_deterministic(bytes: Vec<u8>) -> Result<Vec<u8>, LifeboatError> {
    use printpdf::lopdf::{Document as LoDoc, Object, StringFormat};

    let mut doc = LoDoc::load_mem(&bytes).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal).with_context("printpdf output failed to re-parse")
    })?;
    const FIXED_ID: &[u8] = b"00000000000000000000000000000000";
    let id = Object::String(FIXED_ID.to_vec(), StringFormat::Literal);
    doc.trailer.set("ID", Object::Array(vec![id.clone(), id]));
    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("deterministic PDF re-serialization failed")
    })?;
    Ok(out)
}

/// The approximate number of characters that fit on one body line at
/// [`BODY_SIZE`] within the printable width (Helvetica's average advance is
/// ≈ 0.5 em). Conservative by design — a slightly short estimate only wraps a
/// little earlier, it never overflows the page.
fn body_chars_per_line(width_mm: f32) -> usize {
    let usable = width_mm - 2.0 * MARGIN_X;
    let pt_per_char = BODY_SIZE * 0.5;
    let mm_per_char = pt_per_char * 0.352_778; // 1 pt = 0.352778 mm
    ((usable / mm_per_char).floor() as usize).max(20)
}

/// Greedy word-wrap each input line to at most `max_chars` characters, hard-
/// splitting any single word longer than `max_chars`. Operates on characters
/// (never byte indices) so multi-byte input cannot panic. Deterministic.
fn wrap_body(lines: &[&str], max_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    for &line in lines {
        if line.trim().is_empty() {
            out.push(String::new());
            continue;
        }
        let mut current = String::new();
        let mut current_len = 0usize; // in characters
        for word in line.split_whitespace() {
            let wlen = word.chars().count();
            if wlen > max_chars {
                if current_len > 0 {
                    out.push(std::mem::take(&mut current));
                    current_len = 0;
                }
                let mut chunk = String::new();
                let mut clen = 0usize;
                for ch in word.chars() {
                    chunk.push(ch);
                    clen += 1;
                    if clen == max_chars {
                        out.push(std::mem::take(&mut chunk));
                        clen = 0;
                    }
                }
                if clen > 0 {
                    current = chunk;
                    current_len = clen;
                }
                continue;
            }
            let extra = if current_len == 0 { wlen } else { wlen + 1 };
            if current_len + extra > max_chars {
                out.push(std::mem::take(&mut current));
                current.push_str(word);
                current_len = wlen;
            } else {
                if current_len > 0 {
                    current.push(' ');
                }
                current.push_str(word);
                current_len += extra;
            }
        }
        out.push(current);
    }
    out
}
