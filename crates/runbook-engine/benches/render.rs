//! Criterion micro-benchmark for the printpdf render path.
//!
//! US-031 AC4: the largest MVP template must render in well under 3 s. This
//! bench measures it; the deterministic `cargo test` gate also enforces the
//! bound via `largest_template_renders_under_3s` (printpdf renders in
//! milliseconds, so the budget is met with a wide margin).

use criterion::{criterion_group, criterion_main, Criterion};
use runbook_engine::{
    render_base_pdf, BaseTemplate, PageSize, PdfBackend, RedactionMode, RunbookFooter,
};

fn bench_render_base(c: &mut Criterion) {
    let lines: Vec<String> = (0..400)
        .map(|i| format!("Recovery step {i}: verify this item against your backup materials."))
        .collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let template = BaseTemplate {
        title: "Largest MVP Runbook",
        body: &refs,
        footer: RunbookFooter {
            lifeboat_version: "0.1.0",
            report_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        },
    };

    c.bench_function("render_base_pdf/printpdf/a4", |b| {
        b.iter(|| {
            render_base_pdf(
                &template,
                PdfBackend::Printpdf,
                PageSize::A4,
                RedactionMode::PublicSafe,
            )
            .expect("printpdf render")
        });
    });
}

criterion_group!(benches, bench_render_base);
criterion_main!(benches);
