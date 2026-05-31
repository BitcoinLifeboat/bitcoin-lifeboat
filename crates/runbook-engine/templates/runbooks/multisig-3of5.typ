// Bitcoin Lifeboat — owner runbook: multisig-3of5 (US-032).
//
// Renders the sixteen §9.5 required sections for a 3-of-5 multisignature
// wallet, in public-safe (default) or private export mode, with labeled blank
// fields. This is the largest MVP owner template (five cosigners); the
// signer/device checklist (7) lists each cosigner's fingerprint and path (xpubs
// are never printed) and the verification steps (11) reflect the 3-of-5 quorum.
// The sections, blocks, and the optional §14.3 privacy banner are built by
// runbook-engine's `owner` module and delivered verbatim as `data.sections` /
// `data.privacy_banner` (the single source of truth shared with the Markdown
// and printpdf renderers). Reads everything from `data.json`; nothing from the
// clock or environment, so the render is reproducible (the engine also sets
// SOURCE_DATE_EPOCH=0). Inter / JetBrains Mono come via `--font-path`.
//
// data.json fields: title, template, page_size ("a4"|"us-letter"),
// lifeboat_version, report_hash, mode ("public-safe"|"private"), disclaimer
// (verbatim §15.6 short, footer), privacy_banner (string | none), sections
// (array of { index, heading, blocks: [{ kind, text, n }] }). block kinds:
// para | bullet | check | step | code.

#let data = json("data.json")

#set document(title: data.title, author: "Bitcoin Lifeboat")

#set page(
  paper: data.page_size,
  margin: (x: 20mm, top: 25mm, bottom: 24mm),
  footer: [
    #set text(size: 7pt)
    #set align(left)
    #data.disclaimer
    #linebreak()
    Bitcoin Lifeboat v#data.lifeboat_version - #data.mode - Report hash: #data.report_hash
  ],
)

#set text(font: ("Inter", "Helvetica", "Liberation Sans"), size: 11pt)
#show heading: set text(font: ("Inter", "Helvetica", "Liberation Sans"))

= #data.title

Recovery runbook for a 3-of-5 multisignature wallet.

#if data.privacy_banner != none {
  block(
    width: 100%,
    inset: 8pt,
    radius: 2pt,
    fill: rgb("#fff4e0"),
    stroke: 0.5pt + rgb("#c88c00"),
    text(size: 9pt, data.privacy_banner),
  )
}

#for section in data.sections {
  heading(level: 2)[#str(section.index). #section.heading]
  for b in section.blocks {
    if b.kind == "para" {
      par[#b.text]
    } else if b.kind == "bullet" {
      [- #b.text]
    } else if b.kind == "check" {
      [☐ #b.text]
    } else if b.kind == "step" {
      [#str(b.n). #b.text]
    } else if b.kind == "code" {
      raw(b.text, block: true)
    }
  }
}
