// Bitcoin Lifeboat — heir-singlesig-basic runbook (US-033).
//
// Heir/workshop/business runbook. Renders the sixteen §9.5 sections plus, for
// heir runbooks, the verbatim §15.6 heir disclaimer and an inline glossary.
// Reads everything from data.json (nothing from the clock/environment), so the
// render is reproducible (the engine also sets SOURCE_DATE_EPOCH=0). data.json
// fields: title, subtitle, template, page_size ("a4"|"us-letter"),
// lifeboat_version, report_hash, mode ("public-safe"|"private"), disclaimer
// (verbatim §15.6 short, footer), heir_disclaimer (string|none), glossary
// (array of strings), privacy_banner (string|none), sections (array of
// { index, heading, blocks: [{ kind, text, n }] }). block kinds:
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

#emph(data.subtitle)

#if data.heir_disclaimer != none {
  block(
    width: 100%,
    inset: 8pt,
    radius: 2pt,
    fill: rgb("#eef6ff"),
    stroke: 0.5pt + rgb("#3b6fb0"),
    raw(data.heir_disclaimer, block: true),
  )
}

#if data.glossary.len() > 0 {
  heading(level: 2)[Words to know]
  for g in data.glossary [
    - #g
  ]
}

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
