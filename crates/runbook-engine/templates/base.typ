// Bitcoin Lifeboat — base runbook template (US-031).
//
// Rendered by the bundled `typst` binary (see `src/typst_cli.rs`). Every input
// comes from `data.json`, which `runbook-engine` writes next to this file; the
// template reads NOTHING from the environment or the clock, so the render is
// reproducible (the engine also passes SOURCE_DATE_EPOCH=0). The richer
// owner / heir / workshop / business templates (US-032/033) extend this same
// data shape.
//
// data.json fields:
//   title            string        — runbook title / document title
//   body             array<string> — body paragraphs, rendered in order
//   page_size        string        — "a4" or "us-letter"
//   lifeboat_version string        — application version (footer)
//   report_hash      string        — accompanying report hash (footer)
//   mode             string        — "public-safe" or "private" (footer)
//   disclaimer       string        — verbatim §15.6 short disclaimer (footer)

#let data = json("data.json")

#set document(title: data.title, author: "Bitcoin Lifeboat")

#set page(
  paper: data.page_size,
  margin: (x: 20mm, top: 25mm, bottom: 22mm),
  footer: [
    #set text(size: 7pt)
    #set align(left)
    #data.disclaimer
    #linebreak()
    Bitcoin Lifeboat v#data.lifeboat_version - #data.mode - Report hash: #data.report_hash
  ],
)

// Inter / JetBrains Mono are supplied via `--font-path`; fall back to the
// always-available base families if the bundle is absent.
#set text(font: ("Inter", "Helvetica", "Liberation Sans"), size: 11pt)
#show heading: set text(font: ("Inter", "Helvetica", "Liberation Sans"))

= #data.title

#for line in data.body [
  #line

]
