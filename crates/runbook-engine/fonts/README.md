# Bundled runbook fonts

The Typst rendering path (`runbook-engine`) embeds two fonts into every PDF:

| Role            | Font           | License            |
| --------------- | -------------- | ------------------ |
| Body / headings | Inter          | SIL Open Font 1.1  |
| Code / hashes   | JetBrains Mono | SIL Open Font 1.1  |

Both are [SIL OFL 1.1](https://openfontlicense.org/) licensed, which permits
bundling and redistribution.

## Why the `.ttf` files are not committed here

This directory holds **only this README** in the source tree. The font binaries
— like the `typst` binary itself — are large and are fetched and placed here by
the release/packaging pipeline (US-064), not committed to git. The renderer
points Typst at this directory with `--font-path`:

```
typst compile --root <tmp> --font-path crates/runbook-engine/fonts base.typ out.pdf
```

At runtime the engine resolves the font directory next to the application
binary, or via `RunbookEngine::with_fonts_dir(...)`. If a font file is missing,
Typst substitutes a default face and the render still succeeds — and the
pure-Rust **printpdf fallback** (used whenever the `typst` binary is absent) uses
the standard PDF base-14 fonts (Helvetica / Courier) and needs no font files at
all.

## Populating this directory

The packaging step downloads the upstream releases and drops the regular and
bold/mono faces here, e.g.:

```
fonts/
  Inter-Regular.ttf
  Inter-Bold.ttf
  JetBrainsMono-Regular.ttf
  OFL.txt            # the upstream license text, redistributed verbatim
```
