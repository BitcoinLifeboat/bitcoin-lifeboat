# What Bitcoin Lifeboat is

Bitcoin Lifeboat is a local rehearsal and diagnostic tool. It helps you check
whether your Bitcoin recovery plan would actually work — *before* the day you
need it.

It runs entirely on your own computer. It makes no network requests on its own,
it never asks for your seed phrase, and it does not hold or move any coins.

## What it does

- Reads the **public** description of your wallet (its output descriptor or a
  watch-only export) and checks it for common mistakes.
- Gives you a plain-language **Readiness Check**: what passed, what needs
  attention, and what to do next.
- Helps you write a printable **recovery runbook** for yourself or your heirs,
  with blank lines you fill in by hand — never typed into the app.

## What it is not

- It is **not** a wallet. It cannot send, receive, or hold bitcoin.
- It does **not** tell you that your bitcoin is protected. No tool can promise
  that. It only tests the parts of a recovery plan that can be tested on paper.
- It does **not** ask for, store, or transmit any secret. If you ever paste seed
  words or a private key by accident, it stops and warns you — see
  [Staying safe](safety).

## Where to start

New to the words? Open the [glossary](glossary). Want to understand the single
most important input, the descriptor? Read [What a descriptor is](descriptors).

The full documentation, including per-wallet export guides, lives on the project
website: <https://bitcoinlifeboat.org/docs/>.
