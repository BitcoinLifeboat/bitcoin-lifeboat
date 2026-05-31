# What a descriptor is

A wallet is more than a seed phrase. To rebuild your wallet, recovery software
also needs to know *how* your wallet turns keys into addresses. That recipe is
called an **output descriptor**.

Think of the seed phrase as the key to a lock, and the descriptor as the
blueprint that says which lock the key opens, and how many locks there are.

## Why the seed phrase alone may not be enough

For a simple single-signature wallet, good software can often guess the recipe.
For anything more complex — multisig, passphrases, custom paths, timelocks — the
seed phrase by itself is not enough. Without the descriptor, an heir may hold the
keys and still be unable to find the coins.

This is the gap Bitcoin Lifeboat is built to close: it checks that you have a
complete, correct descriptor written down alongside your keys.

## What a descriptor looks like

A descriptor is a line of text. A simple one looks like this:

```
wpkh([d34db33f/84h/0h/0h]xpub6.../0/*)#checksum
```

Reading it left to right:

- `wpkh(...)` is the **script type** — here, native SegWit single-sig.
- `[d34db33f/84h/0h/0h]` is the **key origin** — the fingerprint of the master
  key plus the derivation path.
- `xpub6...` is the **extended public key** (xpub). It is public, but it is
  sensitive — see [What an xpub reveals](xpub).
- `/0/*` says how to walk through receive and change addresses.
- `#checksum` is an 8-character error-detecting code. A wrong character makes the
  whole descriptor fail to load, which protects you from silent corruption.

A descriptor contains **public** information only. It does not contain your seed
phrase or any private key. Even so, treat it as private: see
[Staying safe](safety) and the [glossary](glossary) for the terms above.
