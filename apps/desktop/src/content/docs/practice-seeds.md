# Practice Seeds

Practice Mode accepts only documented test mnemonics. Do not paste a real wallet
backup into Bitcoin Lifeboat.

## Canonical practice mnemonic

This is the default BIP39 test mnemonic shown in Practice Mode:

```text
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Use it only for disposable practice wallets on regtest or Signet. It is a public
test vector, so anyone can derive the same wallet.

## Why real seed phrases are blocked

Bitcoin Lifeboat is a watch-only recovery-readiness tool. It can check
descriptors, xpubs, fingerprints, known addresses, reports, and runbooks without
learning the words that spend your bitcoin.

If Practice Mode detects a checksum-valid BIP39 mnemonic that is not listed here,
it blocks the paste and leaves the field unchanged.
