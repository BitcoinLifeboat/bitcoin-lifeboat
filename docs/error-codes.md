# Error Codes

Every user-facing failure has a stable code, severity, title, description, and
recommended action. Codes appear in CLI output, JSON, desktop errors, and i18n
keys as `errors.<CODE>`.

## Severity

| Severity | Meaning |
| --- | --- |
| `user_correctable` | The user can change the input or path and retry |
| `warning` | Non-fatal issue that may reduce readiness |
| `critical` | Serious issue that can force `Not Ready` |
| `security` | Secret material, unexpected network behavior, or link refusal |
| `internal` | Bug or environment fault the user cannot fix directly |

## Catalog

| Code | Severity | Title | Description | Action |
| --- | --- | --- | --- | --- |
| `E-INPUT-001` | `user_correctable` | Empty input | No descriptor or file was provided. | Paste a descriptor or choose a file. |
| `E-INPUT-002` | `user_correctable` | Input too large | The file exceeds the 10 MB limit. | Trim the file or contact support if it should be smaller. |
| `E-INPUT-003` | `user_correctable` | Invalid file format | The file's content does not match any known wallet export format. | Confirm the file is a descriptor (.txt, .json) or supported wallet export. |
| `E-PARSE-001` | `user_correctable` | Descriptor cannot be parsed | The text you provided is not a valid BIP380 descriptor. | Confirm you copied the full descriptor including any leading `wsh(`/`wpkh(`. If you're unsure, see the per-wallet export instructions. |
| `E-PARSE-002` | `warning` | Descriptor checksum missing | BIP380 descriptors should include a `#xxxxxxxx` checksum. | Add the checksum (Lifeboat can compute one) or re-export from your wallet. |
| `E-PARSE-003` | `critical` | Descriptor checksum invalid | The descriptor's checksum does not match its content. The descriptor may have been transcribed incorrectly. | Re-export the descriptor from your wallet software. |
| `E-PARSE-004` | `critical` | Descriptor mixes networks | The descriptor contains keys from multiple Bitcoin networks (e.g., mainnet and testnet). | This is almost always a mistake. Re-export the descriptor and verify it contains only mainnet keys (or only testnet, if intentional). |
| `E-PARSE-005` | `critical` | Descriptor contains private keys | The descriptor includes an extended private key (xprv/yprv/zprv/tprv/uprv/vprv) or a raw private key. Lifeboat refuses to process descriptors that contain secret material. | Re-export the descriptor in watch-only form (xpub instead of xprv). |
| `E-PARSE-006` | `user_correctable` | Unsupported descriptor function | The descriptor uses a function Lifeboat does not yet support in this version (e.g., raw(), addr()). | Use a wallet that exports a supported descriptor (wpkh, wsh, sh(wpkh), multi, sortedmulti). |
| `E-PARSE-007` | `warning` | Multisig threshold exceeds key count | The descriptor specifies M-of-N where M > N, which can never be satisfied. | Confirm the descriptor; this likely indicates a transcription error. |
| `E-SECRET-001` | `security` | BIP39 mnemonic detected | The input contains a sequence of words matching a BIP39 wordlist with a valid checksum. Lifeboat does not accept seed phrases. | Export the OUTPUT DESCRIPTOR (not the seed) from your wallet software and paste it instead. |
| `E-SECRET-002` | `security` | Possible BIP39 mnemonic detected | The input contains a sequence of BIP39 words; the checksum did not validate but the pattern is suspicious. | If you intended to paste a descriptor and this is a false positive, type "I confirm this is not a real seed" to proceed. |
| `E-SECRET-003` | `security` | Private key (WIF) detected | The input matches the WIF private key format. Lifeboat does not accept private keys. | Use the corresponding public key or xpub instead. |
| `E-SECRET-004` | `security` | Extended private key detected | The input contains an xprv / yprv / zprv / tprv / uprv / vprv. Lifeboat does not accept extended private keys. | Use the corresponding xpub / ypub / zpub / tpub / upub / vpub instead. |
| `E-SECRET-005` | `security` | SLIP-39 share detected | The input appears to be a SLIP-39 Shamir backup share. | Lifeboat does not need SLIP-39 shares. Use your wallet's output descriptor. |
| `E-SECRET-006` | `security` | codex32 secret detected | The input appears to be a codex32 (BIP-93) secret. | Lifeboat does not need codex32 secrets. Use your wallet's output descriptor. |
| `E-SECRET-007` | `security` | Possible raw private key detected | The input contains a 64-character hex string in a suspicious context (e.g., adjacent to the word "private" or "key"). | Confirm this is not a private key. If you intended a transaction ID or block hash, it should not appear in this field. |
| `E-FS-001` | `user_correctable` | File not found | The file path you provided does not exist or is not readable. | Verify the path and permissions, then try again. |
| `E-FS-002` | `user_correctable` | Cannot write to destination | The destination path is not writable. | Choose a different destination or check permissions. |
| `E-FS-003` | `warning` | Destination file exists | A file already exists at the destination. | Confirm overwrite or choose a different name. |
| `E-NETWORK-001` | `user_correctable` | Network unreachable | The user-initiated network call failed. | Verify your internet connection or try again later. |
| `E-NETWORK-002` | `security` | Unexpected network call attempted | Internal: A component attempted a network call without explicit user action. | This is a bug. Please file an issue at the GitHub repository. |
| `E-DEP-001` | `internal` | Typst not bundled | PDF generation requires the bundled Typst binary, which was not found. | Reinstall Lifeboat. If the issue persists, file an issue. |
| `E-DEP-002` | `internal` | HWI not available | Hardware wallet operations require the HWI sidecar binary (v0.4+), which was not found. | Reinstall the version of Lifeboat that includes HWI, or use file-based PSBT. |
| `E-LINK-001` | `security` | External link not allowed | The link is not in the project's allowlist of external URLs. | Verify the link manually in your browser if you trust it. |
| `E-INTERNAL-001` | `internal` | Unexpected error | An unexpected internal error occurred. | Please file an issue at the GitHub repository with the reproduction steps. |
| `E-INTERNAL-002` | `internal` | Schema migration required | The settings file uses a format from an older version of Lifeboat. | Lifeboat will attempt to migrate. If that fails, delete the settings file. |

## Handling Secrets

For any `E-SECRET-*` code, do not paste the secret again. Use a watch-only output
descriptor or supported wallet export instead. If a real seed phrase or private
key may have been exposed on an untrusted machine, follow the incident steps in
[Safety model](safety-model.md).

