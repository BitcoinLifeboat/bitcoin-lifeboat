# Bitcoin Lifeboat error catalog (en)
# Generated from the stable ErrorCode catalog shape; edit values, not keys.

errors-E-INPUT-001 =
    .title = Empty input
    .description = No descriptor or file was provided.
    .action = Paste a descriptor or choose a file.

errors-E-INPUT-002 =
    .title = Input too large
    .description = The file exceeds the 10 MB limit.
    .action = Trim the file or contact support if it should be smaller.

errors-E-INPUT-003 =
    .title = Invalid file format
    .description = The file's content does not match any known wallet export format.
    .action = Confirm the file is a descriptor (.txt, .json) or supported wallet export.

errors-E-PARSE-001 =
    .title = Descriptor cannot be parsed
    .description = The text you provided is not a valid BIP380 descriptor.
    .action = Confirm you copied the full descriptor including any leading `wsh(`/`wpkh(`. If you're unsure, see the per-wallet export instructions.

errors-E-PARSE-002 =
    .title = Descriptor checksum missing
    .description = BIP380 descriptors should include a `#xxxxxxxx` checksum.
    .action = Add the checksum (Lifeboat can compute one) or re-export from your wallet.

errors-E-PARSE-003 =
    .title = Descriptor checksum invalid
    .description = The descriptor's checksum does not match its content. The descriptor may have been transcribed incorrectly.
    .action = Re-export the descriptor from your wallet software.

errors-E-PARSE-004 =
    .title = Descriptor mixes networks
    .description = The descriptor contains keys from multiple Bitcoin networks (e.g., mainnet and testnet).
    .action = This is almost always a mistake. Re-export the descriptor and verify it contains only mainnet keys (or only testnet, if intentional).

errors-E-PARSE-005 =
    .title = Descriptor contains private keys
    .description = The descriptor includes an extended private key (xprv/yprv/zprv/tprv/uprv/vprv) or a raw private key. Lifeboat refuses to process descriptors that contain secret material.
    .action = Re-export the descriptor in watch-only form (xpub instead of xprv).

errors-E-PARSE-006 =
    .title = Unsupported descriptor function
    .description = The descriptor uses a function Lifeboat does not yet support in this version (e.g., raw(), addr()).
    .action = Use a wallet that exports a supported descriptor (wpkh, wsh, sh(wpkh), multi, sortedmulti).

errors-E-PARSE-007 =
    .title = Multisig threshold exceeds key count
    .description = The descriptor specifies M-of-N where M > N, which can never be satisfied.
    .action = Confirm the descriptor; this likely indicates a transcription error.

errors-E-SECRET-001 =
    .title = BIP39 mnemonic detected
    .description = The input contains a sequence of words matching a BIP39 wordlist with a valid checksum. Lifeboat does not accept seed phrases.
    .action = Export the OUTPUT DESCRIPTOR (not the seed) from your wallet software and paste it instead.

errors-E-SECRET-002 =
    .title = Possible BIP39 mnemonic detected
    .description = The input contains a sequence of BIP39 words; the checksum did not validate but the pattern is suspicious.
    .action = If you intended to paste a descriptor and this is a false positive, type "I confirm this is not a real seed" to proceed.

errors-E-SECRET-003 =
    .title = Private key (WIF) detected
    .description = The input matches the WIF private key format. Lifeboat does not accept private keys.
    .action = Use the corresponding public key or xpub instead.

errors-E-SECRET-004 =
    .title = Extended private key detected
    .description = The input contains an xprv / yprv / zprv / tprv / uprv / vprv. Lifeboat does not accept extended private keys.
    .action = Use the corresponding xpub / ypub / zpub / tpub / upub / vpub instead.

errors-E-SECRET-005 =
    .title = SLIP-39 share detected
    .description = The input appears to be a SLIP-39 Shamir backup share.
    .action = Lifeboat does not need SLIP-39 shares. Use your wallet's output descriptor.

errors-E-SECRET-006 =
    .title = codex32 secret detected
    .description = The input appears to be a codex32 (BIP-93) secret.
    .action = Lifeboat does not need codex32 secrets. Use your wallet's output descriptor.

errors-E-SECRET-007 =
    .title = Possible raw private key detected
    .description = The input contains a 64-character hex string in a suspicious context (e.g., adjacent to the word "private" or "key").
    .action = Confirm this is not a private key. If you intended a transaction ID or block hash, it should not appear in this field.

errors-E-FS-001 =
    .title = File not found
    .description = The file path you provided does not exist or is not readable.
    .action = Verify the path and permissions, then try again.

errors-E-FS-002 =
    .title = Cannot write to destination
    .description = The destination path is not writable.
    .action = Choose a different destination or check permissions.

errors-E-FS-003 =
    .title = Destination file exists
    .description = A file already exists at the destination.
    .action = Confirm overwrite or choose a different name.

errors-E-NETWORK-001 =
    .title = Network unreachable
    .description = The user-initiated network call failed.
    .action = Verify your internet connection or try again later.

errors-E-NETWORK-002 =
    .title = Unexpected network call attempted
    .description = Internal: A component attempted a network call without explicit user action.
    .action = This is a bug. Please file an issue at the GitHub repository.

errors-E-DEP-001 =
    .title = Typst not bundled
    .description = PDF generation requires the bundled Typst binary, which was not found.
    .action = Reinstall Lifeboat. If the issue persists, file an issue.

errors-E-DEP-002 =
    .title = HWI not available
    .description = Hardware wallet operations require the HWI sidecar binary (v0.4+), which was not found.
    .action = Reinstall the version of Lifeboat that includes HWI, or use file-based PSBT.

errors-E-LINK-001 =
    .title = External link not allowed
    .description = The link is not in the project's allowlist of external URLs.
    .action = Verify the link manually in your browser if you trust it.

errors-E-INTERNAL-001 =
    .title = Unexpected error
    .description = An unexpected internal error occurred.
    .action = Please file an issue at the GitHub repository with the reproduction steps.

errors-E-INTERNAL-002 =
    .title = Schema migration required
    .description = The settings file uses a format from an older version of Lifeboat.
    .action = Lifeboat will attempt to migrate. If that fails, delete the settings file.

