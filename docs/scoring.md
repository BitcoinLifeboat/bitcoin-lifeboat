# Readiness Scoring

Readiness scoring turns descriptor and wallet facts into a status, a number, and
an audit trail. The score is not a statement about funds. It describes the
metadata and scenarios Lifeboat tested.

## Status Categories

| Status | Numeric range | Extra requirements |
| --- | --- | --- |
| Ready | 90-100 | No critical issues and a known address match |
| Mostly Ready | 70-89 | No critical issue forced a lower result |
| Needs Attention | 40-69 | No critical issue forced a lower result |
| Not Ready | 0-39, or any critical issue | Critical issue details explain why |
| Cannot Determine | Not numeric | Required information is missing or ambiguous |

`Ready` requires a known-address match. A high numeric score without that match
does not produce `Ready`.

## A-G Check Groups

| Group | Purpose |
| --- | --- |
| A | Descriptor parse, checksum, and normalization |
| B | Script type and declared wallet type |
| C | Key origin completeness and standard account paths |
| D | Multisig threshold, key count, sortedness, and duplicates |
| E | Receive/change descriptor coverage |
| F | Network determinability and user confirmation |
| G | Address derivation and known-address match |

Checks are emitted in a fixed order so reports are deterministic.

## Critical Issues

Any critical issue forces `Not Ready`:

| Code | Meaning |
| --- | --- |
| `C-DESC-PARSE-FAIL` | Descriptor failed to parse |
| `C-DESC-CHECKSUM-INVALID` | Descriptor checksum was present but invalid |
| `C-MULTISIG-NO-DESCRIPTOR` | User indicated multisig but provided no full descriptor |
| `C-MULTISIG-THRESHOLD-MISSING` | Multisig M-of-N could not be determined |
| `C-KEY-COUNT-BELOW-THRESHOLD` | Threshold exceeds key count |
| `C-DUPLICATE-XPUB` | Same xpub appears more than once |
| `C-ADDRESS-MISMATCH` | Known address did not match the derived range |
| `C-WALLET-TYPE-MISMATCH` | Declared wallet type contradicts the descriptor |
| `C-CHANGE-DESC-REQUIRED-MISSING` | A required change descriptor is missing |
| `C-PASSPHRASE-UNDOCUMENTED` | A passphrase exists but heir instructions omit that fact |
| `C-SECRET-DETECTED` | Sensitive-input detector found real secret material |
| `C-DESC-CONTAINS-XPRV` | Descriptor contains private-key material |

## Warning Weights

The numeric score starts at 100. Warnings subtract fixed weights and cannot by
themselves force `Not Ready`.

| Code | Trigger | Impact |
| --- | --- | --- |
| `W-NO-DESC-CHECKSUM` | Descriptor lacks a checksum | -5 |
| `W-NO-CHANGE-DESC` | Change descriptor not provided and descriptor is not multipath | -15 |
| `W-NO-BIRTH-HEIGHT` | Creation date or block height not documented | -5 |
| `W-NO-GAP-LIMIT` | Gap limit not documented | -3 |
| `W-NO-KNOWN-ADDRESS` | No known address supplied | -10 |
| `W-NO-PRINTED-BACKUP` | No printed descriptor backup confirmed | -8 |
| `W-NO-RECENT-DRILL` | No drill in the last 12 months, or no drill recorded | -10 |
| `W-NO-HEIR-INSTRUCTIONS` | No heir instructions written | -8 |
| `W-NO-EMERGENCY-CONTACT` | No emergency contact named | -3 |
| `W-NO-HW-TEST` | Hardware wallet has not signed recently | -8 |
| `W-SAME-LOCATION-BACKUP` | Backup and signing device are stored together | -10 |
| `W-WALLET-SW-UNDOCUMENTED` | Wallet software requirement not documented | -5 |
| `W-NO-MULTIPATH` | Singlesig uses separate descriptors instead of BIP389 multipath | -2 |

The report includes `scoring_audit`, which lists each warning in order, its
impact, and the running score after applying it.

## Cannot Determine

Lifeboat returns `Cannot Determine` when it lacks the information needed to make
a useful call. Common causes:

- A tpub descriptor with no user-selected network.
- Key origin information is entirely absent.
- An imported wallet export format is not recognized.
- The wizard was stopped before address comparison.

The report should say what is missing and how to provide it.

## Survivability

Multisig reports include an additional survivability section: lose one signer,
lose two signers, and lose descriptor backup. This is not a separate score. It is
context for M-of-N setups.

Singlesig wallets do not get a survivability score because a singlesig setup has
one signing path.

Timelock wallets add recovery-window context. Liana-style descriptors can show a
primary path, timelocked recovery paths, and a block-height countdown when you
enter the current block height. This context does not change the numeric score by
itself; it tells you when a recovery path can be rehearsed.

## What the Score Does Not Say

The score cannot verify physical backup locations, the condition of hardware
wallets, legal authority, tax consequences, or future wallet software behavior.
It reflects the inputs supplied and the checks Lifeboat ran.
