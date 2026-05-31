# Heir Mode

Heir mode helps an owner create instructions for a spouse, heir, executor, or
trusted helper. It does not give the heir custody by itself. It produces a
runbook that tells the heir what materials exist, what order to follow, and when
to stop and ask for help.

## What Goes Into a Heir Runbook

A runbook may include:

- Wallet type and high-level setup notes.
- Public-safe descriptor summary.
- Required materials.
- Blank lines for signer locations, helper names, and owner-specific notes.
- Steps for checking the plan without using mainnet funds.
- The heir disclaimer and scam warning.

Lifeboat does not collect seed words, passphrases, private keys, or signer
locations as free text. Location blanks are completed by the owner after
printing.

## Owner Flow

1. Choose a runbook template.
2. Optionally provide a watch-only descriptor or wallet export.
3. Confirm public-safe or private export mode.
4. Preview the runbook.
5. Export PDF, Markdown, text, or HTML.
6. Print, review, and complete blank fields by hand.
7. Store the runbook separately from seed words and hardware devices.

Private mode can include more wallet metadata. Use it only for a document kept
with the same care as the rest of the recovery package.

## Heir Flow

The heir should:

1. Read the first page slowly.
2. Gather only the materials named by the owner.
3. Avoid anyone who contacts them first and offers paid "unlock" help.
4. Use test networks or a guided drill first when possible.
5. Stop if a step asks for something not listed in the owner's plan.
6. Contact the trusted helper named by the owner.

The runbook must be clear enough to reduce panic, but it should not contain the
secret material that spends coins.

## Family Drill

A family drill should use fake funds or test-network funds. The goal is to
verify that the heir can find the runbook, identify the needed devices, recognize
the wallet software, and know when to ask for help.

Never ask an heir to type a real seed phrase into Lifeboat. Practice Mode in a
later milestone uses a documented test mnemonic only.

## Templates

Templates include singlesig and multisig owner runbooks, heir-focused variants,
and the Liana timelock runbook for inheritance-style recovery paths. The
`liana-timelock` template leaves blank fields for the primary path, recovery
path, block height, helper names, and next drill date.

See [CLI reference](cli-reference.md) for `lifeboat generate-runbook` and
[Safety model](safety-model.md) for storage guidance.
