# Signet Practice

Signet is a Bitcoin test network for rehearsals. Lifeboat uses it only when you
choose a Signet practice flow and confirm any network action. Regtest remains the
offline default for deterministic drills.

## What Signet Is For

Use Signet when you want practice coins, real network latency, and a transaction
ID that can be checked on a public Signet explorer. Use regtest when you want the
same drill without any external network call.

Signet coins have no mainnet value. They are useful for rehearsing the mechanics
of receiving, spending, signing, finalizing, and optionally broadcasting a test
transaction.

## Network Boundary

Lifeboat does not connect to Signet in the background. The app may open the
Signet faucet in your system browser when you click the faucet action. Broadcast
is a separate action, and the confirmation names the endpoint before the Rust
command runs:

```text
Network call to https://mutinynet.com/api/tx
```

The broadcast helper has only Signet endpoints. There is no mainnet endpoint in
the type used by the command.

## Practice Mode Steps

1. Open Practice Mode.
2. Choose `signet`.
3. Start the drill and copy the receive address.
4. Use the faucet link in your browser to request Signet coins.
5. Run the local send drill once the practice wallet has funding.
6. Review the unsigned PSBT, signed PSBT, finalized transaction ID, fee, and
   broadcast availability.
7. Broadcast only if you want a public Signet transaction.
8. Save the drill result only if you want a local signed record.

The drill result is a public summary. It does not include the PSBT, transaction
hex, descriptor, xpubs, addresses, or seed material.

## CLI Checks

After exporting or receiving a PSBT file, inspect it with:

```sh
lifeboat psbt inspect --file updated.psbt --network signet
```

For JSON automation:

```sh
lifeboat --json psbt validate --file updated.psbt --network signet
```

The CLI does not broadcast. Its PSBT commands are for local inspection,
validation, and finalized transaction extraction.

## Troubleshooting

- If the faucet page does not fund the address, wait a few minutes and try again
  or use regtest instead.
- If fee data is unknown, the PSBT does not include UTXO data for every input.
- If `extract-tx` refuses the file, the PSBT is not finalized yet.
- If you need to sign with real hardware, use your wallet's file-based PSBT flow.
  Lifeboat's hardware-wallet drills begin in the v0.3/v0.4 milestones.
