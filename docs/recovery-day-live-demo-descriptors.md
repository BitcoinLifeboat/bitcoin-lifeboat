# Recovery Day Live Demo Descriptors

Use these samples for public demos. They are testnet/regtest-oriented fixtures
from the source tree, not participant wallets.

Do not paste a real seed phrase, passphrase, private key, or xprv into Lifeboat.
If a participant wants to test their own wallet, they should do it privately on
their own machine.

## Singlesig Descriptor

Source fixture: `fixtures/descriptors/singlesig/wpkh_valid.txt`

```text
wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/0/*)#r6yctejg
```

Known receive address fixture: `fixtures/addresses/known_match_tb1.txt`

```text
tb1q8ke5xqhsyqydxk9jkkrn83f6ltp7edst4xv2ar2xlqdry2g8588qpqjjdj
```

Demo use:

1. Paste the descriptor into the Readiness Check.
2. Select a singlesig wallet type.
3. Paste the known address when the app asks for address comparison.
4. Export a public-safe report.

## 2-of-3 Multisig Descriptor

Source fixture: `fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt`

```text
wsh(sortedmulti(2,[4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/0/*,[6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/0/*,[8dfc9b34/48'/1'/0'/2']tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq/0/*))#c2yhzrq7
```

Demo use:

1. Select a 2-of-3 multisig wallet type.
2. Run the Readiness Check without a known address first.
3. Show how the report distinguishes parsed quorum facts from missing external
   evidence.
4. Open the multisig survivability drill and simulate losing signer 2.

## Liana Timelock Descriptor

Source fixture: `fixtures/descriptors/timelock/liana_basic.txt`

```text
wsh(or_d(pk([4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/<0;1>/*),and_v(v:pkh([6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/<0;1>/*),older(65535))))#d3zjscz4
```

Demo use:

1. Select the Liana sample in the Readiness wizard.
2. Enter a current block height by hand.
3. Show the redacted recovery tree and countdown.
4. Open the Liana timelock runbook template.

## Facilitator Notes

- These descriptors contain xpubs, not private keys.
- Do not edit the checksum during a demo unless you want to show checksum
  failure.
- Do not use mainnet addresses in public demos.
- If someone wants to test a wallet export from their own wallet, move them out
  of the public demo flow.
