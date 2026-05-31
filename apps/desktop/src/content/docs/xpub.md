# What an xpub reveals

An **extended public key** (xpub) is the public part of one branch of your
wallet. Recovery software needs it to find your addresses. It cannot spend your
coins. But it is far from harmless.

## An xpub is a privacy bombshell

An xpub reveals **every** receive and change address for that branch of your
wallet — past, present, and future. Anyone who has your xpub can look up the
blockchain and see:

- your whole transaction history for that wallet,
- your current balance,
- and every new address you will ever use.

It cannot move your coins, but it removes your financial privacy completely.

## How Lifeboat handles xpubs

By default, every report and runbook is in **public-safe** mode. In this mode an
xpub is shortened to its first six and last four characters, like
`xpub66...X5tH`, so you can share the document with family or an adviser without
leaking your history.

You can switch a single export to **private** mode, which includes the full
xpub. The app asks you to confirm first, and it adds this warning to the top of
the document:

> This document contains an extended public key (xpub). An xpub reveals every
> receive and change address for this wallet, past and future. Anyone with this
> xpub can see your wallet's entire transaction history on the blockchain. Store
> this where you store your seed backup. Do not email it, do not upload it, do
> not share it on chat.

## Rules of thumb

- Store a full xpub the way you store a seed backup: offline, private, and
  access-controlled.
- Do not paste an xpub into a chat, an email, or a website.
- When in doubt, keep the export in public-safe mode.

See [Staying safe](safety) for the full safety checklist.
