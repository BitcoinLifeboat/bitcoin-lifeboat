# Debian Apt Channel

The release workflow already builds a Linux x86_64 `.deb`. The apt channel adds
the repository metadata needed for users who prefer normal Debian package
updates.

Install flow for a published channel:

```sh
curl -fsSL https://bitcoinlifeboat.org/apt/bitcoin-lifeboat-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/bitcoin-lifeboat-archive-keyring.gpg >/dev/null
sudo install -Dm644 bitcoin-lifeboat.sources /etc/apt/sources.list.d/bitcoin-lifeboat.sources
sudo apt update
sudo apt install bitcoin-lifeboat
```

Alpha metadata may still contain placeholder release checksums in adjacent
packaging files. Do not publish a non-alpha apt channel until US-099 confirms
that release placeholders have been replaced.
