# Flatpak Manifest

`org.bitcoinlifeboat.BitcoinLifeboat.json` is the v0.2 Flatpak manifest. It is
kept as JSON so the packaging gate can validate it with the Python standard
library in CI.

The manifest expects a release-produced Flatpak source archive containing:

- `bitcoin-lifeboat`
- `org.bitcoinlifeboat.BitcoinLifeboat.desktop`
- `org.bitcoinlifeboat.BitcoinLifeboat.metainfo.xml`

The archive URL and checksum use placeholders during alpha work. Replace them
when cutting a concrete release.
