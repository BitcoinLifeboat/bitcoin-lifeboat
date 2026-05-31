# Distribution Packaging

This directory holds the v0.2 distribution-channel metadata. The release
workflow still produces the signed installers and CLI archives; these files tell
package managers where those artifacts live and how users should install them.

Run the local packaging gate from the repository root:

```sh
scripts/verify-packaging.sh
```

The script validates the Homebrew formula syntax, parses the Flatpak manifest,
checks the Debian apt source metadata, and stages the files under
`target/packaging/channels/`. It does not sign or publish anything. Release
publishing still happens through the protected GitHub release workflow.

Placeholder tokens such as `__GH_ORG__` and `__SHA256_*__` are intentional in
alpha channel metadata. Before a public non-alpha release, replace them with the
configured repository owner and release checksums, then let US-099 enforce the
remaining placeholder gate.
