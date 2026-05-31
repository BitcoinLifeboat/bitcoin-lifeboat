# Configuration

`project.config.toml` at the repository root holds the deferred implementation choices
from PRD §30.6. It is the single source of truth for deployment-specific values. Every
later story reads from it; no story hardcodes the org, domain, disclosure route, or PGP key.

Three values ship as **placeholder tokens** because they depend on you. Builds proceed
normally with the placeholders in place — you can develop, test, and cut `alpha`/`beta`
releases without replacing them. **US-099 blocks any public (non-alpha/beta) release while
any placeholder token remains in the tree.**

## Values

| Key | Default / placeholder | Meaning |
| --- | --- | --- |
| `github.org` | `__GH_ORG__` *(placeholder)* | GitHub organization or user that owns the repo. Feeds the external-link allowlist and release URLs. |
| `github.repo` | `bitcoin-lifeboat` | Repository name. |
| `github.url_base` | `https://github.com/__GH_ORG__/bitcoin-lifeboat` | Base GitHub URL. Built from `org` + `repo`; the link allowlist (US-043) is generated from this. |
| `site.domain` | `bitcoinlifeboat.org` | Public site / docs domain. Part of the link allowlist. |
| `site.security_contact` | `GitHub private vulnerability reporting` | Disclosure route published in `SECURITY.md` for vulnerability reports. |
| `maintainer.pgp_fingerprint` | `__MAINTAINER_PGP_FINGERPRINT__` *(placeholder)* | 40-hex OpenPGP fingerprint used to verify release signatures. |
| `maintainer.pgp_key_block_file` | `__MAINTAINER_PGP_KEY_BLOCK__` *(placeholder)* | Path (relative to repo root) of the ASCII-armored public key block. |
| `code_signing.mode` | `conditional-on-ci-secrets` | Paid OS signing runs only when the matching CI secrets are present. |
| `code_signing.apple_notarization` | `deferred-to-beta` | Apple notarization is wired up at the beta milestone, once funded. |
| `code_signing.windows_ov_signing` | `deferred-to-beta` | Windows OV signing is wired up at the beta milestone, once funded. |
| `code_signing.minisign_and_cosign` | `always-on` | minisign + cosign signing is always enabled and needs no paid certificate. |
| `docs.framework` | `astro-starlight` | Documentation-site framework. |
| `docs.host` | `github-pages` | Documentation-site host. |
| `release.channel_default` | `alpha` | Default release channel. |
| `placeholders.tokens` | see file | Extra placeholder-shaped tokens US-099 scans for before allowing a public release. The three default tokens are also enforced by the gate. |

## Placeholder tokens

| Token | Replace with | Required before |
| --- | --- | --- |
| `__GH_ORG__` | Your GitHub org/user | Public (stable) release |
| `__MAINTAINER_PGP_FINGERPRINT__` | Your 40-hex PGP fingerprint | Public (stable) release |
| `__MAINTAINER_PGP_KEY_BLOCK__` | Path to your public key block file | Public (stable) release |

## Swap procedure

**Before Bitcoin Lifeboat is built** (editing the Ralph control plane): set the values in
`prd.json` under the top-level `projectConfig` object. US-001 materializes them into
`project.config.toml`.

**After the repository exists** (this repo):

1. Edit `project.config.toml` and set `github.org`, `maintainer.pgp_fingerprint`, and
   `maintainer.pgp_key_block_file` to real values. Update `github.url_base` to match the org.
2. Add the public key block file at the path you set in `maintainer.pgp_key_block_file`.
3. Grep the tree for any remaining tokens and replace them in generated/checked-in files:

   ```sh
   grep -rn -e __GH_ORG__ -e __MAINTAINER_PGP_FINGERPRINT__ -e __MAINTAINER_PGP_KEY_BLOCK__ .
   ```

4. When you fund OS code signing, add the Apple and Windows CI signing secrets and flip the
   relevant `code_signing.*` keys from `deferred-to-beta`.

Once no placeholder token remains and the security-audit sign-off is recorded, the
US-099 release gate permits a public stable release.
