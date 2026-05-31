#!/usr/bin/env bash
set -euo pipefail

script_path="${BASH_SOURCE[0]}"
repo_root="$(cd "$(dirname "${script_path}")/.." && pwd)"
tag_name=""
audit_signoff="docs/security-audit-signoff.json"
hardware_matrix="docs/hardware-wallet-device-matrix.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/verify-release-gates.sh --tag v1.0.0
  scripts/verify-release-gates.sh --self-test

Options:
  --tag TAG              Release tag to check, for example v1.0.0 or v0.9.0-beta.1.
  --repo-root DIR        Repository root. Defaults to this script's parent directory.
  --audit-signoff PATH   Audit sign-off JSON path, relative to repo root.
                         Defaults to docs/security-audit-signoff.json.
  --hardware-matrix PATH Hardware-wallet manual device matrix JSON path,
                         relative to repo root. Defaults to
                         docs/hardware-wallet-device-matrix.json.
  --self-test            Run the script's release-gate fixture tests.
USAGE
}

die() {
  echo "release gate failed: $*" >&2
  exit 1
}

classify_tag() {
  local tag="$1"

  if [[ ! "${tag}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)([-+][0-9A-Za-z.-]+)?$ ]]; then
    die "release tag must look like v1.0.0 or v0.9.0-alpha.1; got ${tag}"
  fi

  local major="${BASH_REMATCH[1]}"
  local version="${tag#v}"
  local prerelease=""

  if [[ "${version}" == *-* ]]; then
    prerelease="${version#*-}"
    prerelease="${prerelease%%+*}"
  fi

  if [[ "${prerelease}" =~ ^alpha(\.|$) ]]; then
    printf '%s:%s:%s\n' "${major}" "alpha" "false"
  elif [[ "${prerelease}" =~ ^beta(\.|$) ]]; then
    printf '%s:%s:%s\n' "${major}" "beta" "false"
  else
    printf '%s:%s:%s\n' "${major}" "stable" "true"
  fi
}

verify_audit_signoff() {
  local signoff_path="${repo_root}/${audit_signoff}"
  [[ -f "${signoff_path}" ]] || die "stable releases require ${audit_signoff}"

  python3 - "${signoff_path}" <<'PY'
import json
import re
import sys
from datetime import date
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"{path}: could not parse JSON: {exc}", file=sys.stderr)
    sys.exit(1)

errors = []
required_strings = ["auditor", "report_date", "scope", "report_sha256"]
for key in required_strings:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{key} must be a non-empty string")

if isinstance(data.get("report_date"), str):
    try:
        date.fromisoformat(data["report_date"])
    except ValueError:
        errors.append("report_date must be YYYY-MM-DD")

if isinstance(data.get("report_sha256"), str) and not re.fullmatch(r"sha256:[0-9a-f]{64}", data["report_sha256"]):
    errors.append("report_sha256 must be sha256:<64 lowercase hex characters>")

if data.get("status") != "complete":
    errors.append('status must be "complete"')

signoff = data.get("signoff")
if not isinstance(signoff, dict):
    errors.append("signoff must be an object")
else:
    if signoff.get("all_findings_remediated") is not True:
        errors.append("signoff.all_findings_remediated must be true")
    if signoff.get("stable_release_approved") is not True:
        errors.append("signoff.stable_release_approved must be true")

findings = data.get("findings")
if not isinstance(findings, list):
    errors.append("findings must be an array")
else:
    allowed = {"resolved", "not_applicable"}
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            errors.append(f"findings[{index}] must be an object")
            continue
        resolution = finding.get("resolution")
        if resolution not in allowed:
            identifier = finding.get("id", f"#{index}")
            errors.append(
                f"finding {identifier} resolution must be one of {sorted(allowed)}"
            )

if errors:
    print(f"{path}: audit sign-off is not complete:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)
PY
}

verify_no_placeholders() {
  python3 - "${repo_root}" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
config = root / "project.config.toml"
text = config.read_text(encoding="utf-8")

section_match = re.search(r"(?ms)^\[placeholders\]\s*(.*?)(?:^\[|\Z)", text)
if not section_match:
    print("project.config.toml is missing [placeholders]", file=sys.stderr)
    sys.exit(1)

tokens = [
    "__GH_ORG__",
    "__MAINTAINER_PGP_FINGERPRINT__",
    "__MAINTAINER_PGP_KEY_BLOCK__",
]
tokens_match = re.search(r"(?ms)^\s*tokens\s*=\s*\[(.*?)\]\s*$", section_match.group(1))
if tokens_match:
    configured = re.findall(r'"([^"]+)"', tokens_match.group(1))
    tokens.extend(token for token in configured if re.fullmatch(r"__[A-Z0-9_]+__", token))
tokens = list(dict.fromkeys(tokens))

try:
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.split(b"\0")
except subprocess.CalledProcessError as exc:
    sys.stderr.write(exc.stderr.decode("utf-8", "replace"))
    sys.exit(exc.returncode)

matches = []
encoded = [(token, token.encode("utf-8")) for token in tokens]
for raw in tracked:
    if not raw:
        continue
    rel = raw.decode("utf-8", "surrogateescape")
    path = root / rel
    if not path.is_file():
        continue
    try:
        content = path.read_bytes()
    except OSError:
        continue
    for token, token_bytes in encoded:
        if token_bytes in content:
            matches.append((rel, token))

if matches:
    print("public release still contains placeholder tokens:", file=sys.stderr)
    for rel, token in matches[:40]:
        print(f"  - {rel}: {token}", file=sys.stderr)
    if len(matches) > 40:
        print(f"  ... and {len(matches) - 40} more matches", file=sys.stderr)
    sys.exit(1)
PY
}

verify_hardware_matrix() {
  local matrix_path="${repo_root}/${hardware_matrix}"
  [[ -f "${matrix_path}" ]] || die "stable releases require ${hardware_matrix}"

  python3 - "${matrix_path}" <<'PY'
import json
import sys
from datetime import date
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"{path}: could not parse JSON: {exc}", file=sys.stderr)
    sys.exit(1)

errors = []
required_devices = {"trezor", "coldcard", "bitbox02", "jade", "ledger"}
placeholder_values = {"", "tbd", "pending", "unknown", "n/a"}

for key in ["schema_version", "app_version", "build_id", "tested_at"]:
    value = data.get(key)
    if not isinstance(value, str) or value.strip().lower() in placeholder_values:
        errors.append(f"{key} must be a non-placeholder string")

if isinstance(data.get("tested_at"), str):
    try:
        date.fromisoformat(data["tested_at"])
    except ValueError:
        errors.append("tested_at must be YYYY-MM-DD")

tests = data.get("manual_tests")
if not isinstance(tests, list) or not tests:
    errors.append("manual_tests must be a non-empty array")
    tests = []

passed_devices = set()
allowed_results = {"pass", "fail", "blocked"}
for index, entry in enumerate(tests, start=1):
    if not isinstance(entry, dict):
        errors.append(f"manual_tests[{index}] must be an object")
        continue

    device = entry.get("device")
    if not isinstance(device, str) or device.strip().lower() not in required_devices:
        errors.append(f"manual_tests[{index}].device must be one of {sorted(required_devices)}")
        continue
    device_key = device.strip().lower()

    for key in ["firmware_tested", "host_os", "path_tested", "tester", "date", "evidence_ref"]:
        value = entry.get(key)
        if not isinstance(value, str) or value.strip().lower() in placeholder_values:
            errors.append(f"manual_tests[{index}].{key} must be a non-placeholder string")

    if isinstance(entry.get("date"), str):
        try:
            date.fromisoformat(entry["date"])
        except ValueError:
            errors.append(f"manual_tests[{index}].date must be YYYY-MM-DD")

    result = entry.get("result")
    if result not in allowed_results:
        errors.append(f"manual_tests[{index}].result must be one of {sorted(allowed_results)}")
    elif result == "pass":
        passed_devices.add(device_key)

    notes = entry.get("notes", "")
    if notes is not None and not isinstance(notes, str):
        errors.append(f"manual_tests[{index}].notes must be a string when present")

    joined = json.dumps(entry, sort_keys=True).lower()
    forbidden = ["seed phrase", "mnemonic", "xprv", "private key", "passphrase:"]
    for token in forbidden:
        if token in joined:
            errors.append(f"manual_tests[{index}] appears to contain forbidden secret material: {token}")

missing = sorted(required_devices - passed_devices)
if missing:
    errors.append(f"missing passing manual device checks for: {', '.join(missing)}")

if errors:
    print(f"{path}: hardware-wallet manual matrix is not release-ready:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)
PY
}

verify_release() {
  local tag="$1"
  local major channel public_release
  IFS=: read -r major channel public_release < <(classify_tag "${tag}")

  echo "release tag: ${tag}"
  echo "release channel: ${channel}"

  if [[ "${major}" -eq 0 && "${public_release}" == "true" ]]; then
    die "pre-v1.0 releases must use an -alpha.N or -beta.N tag so the website banner stays accurate"
  fi

  if [[ "${public_release}" == "false" ]]; then
    echo "${channel} release gate passed: audit sign-off and placeholder replacement are deferred until a public release."
    return 0
  fi

  verify_audit_signoff
  verify_no_placeholders
  verify_hardware_matrix
  echo "stable release gate passed: audit sign-off, placeholder replacement, and manual hardware checks are complete."
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  SELF_TEST_TMP="${tmp}"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT

  mkdir -p "${tmp}/docs"
  git -C "${tmp}" init -q

  cat > "${tmp}/project.config.toml" <<'EOF'
[placeholders]
tokens = ["__GH_ORG__", "__MAINTAINER_PGP_FINGERPRINT__", "__MAINTAINER_PGP_KEY_BLOCK__"]
EOF
  cat > "${tmp}/README.md" <<'EOF'
Release docs still mention __GH_ORG__ until configured.
EOF
  cat > "${tmp}/docs/security-audit-signoff.json" <<'EOF'
{
  "schema_version": "1.0.0",
  "status": "complete",
  "auditor": "Example auditor",
  "report_date": "2026-05-31",
  "scope": "Bitcoin Lifeboat v1.0 Stable release",
  "report_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "findings": [
    {
      "id": "AUD-001",
      "severity": "medium",
      "resolution": "resolved"
    }
  ],
  "signoff": {
    "all_findings_remediated": true,
    "stable_release_approved": true
  }
}
EOF
  cat > "${tmp}/docs/hardware-wallet-device-matrix.json" <<'EOF'
{
  "schema_version": "1.0.0",
  "app_version": "1.0.0",
  "build_id": "v1.0.0-example",
  "tested_at": "2026-05-31",
  "manual_tests": [
    {
      "device": "trezor",
      "firmware_tested": "Example 1.0.0",
      "host_os": "Ubuntu 24.04",
      "path_tested": "HWI sidecar",
      "result": "pass",
      "tester": "Example tester",
      "date": "2026-05-31",
      "evidence_ref": "https://example.invalid/evidence/trezor",
      "notes": "Test-network PSBT signed and validated."
    },
    {
      "device": "coldcard",
      "firmware_tested": "Example 1.0.0",
      "host_os": "Ubuntu 24.04",
      "path_tested": "File PSBT",
      "result": "pass",
      "tester": "Example tester",
      "date": "2026-05-31",
      "evidence_ref": "https://example.invalid/evidence/coldcard",
      "notes": "Test-network PSBT signed and validated."
    },
    {
      "device": "bitbox02",
      "firmware_tested": "Example 1.0.0",
      "host_os": "Ubuntu 24.04",
      "path_tested": "HWI sidecar",
      "result": "pass",
      "tester": "Example tester",
      "date": "2026-05-31",
      "evidence_ref": "https://example.invalid/evidence/bitbox02",
      "notes": "Test-network PSBT signed and validated."
    },
    {
      "device": "jade",
      "firmware_tested": "Example 1.0.0",
      "host_os": "Ubuntu 24.04",
      "path_tested": "QR PSBT",
      "result": "pass",
      "tester": "Example tester",
      "date": "2026-05-31",
      "evidence_ref": "https://example.invalid/evidence/jade",
      "notes": "Test-network PSBT signed and validated."
    },
    {
      "device": "ledger",
      "firmware_tested": "Example 1.0.0",
      "host_os": "Ubuntu 24.04",
      "path_tested": "HWI sidecar",
      "result": "pass",
      "tester": "Example tester",
      "date": "2026-05-31",
      "evidence_ref": "https://example.invalid/evidence/ledger",
      "notes": "Test-network PSBT signed and validated."
    }
  ]
}
EOF
  git -C "${tmp}" add .

  expect_success() {
    local label="$1"
    shift
    if ! "${script_path}" --repo-root "${tmp}" "$@" >/dev/null 2>&1; then
      echo "self-test failed: expected success for ${label}" >&2
      "${script_path}" --repo-root "${tmp}" "$@" >&2 || true
      exit 1
    fi
  }

  expect_failure() {
    local label="$1"
    shift
    if "${script_path}" --repo-root "${tmp}" "$@" >/dev/null 2>&1; then
      echo "self-test failed: expected failure for ${label}" >&2
      exit 1
    fi
  }

  expect_success "alpha with placeholders" --tag v0.9.0-alpha.1
  expect_success "beta with placeholders" --tag v0.9.0-beta.1
  expect_failure "pre-v1 public tag" --tag v0.9.0
  expect_failure "stable tag with placeholders" --tag v1.0.0

  python3 - "${tmp}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for path in [root / "project.config.toml", root / "README.md"]:
    text = path.read_text(encoding="utf-8")
    text = text.replace("__GH_ORG__", "example-org")
    text = text.replace("__MAINTAINER_PGP_FINGERPRINT__", "0123456789ABCDEF0123456789ABCDEF01234567")
    text = text.replace("__MAINTAINER_PGP_KEY_BLOCK__", "docs/release-key.asc")
    path.write_text(text, encoding="utf-8")
PY
  git -C "${tmp}" add .
  expect_success "stable tag with signoff and no placeholders" --tag v1.0.0

  rm "${tmp}/docs/hardware-wallet-device-matrix.json"
  git -C "${tmp}" add -u
  expect_failure "stable tag without manual hardware matrix" --tag v1.0.0

  cat > "${tmp}/docs/hardware-wallet-device-matrix.json" <<'EOF'
{
  "schema_version": "1.0.0",
  "app_version": "1.0.0",
  "build_id": "v1.0.0-example",
  "tested_at": "2026-05-31",
  "manual_tests": []
}
EOF
  git -C "${tmp}" add .
  expect_failure "stable tag with incomplete manual hardware matrix" --tag v1.0.0

  rm "${tmp}/docs/security-audit-signoff.json"
  git -C "${tmp}" add -u
  expect_failure "stable tag without signoff" --tag v1.0.0

  echo "release gate self-test passed"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -ge 2 ]] || die "--tag requires a value"
      tag_name="$2"
      shift 2
      ;;
    --repo-root)
      [[ $# -ge 2 ]] || die "--repo-root requires a value"
      repo_root="$(cd "$2" && pwd)"
      shift 2
      ;;
    --audit-signoff)
      [[ $# -ge 2 ]] || die "--audit-signoff requires a value"
      audit_signoff="$2"
      shift 2
      ;;
    --hardware-matrix)
      [[ $# -ge 2 ]] || die "--hardware-matrix requires a value"
      hardware_matrix="$2"
      shift 2
      ;;
    --self-test)
      self_test
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "${tag_name}" ]] || {
  usage >&2
  die "--tag is required unless --self-test is used"
}

verify_release "${tag_name}"
