#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Native desktop dependency check skipped: $(uname -s) is not Linux."
  exit 0
fi

if ! command -v pkg-config >/dev/null 2>&1; then
  cat >&2 <<'MSG'
Native desktop dependency check failed: pkg-config is not installed.

On Debian/Ubuntu install the Tauri Linux build prerequisites:
  sudo apt-get install -y pkg-config build-essential libwebkit2gtk-4.1-dev libgtk-3-dev \
    libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libssl-dev librsvg2-dev \
    libayatana-appindicator3-dev
MSG
  exit 1
fi

required_modules=(
  "gtk+-3.0"
  "gdk-3.0"
  "webkit2gtk-4.1"
  "javascriptcoregtk-4.1"
  "libsoup-3.0"
  "librsvg-2.0"
  "ayatana-appindicator3-0.1"
)

missing=()
for module in "${required_modules[@]}"; do
  if ! pkg-config --exists "${module}"; then
    missing+=("${module}")
  fi
done

if ((${#missing[@]} > 0)); then
  {
    echo "Native desktop dependency check failed."
    echo
    echo "Missing pkg-config modules:"
    for module in "${missing[@]}"; do
      echo "  - ${module}"
    done
    echo
    echo "On Debian/Ubuntu install:"
    echo "  sudo apt-get install -y pkg-config build-essential libwebkit2gtk-4.1-dev libgtk-3-dev \\"
    echo "    libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libssl-dev librsvg2-dev \\"
    echo "    libayatana-appindicator3-dev"
  } >&2
  exit 1
fi

echo "Native desktop dependency check passed (${#required_modules[@]} pkg-config modules)."
