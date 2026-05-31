#!/usr/bin/env bash
set -euo pipefail

device="${1:-}"

case "$device" in
  trezor)
    cargo test -p hwi-bridge --locked hwi_emulator_smoke_trezor
    ;;
  coldcard)
    cargo test -p hwi-bridge --locked hwi_emulator_smoke_coldcard
    ;;
  bitbox02)
    cargo test -p hwi-bridge --locked hwi_emulator_smoke_bitbox02
    ;;
  jade)
    cargo test -p qr-psbt --locked psbt_round_trips_through_bbqr
    cargo test -p qr-psbt --locked rqrr_decodes_generated_qr_from_luminance
    ;;
  *)
    printf 'usage: %s trezor|coldcard|bitbox02|jade\n' "$0" >&2
    exit 64
    ;;
esac
