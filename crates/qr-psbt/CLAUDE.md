# qr-psbt

QR PSBT transport is a root Rust 1.78 workspace crate and must keep its default
build GUI-free. UR, BBQr, and pure image QR decoding live here; hardware camera
capture is available only behind the explicit `camera` feature via `nokhwa`.

Encode new outbound PSBT QR payloads as current BCR `ur:psbt`, not deprecated
`ur:crypto-psbt`. Decoding accepts `crypto-psbt` only for import compatibility.

The `ur` crate transports arbitrary message bytes. For BCR-2020-006 PSBTs, wrap
the raw binary PSBT in a deterministic CBOR byte string before passing it to
`ur::Encoder`, and unwrap that CBOR byte string after `ur::Decoder` completes.

For BBQr, encode with `FileType::Psbt` and validate the recovered bytes with the
same PSBT magic/size guard as UR. Keep `bbqr`'s `qr-codes` feature disabled in
the default build; tests generate QR images with `qrcode` and decode luminance
buffers through `rqrr`.

Renderable QR SVGs are produced here with `render_qr_svg`, using the workspace
`qrcode` dependency with its `svg` feature. Desktop/UI callers should request SVG
frames from Rust and display them; do not add a frontend QR renderer or PSBT
parser.
