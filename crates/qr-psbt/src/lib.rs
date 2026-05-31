//! `qr-psbt` - QR transport helpers for PSBT files.
//!
//! This crate owns the BCR-2020-005/006 UR and BBQr layers for animated QR PSBT exchange.
//! It deliberately handles only byte transport: callers remain responsible for
//! deciding when a PSBT may be signed, finalized, saved, or broadcast. The
//! UR payload is encoded as a deterministic CBOR byte string under the current
//! BCR registry type `ur:psbt`; BBQr uses the protocol's PSBT file type.

use std::num::TryFromIntError;

use bbqr::{
    continuous_join::{ContinuousJoinResult, ContinuousJoiner},
    file_type::FileType,
    join::Joined,
    split::{Split, SplitOptions},
};
use error_taxonomy::{ErrorCode, LifeboatError};
use qrcode::{render::svg, EcLevel, QrCode};

/// Current BCR-2020-006 UR type for Partially Signed Bitcoin Transactions.
pub const PSBT_UR_TYPE: &str = "psbt";

/// Legacy v1 type seen in older air-gapped wallet ecosystems.
pub const LEGACY_CRYPTO_PSBT_UR_TYPE: &str = "crypto-psbt";

/// Default maximum fountain fragment size for animated QR frames.
pub const DEFAULT_MAX_FRAGMENT_LENGTH: usize = 400;

/// Match the existing PSBT import guard used by `psbt-tools`.
pub const MAX_PSBT_UR_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

/// Maximum BBQr parts supported by the upstream protocol.
pub const DEFAULT_BBQR_MAX_PARTS: usize = 1295;

/// Default rendered SVG side length for one QR frame.
pub const DEFAULT_QR_SVG_DIMENSION: u32 = 320;

const PSBT_MAGIC: &[u8] = b"psbt\xff";
const CBOR_MAJOR_TYPE_BYTES: u8 = 0x40;
const CBOR_ADDITIONAL_INFO_MASK: u8 = 0x1f;
const CBOR_ONE_BYTE_LENGTH: u8 = 24;
const CBOR_TWO_BYTE_LENGTH: u8 = 25;
const CBOR_FOUR_BYTE_LENGTH: u8 = 26;

/// A finite BBQr part set sufficient to reconstruct one PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtBbqrParts {
    parts: Vec<String>,
}

impl PsbtBbqrParts {
    /// BBQr parts in transmission order.
    #[must_use]
    pub fn parts(&self) -> &[String] {
        &self.parts
    }

    /// Consume and return the BBQr part strings.
    #[must_use]
    pub fn into_parts(self) -> Vec<String> {
        self.parts
    }

    /// Number of BBQr parts.
    #[must_use]
    pub fn part_count(&self) -> usize {
        self.parts.len()
    }
}

/// Result of feeding one BBQr part into an incremental decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtBbqrDecodeState {
    /// No non-empty BBQr part has been accepted yet.
    NotStarted,
    /// More parts are required before the PSBT can be recovered.
    InProgress { parts_left: usize },
    /// The PSBT was fully recovered.
    Complete(Vec<u8>),
}

/// A finite set of UR frames sufficient to reconstruct one PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtUrFrames {
    frames: Vec<String>,
    fragment_count: usize,
    max_fragment_length: usize,
}

impl PsbtUrFrames {
    /// UR frames in transmission order.
    #[must_use]
    pub fn frames(&self) -> &[String] {
        &self.frames
    }

    /// Consume and return the UR frame strings.
    #[must_use]
    pub fn into_frames(self) -> Vec<String> {
        self.frames
    }

    /// Number of source fragments the fountain encoder split the payload into.
    #[must_use]
    pub const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Maximum fragment length used for the encoder.
    #[must_use]
    pub const fn max_fragment_length(&self) -> usize {
        self.max_fragment_length
    }
}

/// Streaming animated-UR encoder for one PSBT.
pub struct PsbtUrEncoder {
    inner: ur::Encoder<'static>,
    fragment_count: usize,
    max_fragment_length: usize,
}

impl PsbtUrEncoder {
    /// Create an encoder over a binary PSBT.
    ///
    /// The returned encoder emits `ur:psbt/<seq>/<fragment>` frames. It can emit
    /// more than [`fragment_count`](Self::fragment_count) frames; later frames
    /// are fountain-code mixes that help receivers recover from missed QR scans.
    pub fn new(psbt: &[u8], max_fragment_length: usize) -> Result<Self, LifeboatError> {
        let cbor = encode_psbt_cbor(psbt)?;
        let inner = ur::Encoder::new(&cbor, max_fragment_length, PSBT_UR_TYPE).map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("UR PSBT encoder could not be initialized")
        })?;
        let fragment_count = inner.fragment_count();
        Ok(Self {
            inner,
            fragment_count,
            max_fragment_length,
        })
    }

    /// Return the next animated-UR frame.
    pub fn next_frame(&mut self) -> Result<String, LifeboatError> {
        self.inner.next_part().map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("UR PSBT frame could not be encoded")
        })
    }

    /// Number of source fragments in the finite fixed-rate sequence.
    #[must_use]
    pub const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Maximum fragment length used for the encoder.
    #[must_use]
    pub const fn max_fragment_length(&self) -> usize {
        self.max_fragment_length
    }

    /// Number of frames already emitted.
    #[must_use]
    pub const fn current_index(&self) -> usize {
        self.inner.current_index()
    }
}

/// Encode a binary PSBT into the first complete set of animated-UR frames.
pub fn encode_psbt_ur_frames(
    psbt: &[u8],
    max_fragment_length: usize,
) -> Result<PsbtUrFrames, LifeboatError> {
    let mut encoder = PsbtUrEncoder::new(psbt, max_fragment_length)?;
    let fragment_count = encoder.fragment_count();
    let frames = (0..fragment_count)
        .map(|_| encoder.next_frame())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PsbtUrFrames {
        frames,
        fragment_count,
        max_fragment_length,
    })
}

/// Encode a binary PSBT into BBQr parts.
pub fn encode_psbt_bbqr_parts(psbt: &[u8]) -> Result<PsbtBbqrParts, LifeboatError> {
    encode_psbt_bbqr_parts_with_options(psbt, SplitOptions::default())
}

/// Encode a binary PSBT into BBQr parts using caller-provided split options.
pub fn encode_psbt_bbqr_parts_with_options(
    psbt: &[u8],
    options: SplitOptions,
) -> Result<PsbtBbqrParts, LifeboatError> {
    validate_psbt_payload(psbt)?;
    let split = Split::try_from_data(psbt, FileType::Psbt, options).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BBQr PSBT parts could not be encoded")
            .with_source(err)
    })?;

    Ok(PsbtBbqrParts { parts: split.parts })
}

/// Render one UR or BBQr payload string as a standalone SVG QR code.
pub fn render_qr_svg(payload: &str, min_dimension: u32) -> Result<String, LifeboatError> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty).with_context("QR payload is empty"));
    }

    let dimension = if min_dimension == 0 {
        DEFAULT_QR_SVG_DIMENSION
    } else {
        min_dimension
    };

    let code =
        QrCode::with_error_correction_level(trimmed.as_bytes(), EcLevel::M).map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("QR payload could not be rendered")
                .with_source(err)
        })?;

    Ok(code
        .render()
        .min_dimensions(dimension, dimension)
        .dark_color(svg::Color("#0f172a"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

/// Decode a finite list of BBQr PSBT parts back into raw PSBT bytes.
pub fn decode_psbt_bbqr_parts<I, S>(parts: I) -> Result<Vec<u8>, LifeboatError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let parts = parts
        .into_iter()
        .map(|part| part.as_ref().trim().to_owned())
        .collect::<Vec<_>>();

    if parts.iter().all(String::is_empty) {
        return Err(LifeboatError::new(ErrorCode::InputEmpty)
            .with_context("no BBQr PSBT parts were provided"));
    }

    let joined = Joined::try_from_parts(parts).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BBQr PSBT parts could not be joined")
            .with_source(err)
    })?;

    joined_psbt_bytes(joined)
}

/// Incremental BBQr decoder for one PSBT.
#[derive(Default)]
pub struct PsbtBbqrDecoder {
    inner: ContinuousJoiner,
}

impl PsbtBbqrDecoder {
    /// Receive one BBQr part.
    pub fn receive(&mut self, part: &str) -> Result<PsbtBbqrDecodeState, LifeboatError> {
        let result = self.inner.add_part(part.trim().to_owned()).map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("BBQr PSBT part could not be accepted")
                .with_source(err)
        })?;

        match result {
            ContinuousJoinResult::NotStarted => Ok(PsbtBbqrDecodeState::NotStarted),
            ContinuousJoinResult::InProgress { parts_left } => {
                Ok(PsbtBbqrDecodeState::InProgress { parts_left })
            }
            ContinuousJoinResult::Complete(joined) => {
                joined_psbt_bytes(joined).map(PsbtBbqrDecodeState::Complete)
            }
        }
    }
}

fn joined_psbt_bytes(joined: Joined) -> Result<Vec<u8>, LifeboatError> {
    if joined.file_type != FileType::Psbt {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BBQr payload is not a PSBT"));
    }
    validate_psbt_payload(&joined.data)?;
    Ok(joined.data)
}

/// Incremental animated-UR decoder for one PSBT.
#[derive(Default)]
pub struct PsbtUrDecoder {
    inner: ur::Decoder,
    single_part: Option<Vec<u8>>,
}

impl PsbtUrDecoder {
    /// Receive one `ur:psbt` or legacy `ur:crypto-psbt` frame.
    pub fn receive(&mut self, frame: &str) -> Result<(), LifeboatError> {
        let normalized = normalize_ur_frame(frame)?;
        let (kind, payload) = ur::ur::decode(&normalized).map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("UR PSBT frame could not be decoded")
        })?;

        match kind {
            ur::ur::Kind::SinglePart => {
                let psbt = decode_psbt_cbor(&payload)?;
                if let Some(existing) = &self.single_part {
                    if existing != &psbt {
                        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                            .with_context("UR PSBT single-part frames disagree"));
                    }
                }
                self.single_part = Some(psbt);
                Ok(())
            }
            ur::ur::Kind::MultiPart => self.inner.receive(&normalized).map_err(|_| {
                LifeboatError::new(ErrorCode::InputInvalidFormat)
                    .with_context("UR PSBT fountain frame could not be assembled")
            }),
        }
    }

    /// Whether enough frames have arrived to recover the PSBT.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.single_part.is_some() || self.inner.complete()
    }

    /// Return the decoded PSBT once complete.
    pub fn message(&self) -> Result<Option<Vec<u8>>, LifeboatError> {
        if let Some(psbt) = &self.single_part {
            return Ok(Some(psbt.clone()));
        }

        let Some(cbor) = self.inner.message().map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("UR PSBT fountain payload could not be recovered")
        })?
        else {
            return Ok(None);
        };

        decode_psbt_cbor(&cbor).map(Some)
    }
}

/// Decode a finite list of UR PSBT frames back into raw PSBT bytes.
pub fn decode_psbt_ur_frames<I, S>(frames: I) -> Result<Vec<u8>, LifeboatError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut received_any = false;
    let mut decoder = PsbtUrDecoder::default();
    for frame in frames {
        received_any = true;
        decoder.receive(frame.as_ref())?;
    }

    if !received_any {
        return Err(LifeboatError::new(ErrorCode::InputEmpty)
            .with_context("no UR PSBT frames were provided"));
    }

    decoder.message()?.ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR PSBT frames did not assemble a complete payload")
    })
}

fn normalize_ur_frame(frame: &str) -> Result<String, LifeboatError> {
    let trimmed = frame.trim();
    if trimmed.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputEmpty).with_context("UR PSBT frame is empty")
        );
    }

    let normalized = trimmed.to_ascii_lowercase();
    let r#type = ur_type(&normalized)?;
    if r#type != PSBT_UR_TYPE && r#type != LEGACY_CRYPTO_PSBT_UR_TYPE {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR frame type is not psbt"));
    }
    Ok(normalized)
}

fn ur_type(normalized: &str) -> Result<&str, LifeboatError> {
    let without_scheme = normalized.strip_prefix("ur:").ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR frame has an invalid scheme")
    })?;
    let (r#type, _) = without_scheme.split_once('/').ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context("UR frame has no type")
    })?;
    if r#type.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context("UR frame has no type")
        );
    }
    Ok(r#type)
}

/// Decode QR payload strings from an 8-bit luminance image.
pub fn decode_qr_codes_from_luma(
    width: usize,
    height: usize,
    luminance: &[u8],
) -> Result<Vec<String>, LifeboatError> {
    if width == 0 || height == 0 || luminance.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty).with_context("QR image is empty"));
    }
    let expected = width.checked_mul(height).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputTooLarge).with_context("QR image dimensions overflow")
    })?;
    if luminance.len() != expected {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("QR luminance buffer dimensions do not match"));
    }

    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luminance[y * width + x]);
    let mut decoded = Vec::new();
    let mut decode_failed = false;

    for grid in prepared.detect_grids() {
        match grid.decode() {
            Ok((_meta, content)) => decoded.push(content),
            Err(_err) => decode_failed = true,
        }
    }

    if decoded.is_empty() && decode_failed {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("QR code was detected but could not be decoded"));
    }

    Ok(decoded)
}

/// Decode QR payload strings from an 8-bit RGB image.
pub fn decode_qr_codes_from_rgb(
    width: usize,
    height: usize,
    rgb: &[u8],
) -> Result<Vec<String>, LifeboatError> {
    let expected_pixels = width.checked_mul(height).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputTooLarge).with_context("QR image dimensions overflow")
    })?;
    let expected_bytes = expected_pixels.checked_mul(3).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputTooLarge).with_context("QR RGB buffer length overflow")
    })?;
    if rgb.len() != expected_bytes {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("QR RGB buffer dimensions do not match"));
    }

    let luminance = rgb
        .chunks_exact(3)
        .map(|pixel| {
            let r = u32::from(pixel[0]);
            let g = u32::from(pixel[1]);
            let b = u32::from(pixel[2]);
            ((299 * r + 587 * g + 114 * b) / 1000) as u8
        })
        .collect::<Vec<_>>();

    decode_qr_codes_from_luma(width, height, &luminance)
}

/// One RGB camera frame captured through `nokhwa`.
#[cfg(feature = "camera")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraFrame {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Packed RGB bytes, three bytes per pixel.
    pub rgb: Vec<u8>,
}

/// Capture one RGB frame from a native camera through `nokhwa`.
#[cfg(feature = "camera")]
pub fn capture_camera_frame(camera_index: u32) -> Result<CameraFrame, LifeboatError> {
    use nokhwa::{
        pixel_format::RgbFormat,
        utils::{CameraIndex, RequestedFormat, RequestedFormatType},
        Camera,
    };

    let requested =
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    let mut camera = Camera::new(CameraIndex::Index(camera_index), requested).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("camera could not be opened")
            .with_source(err)
    })?;
    camera.open_stream().map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("camera stream could not be opened")
            .with_source(err)
    })?;
    let frame = camera.frame().map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("camera frame could not be captured")
            .with_source(err)
    })?;
    let decoded = frame.decode_image::<RgbFormat>().map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("camera frame could not be decoded to RGB")
            .with_source(err)
    })?;
    let width = decoded.width();
    let height = decoded.height();
    Ok(CameraFrame {
        width,
        height,
        rgb: decoded.into_raw(),
    })
}

/// Capture one camera frame and decode any QR payloads it contains.
#[cfg(feature = "camera")]
pub fn capture_camera_qr_codes(camera_index: u32) -> Result<Vec<String>, LifeboatError> {
    let frame = capture_camera_frame(camera_index)?;
    decode_qr_codes_from_rgb(frame.width as usize, frame.height as usize, &frame.rgb)
}

fn encode_psbt_cbor(psbt: &[u8]) -> Result<Vec<u8>, LifeboatError> {
    validate_psbt_payload(psbt)?;

    let mut out = Vec::with_capacity(psbt.len().saturating_add(5));
    write_cbor_bytes_header(psbt.len(), &mut out)?;
    out.extend_from_slice(psbt);
    Ok(out)
}

fn write_cbor_bytes_header(len: usize, out: &mut Vec<u8>) -> Result<(), LifeboatError> {
    if len <= 23 {
        out.push(CBOR_MAJOR_TYPE_BYTES | u8::try_from(len).map_err(length_conversion_error)?);
    } else if len <= usize::from(u8::MAX) {
        out.push(CBOR_MAJOR_TYPE_BYTES | CBOR_ONE_BYTE_LENGTH);
        out.push(u8::try_from(len).map_err(length_conversion_error)?);
    } else if len <= usize::from(u16::MAX) {
        out.push(CBOR_MAJOR_TYPE_BYTES | CBOR_TWO_BYTE_LENGTH);
        out.extend_from_slice(
            &u16::try_from(len)
                .map_err(length_conversion_error)?
                .to_be_bytes(),
        );
    } else {
        let len_u32 = u32::try_from(len).map_err(|err| {
            LifeboatError::new(ErrorCode::InputTooLarge)
                .with_context("PSBT payload exceeds the UR size limit")
                .with_source(err)
        })?;
        out.push(CBOR_MAJOR_TYPE_BYTES | CBOR_FOUR_BYTE_LENGTH);
        out.extend_from_slice(&len_u32.to_be_bytes());
    }
    Ok(())
}

fn decode_psbt_cbor(cbor: &[u8]) -> Result<Vec<u8>, LifeboatError> {
    let first = *cbor.first().ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context("UR PSBT payload is empty")
    })?;
    if first & !CBOR_ADDITIONAL_INFO_MASK != CBOR_MAJOR_TYPE_BYTES {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR PSBT payload is not a CBOR byte string"));
    }

    let (len, offset) = read_cbor_bytes_len(first & CBOR_ADDITIONAL_INFO_MASK, cbor)?;
    let end = offset.checked_add(len).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputTooLarge).with_context("UR PSBT payload length overflow")
    })?;
    let psbt = cbor.get(offset..end).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR PSBT CBOR byte string is truncated")
    })?;
    if end != cbor.len() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR PSBT CBOR payload has trailing data"));
    }

    validate_psbt_payload(psbt)?;
    Ok(psbt.to_vec())
}

fn read_cbor_bytes_len(additional_info: u8, cbor: &[u8]) -> Result<(usize, usize), LifeboatError> {
    match additional_info {
        len @ 0..=23 => Ok((usize::from(len), 1)),
        CBOR_ONE_BYTE_LENGTH => {
            let len = usize::from(*cbor.get(1).ok_or_else(truncated_cbor_len)?);
            if len < 24 {
                return Err(non_deterministic_cbor_len());
            }
            Ok((len, 2))
        }
        CBOR_TWO_BYTE_LENGTH => {
            let bytes = read_cbor_len_bytes::<2>(cbor, 1)?;
            let len = usize::from(u16::from_be_bytes(bytes));
            if len <= usize::from(u8::MAX) {
                return Err(non_deterministic_cbor_len());
            }
            Ok((len, 3))
        }
        CBOR_FOUR_BYTE_LENGTH => {
            let bytes = read_cbor_len_bytes::<4>(cbor, 1)?;
            let len =
                usize::try_from(u32::from_be_bytes(bytes)).map_err(length_conversion_error)?;
            if len <= usize::from(u16::MAX) {
                return Err(non_deterministic_cbor_len());
            }
            Ok((len, 5))
        }
        _ => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("UR PSBT CBOR byte-string length is unsupported")),
    }
}

fn read_cbor_len_bytes<const N: usize>(
    cbor: &[u8],
    offset: usize,
) -> Result<[u8; N], LifeboatError> {
    let end = offset.checked_add(N).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputTooLarge)
            .with_context("UR PSBT CBOR length offset overflow")
    })?;
    let bytes = cbor.get(offset..end).ok_or_else(truncated_cbor_len)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn validate_psbt_payload(psbt: &[u8]) -> Result<(), LifeboatError> {
    if psbt.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty).with_context("PSBT payload is empty"));
    }
    if psbt.len() > MAX_PSBT_UR_PAYLOAD_BYTES {
        return Err(LifeboatError::new(ErrorCode::InputTooLarge)
            .with_context("PSBT payload exceeds the 10 MB limit"));
    }
    if !psbt.starts_with(PSBT_MAGIC) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT payload magic bytes are invalid"));
    }
    Ok(())
}

fn truncated_cbor_len() -> LifeboatError {
    LifeboatError::new(ErrorCode::InputInvalidFormat)
        .with_context("UR PSBT CBOR byte-string length is truncated")
}

fn non_deterministic_cbor_len() -> LifeboatError {
    LifeboatError::new(ErrorCode::InputInvalidFormat)
        .with_context("UR PSBT CBOR byte-string length is not deterministic")
}

fn length_conversion_error(err: TryFromIntError) -> LifeboatError {
    LifeboatError::new(ErrorCode::Internal)
        .with_context("UR PSBT length conversion failed")
        .with_source(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use bbqr::qr::Version;
    use qrcode::{Color, QrCode};

    const BIP174_UPDATED_V0: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/psbt/bip174_updated_v0.txt"
    ));

    fn fixture_psbt() -> Vec<u8> {
        BASE64_STANDARD
            .decode(BIP174_UPDATED_V0.trim())
            .expect("fixture is valid base64")
    }

    #[test]
    fn psbt_round_trips_through_multiframe_ur() {
        let psbt = fixture_psbt();
        let frames = encode_psbt_ur_frames(&psbt, 50).expect("PSBT encodes to UR frames");

        assert!(frames.fragment_count() > 1, "fixture must span frames");
        assert_eq!(frames.frames().len(), frames.fragment_count());
        assert!(frames
            .frames()
            .iter()
            .all(|frame| frame.starts_with("ur:psbt/")));

        let decoded = decode_psbt_ur_frames(frames.frames()).expect("frames decode");
        assert_eq!(decoded, psbt);
    }

    #[test]
    fn fountain_frames_recover_after_missed_scans() {
        let psbt = fixture_psbt();
        let mut encoder = PsbtUrEncoder::new(&psbt, 45).expect("encoder");
        let fragment_count = encoder.fragment_count();
        assert!(fragment_count > 1, "fixture must span frames");

        let mut decoder = PsbtUrDecoder::default();
        while !decoder.is_complete() {
            let frame = encoder.next_frame().expect("next UR frame");
            if encoder.current_index() % 2 == 1 {
                decoder.receive(&frame).expect("odd frame accepted");
            }
        }

        assert!(
            encoder.current_index() > fragment_count,
            "decoder should need fountain frames beyond the fixed sequence"
        );
        assert_eq!(decoder.message().expect("message"), Some(psbt));
    }

    #[test]
    fn decoder_accepts_uppercase_frames_from_qr_readers() {
        let psbt = fixture_psbt();
        let frames = encode_psbt_ur_frames(&psbt, 60).expect("PSBT encodes");
        let uppercase = frames
            .frames()
            .iter()
            .map(|frame| frame.to_ascii_uppercase())
            .collect::<Vec<_>>();

        let decoded = decode_psbt_ur_frames(uppercase).expect("uppercase frames decode");
        assert_eq!(decoded, psbt);
    }

    #[test]
    fn decoder_accepts_legacy_crypto_psbt_type_for_import_only() {
        let psbt = fixture_psbt();
        let mut encoder = ur::Encoder::new(
            &encode_psbt_cbor(&psbt).expect("cbor"),
            55,
            LEGACY_CRYPTO_PSBT_UR_TYPE,
        )
        .expect("legacy encoder");
        let frames = (0..encoder.fragment_count())
            .map(|_| encoder.next_part().expect("legacy frame"))
            .collect::<Vec<_>>();

        let decoded = decode_psbt_ur_frames(frames).expect("legacy frames decode");
        assert_eq!(decoded, psbt);
    }

    #[test]
    fn rejects_non_psbt_ur_type() {
        let psbt = fixture_psbt();
        let cbor = encode_psbt_cbor(&psbt).expect("cbor");
        let mut encoder = ur::Encoder::new(&cbor, 60, "bytes").expect("bytes encoder");
        let err = decode_psbt_ur_frames([encoder.next_part().expect("frame")])
            .expect_err("wrong type rejected");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn rejects_incomplete_multiframe_sequence() {
        let psbt = fixture_psbt();
        let frames = encode_psbt_ur_frames(&psbt, 30).expect("PSBT encodes");
        let first_only = frames.frames().iter().take(1);
        let err = decode_psbt_ur_frames(first_only).expect_err("incomplete frames rejected");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn cbor_byte_string_is_deterministic() {
        let psbt = fixture_psbt();
        let cbor = encode_psbt_cbor(&psbt).expect("cbor");
        assert_eq!(cbor[0], CBOR_MAJOR_TYPE_BYTES | CBOR_TWO_BYTE_LENGTH);
        assert_eq!(decode_psbt_cbor(&cbor).expect("decode"), psbt);

        let non_minimal = [CBOR_MAJOR_TYPE_BYTES | CBOR_ONE_BYTE_LENGTH, 1, 0x00];
        let err = decode_psbt_cbor(&non_minimal).expect_err("non-minimal CBOR rejected");
        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn rejects_non_psbt_payloads() {
        let err = encode_psbt_ur_frames(b"not a psbt", DEFAULT_MAX_FRAGMENT_LENGTH)
            .expect_err("magic rejected");
        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn psbt_round_trips_through_bbqr() {
        let psbt = fixture_psbt();
        let parts = encode_psbt_bbqr_parts(&psbt).expect("PSBT encodes to BBQr parts");

        assert!(parts.part_count() >= 1);
        assert!(parts
            .parts()
            .iter()
            .all(|part| part.starts_with("B$") && part.as_bytes().get(3) == Some(&b'P')));

        let decoded = decode_psbt_bbqr_parts(parts.parts()).expect("BBQr parts decode");
        assert_eq!(decoded, psbt);
    }

    #[test]
    fn renders_payload_as_svg_qr_code() {
        let svg = render_qr_svg("ur:psbt/oyadgdaemw", 280).expect("QR SVG renders");

        assert!(svg.contains("<svg"));
        assert!(svg.contains("width=\""));
        assert!(svg.contains("height=\""));
        assert!(svg.contains("#0f172a"));
        assert!(svg.contains("#ffffff"));
    }

    #[test]
    fn incremental_bbqr_decoder_reports_progress() {
        let psbt = fixture_psbt();
        let parts = encode_psbt_bbqr_parts_with_options(
            &psbt,
            SplitOptions {
                min_split_number: 2,
                max_split_number: DEFAULT_BBQR_MAX_PARTS,
                min_version: Version::V01,
                max_version: Version::V40,
                ..SplitOptions::default()
            },
        )
        .expect("PSBT encodes to multiple BBQr parts");
        assert!(parts.part_count() > 1);

        let mut decoder = PsbtBbqrDecoder::default();
        let mut last_state = PsbtBbqrDecodeState::NotStarted;
        for part in parts.parts() {
            last_state = decoder.receive(part).expect("BBQr part accepted");
        }

        assert_eq!(last_state, PsbtBbqrDecodeState::Complete(psbt));
    }

    #[test]
    fn rqrr_decodes_generated_qr_from_luminance() {
        let payload = "B$2P0100PSBT";
        let (width, height, luminance) = render_test_qr(payload);

        let decoded = decode_qr_codes_from_luma(width, height, &luminance).expect("QR decodes");
        assert_eq!(decoded, vec![payload.to_owned()]);
    }

    #[test]
    fn rqrr_decodes_generated_qr_from_rgb() {
        let payload = "ur:psbt/oyadgdaemw";
        let (width, height, luminance) = render_test_qr(payload);
        let rgb = luminance
            .iter()
            .flat_map(|value| [*value, *value, *value])
            .collect::<Vec<_>>();

        let decoded = decode_qr_codes_from_rgb(width, height, &rgb).expect("QR decodes");
        assert_eq!(decoded, vec![payload.to_owned()]);
    }

    #[cfg(feature = "camera")]
    #[test]
    #[ignore = "requires attached camera hardware and OS camera permissions"]
    fn camera_capture_smoke_test() {
        let qr_codes = capture_camera_qr_codes(0).expect("camera captures a frame");
        assert!(
            qr_codes.is_empty() || qr_codes.iter().all(|code| !code.trim().is_empty()),
            "decoded QR payloads must be non-empty strings"
        );
    }

    fn render_test_qr(payload: &str) -> (usize, usize, Vec<u8>) {
        let code = QrCode::new(payload.as_bytes()).expect("test QR builds");
        let module_width = code.width();
        let quiet_zone = 4usize;
        let scale = 4usize;
        let image_width = (module_width + 2 * quiet_zone) * scale;
        let mut luminance = vec![255u8; image_width * image_width];
        let colors = code.to_colors();

        for y in 0..module_width {
            for x in 0..module_width {
                let value = if colors[y * module_width + x] == Color::Light {
                    255
                } else {
                    0
                };
                let out_x = (x + quiet_zone) * scale;
                let out_y = (y + quiet_zone) * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        luminance[(out_y + dy) * image_width + out_x + dx] = value;
                    }
                }
            }
        }

        (image_width, image_width, luminance)
    }
}
