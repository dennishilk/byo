use std::collections::BTreeMap;
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use image::{ImageFormat, ImageReader};

use crate::filename::{append_filename_report, MAX_FILENAME_BYTES};
use crate::{
    inspect_url, AnalysisState, InputKind, Limitation, QrCodeReport, QrPayload, QrPayloadKind,
    Report, Severity, WifiPayload,
};

pub const MAX_ENCODED_IMAGE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_IMAGE_WIDTH: u32 = 8_192;
pub const MAX_IMAGE_HEIGHT: u32 = 8_192;
pub const MAX_DECODED_IMAGE_PIXELS: u64 = 32_000_000;
pub const MAX_QR_PAYLOAD_BYTES: usize = 8 * 1024;
pub const MAX_QR_CODES: usize = 7;

const MAX_IMAGE_DECODER_ALLOCATION_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PAYLOAD_DISPLAY_CHARACTERS: usize = 2_048;
const MAX_BINARY_HEX_BYTES: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub struct QrImageContext {
    pub filename: String,
    pub declared_size: u64,
    pub filename_was_lossy: bool,
    pub selected_via_symlink: bool,
}

impl QrImageContext {
    pub fn new(filename: impl Into<String>, declared_size: u64) -> Self {
        Self {
            filename: filename.into(),
            declared_size,
            filename_was_lossy: false,
            selected_via_symlink: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RasterFormat {
    Png,
    Jpeg,
}

impl RasterFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "PNG",
            Self::Jpeg => "JPEG",
        }
    }

    const fn image_format(self) -> ImageFormat {
        match self {
            Self::Png => ImageFormat::Png,
            Self::Jpeg => ImageFormat::Jpeg,
        }
    }

    fn extension_is_compatible(self, extension: &str) -> bool {
        match self {
            Self::Png => extension.eq_ignore_ascii_case("png"),
            Self::Jpeg => ["jpg", "jpeg", "jpe"]
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension)),
        }
    }
}

struct CandidateDecode {
    index: u32,
    payload: Result<Vec<u8>, String>,
}

struct DetectionResult {
    candidates_detected: usize,
    candidates: Vec<CandidateDecode>,
}

struct ClassifiedPayload {
    payload: QrPayload,
    url_analysis: Option<Box<Report>>,
    limitations: Vec<Limitation>,
}

pub fn inspect_qr_image(encoded: &[u8], context: QrImageContext) -> Report {
    let filename_for_report = if context.filename.len() <= MAX_FILENAME_BYTES {
        context.filename.clone()
    } else {
        "<filename omitted: exceeds analysis limit>".to_owned()
    };
    let original_filename =
        (context.filename.len() <= MAX_FILENAME_BYTES).then(|| context.filename.clone());
    let mut report = Report::new(
        InputKind::QrImage,
        original_filename,
        filename_for_report.clone(),
    );

    let mut name_fields = BTreeMap::new();
    name_fields.insert("value".to_owned(), filename_for_report.into());
    report.add_observation("qr.file.name", "Selected QR image filename", name_fields);

    let supplied_size = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
    let mut size_fields = BTreeMap::new();
    size_fields.insert("declared_bytes".to_owned(), context.declared_size.into());
    size_fields.insert("supplied_bytes".to_owned(), supplied_size.into());
    report.add_observation("qr.image.encoded_size", "Encoded image size", size_fields);

    if context.filename_was_lossy {
        report.add_limitation(
            "filename.encoding_loss",
            "The platform filename was not valid Unicode, so its displayed form is lossy and filename rules may be incomplete.",
        );
        report.mark_partial();
    }
    if context.selected_via_symlink {
        let mut fields = BTreeMap::new();
        fields.insert("selected_via_symlink".to_owned(), true.into());
        report.add_observation(
            "qr.path.symlink",
            "Selected QR image path is a symbolic link",
            fields,
        );
        report.add_limitation(
            "qr.path.symlink_target",
            "The opened regular-file target was inspected; path canonicalization was not treated as evidence of trust.",
        );
    }

    let filename_evidence = append_filename_report(&mut report, &context.filename);

    if context.declared_size > MAX_ENCODED_IMAGE_BYTES || supplied_size > MAX_ENCODED_IMAGE_BYTES {
        report.add_limitation(
            "qr.image.encoded_size_limit",
            "QR image decoding was refused because the encoded source exceeded the 32 MiB limit.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    }

    if supplied_size != context.declared_size {
        report.add_limitation(
            "qr.image.size_changed_or_incomplete",
            "The supplied byte count differed from the size reported by the opened handle.",
        );
        report.mark_partial();
    }

    let Some(format) = detect_raster_format(encoded) else {
        let mut fields = BTreeMap::new();
        fields.insert("supported".to_owned(), false.into());
        report.add_observation("qr.image.format", "QR source image format", fields);
        report.add_limitation(
            "qr.image.unsupported_format",
            "M2 accepts only PNG and JPEG source images identified from their encoded bytes.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    };

    let mut format_fields = BTreeMap::new();
    format_fields.insert("name".to_owned(), format.as_str().into());
    format_fields.insert("supported".to_owned(), true.into());
    let format_id =
        report.add_observation("qr.image.format", "QR source image format", format_fields);

    if let Some(extension) = filename_evidence
        .analysis
        .as_ref()
        .and_then(|analysis| analysis.final_extension.as_deref())
    {
        if !format.extension_is_compatible(extension) {
            report.add_finding(
                "qr.image.extension_format_mismatch",
                Severity::Warning,
                "Filename extension and decoded raster format differ",
                "The image was decoded according to its bytes, not its filename. This inconsistency is not a safety verdict.",
                vec![filename_evidence.extension_observation_id, format_id.clone()],
            );
        }
    }

    let (width, height) = match read_dimensions(encoded, format) {
        Ok(dimensions) => dimensions,
        Err(error) => {
            report.add_limitation(
                "qr.image.header_decode_failed",
                format!(
                    "The {} header could not be decoded within the configured resource limits: {}",
                    format.as_str(),
                    bounded_text(&error, 256).0
                ),
            );
            report.mark_failed();
            append_qr_scope_limitations(&mut report);
            return report;
        }
    };

    let Some(pixel_count) = checked_pixel_count(u64::from(width), u64::from(height)) else {
        report.add_limitation(
            "qr.image.pixel_count_overflow",
            "Image dimensions could not be multiplied without overflowing the bounded pixel-count representation.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    };

    let mut dimension_fields = BTreeMap::new();
    dimension_fields.insert("width".to_owned(), u64::from(width).into());
    dimension_fields.insert("height".to_owned(), u64::from(height).into());
    dimension_fields.insert("pixel_count".to_owned(), pixel_count.into());
    report.add_observation(
        "qr.image.dimensions",
        "Decoded image dimensions",
        dimension_fields,
    );

    if width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT {
        report.add_limitation(
            "qr.image.dimension_limit",
            "Image decoding was refused because width or height exceeded 8,192 pixels.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    }
    if pixel_count > MAX_DECODED_IMAGE_PIXELS {
        report.add_limitation(
            "qr.image.pixel_limit",
            "Image decoding was refused because the decoded image exceeded 32,000,000 pixels.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    }

    let decoded = match decode_raster(encoded, format) {
        Ok(image) => image,
        Err(error) => {
            report.add_limitation(
                "qr.image.decode_failed",
                format!(
                    "The {} image could not be decoded within the configured resource limits: {}",
                    format.as_str(),
                    bounded_text(&error, 256).0
                ),
            );
            report.mark_failed();
            append_qr_scope_limitations(&mut report);
            return report;
        }
    };

    let grayscale = decoded.into_luma8();
    let (Ok(width_usize), Ok(height_usize), Ok(expected_pixels)) = (
        usize::try_from(width),
        usize::try_from(height),
        usize::try_from(pixel_count),
    ) else {
        report.add_limitation(
            "qr.image.platform_size_limit",
            "Decoded image dimensions could not be represented safely on this platform.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    };
    if grayscale.width() != width
        || grayscale.height() != height
        || grayscale.as_raw().len() != expected_pixels
    {
        report.add_limitation(
            "qr.image.decoded_buffer_mismatch",
            "The grayscale decoder output did not match the checked image dimensions and pixel count.",
        );
        report.mark_failed();
        append_qr_scope_limitations(&mut report);
        return report;
    }

    let detection = catch_unwind(AssertUnwindSafe(|| {
        detect_qr_codes(width_usize, height_usize, grayscale.as_raw().as_slice())
    }));
    let detection = match detection {
        Ok(result) => result,
        Err(_) => {
            report.add_limitation(
                "qr.decoder_panicked",
                "The in-process QR decoder aborted while processing hostile image data; no QR result is reported.",
            );
            report.mark_failed();
            append_qr_scope_limitations(&mut report);
            return report;
        }
    };

    let processed = detection.candidates.len();
    let mut detection_fields = BTreeMap::new();
    detection_fields.insert(
        "codes_found".to_owned(),
        u64::try_from(detection.candidates_detected)
            .unwrap_or(u64::MAX)
            .into(),
    );
    detection_fields.insert(
        "codes_processed".to_owned(),
        u64::try_from(processed).unwrap_or(u64::MAX).into(),
    );
    detection_fields.insert(
        "processing_limit".to_owned(),
        u64::try_from(MAX_QR_CODES).unwrap_or(u64::MAX).into(),
    );
    detection_fields.insert(
        "detected".to_owned(),
        (!detection.candidates.is_empty()).into(),
    );
    report.add_observation(
        "qr.detection",
        if detection.candidates_detected == 0 {
            "No QR code was detected"
        } else {
            "QR code detection result"
        },
        detection_fields,
    );

    if detection.candidates_detected > MAX_QR_CODES {
        report.add_limitation(
            "qr.code_count_limit",
            "More than seven QR candidates were detected; only the first seven were extracted and decoded.",
        );
        report.mark_partial();
    }

    for candidate in detection.candidates {
        append_candidate_report(&mut report, candidate);
    }

    append_qr_scope_limitations(&mut report);
    report
}

fn detect_raster_format(encoded: &[u8]) -> Option<RasterFormat> {
    if encoded.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(RasterFormat::Png)
    } else if encoded.starts_with(b"\xff\xd8\xff") {
        Some(RasterFormat::Jpeg)
    } else {
        None
    }
}

fn decoder_limits(enforce_dimensions: bool) -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_IMAGE_DECODER_ALLOCATION_BYTES);
    if enforce_dimensions {
        limits.max_image_width = Some(MAX_IMAGE_WIDTH);
        limits.max_image_height = Some(MAX_IMAGE_HEIGHT);
    }
    limits
}

fn read_dimensions(encoded: &[u8], format: RasterFormat) -> Result<(u32, u32), String> {
    let mut reader = ImageReader::with_format(Cursor::new(encoded), format.image_format());
    reader.limits(decoder_limits(false));
    reader.into_dimensions().map_err(|error| error.to_string())
}

fn decode_raster(encoded: &[u8], format: RasterFormat) -> Result<image::DynamicImage, String> {
    let mut reader = ImageReader::with_format(Cursor::new(encoded), format.image_format());
    reader.limits(decoder_limits(true));
    reader.decode().map_err(|error| error.to_string())
}

fn checked_pixel_count(width: u64, height: u64) -> Option<u64> {
    width.checked_mul(height)
}

fn detect_qr_codes(width: usize, height: usize, pixels: &[u8]) -> DetectionResult {
    let mut decoder = quircs::Quirc::default();
    let mut candidates = Vec::with_capacity(MAX_QR_CODES);
    {
        let codes = decoder.identify(width, height, pixels);
        for (position, candidate) in codes.take(MAX_QR_CODES).enumerate() {
            let index = u32::try_from(position.saturating_add(1)).unwrap_or(u32::MAX);
            let payload = match candidate {
                Ok(code) => code
                    .decode()
                    .map(|data| data.payload)
                    .map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            candidates.push(CandidateDecode { index, payload });
        }
    }
    DetectionResult {
        candidates_detected: decoder.count(),
        candidates,
    }
}

fn append_candidate_report(report: &mut Report, candidate: CandidateDecode) {
    let payload_bytes = match candidate.payload {
        Ok(payload) => payload,
        Err(error) => {
            let limitation = Limitation {
                code: "qr.code_decode_failed".to_owned(),
                explanation: format!(
                    "QR #{} was detected but its payload could not be decoded: {}",
                    candidate.index,
                    bounded_text(&error, 256).0
                ),
            };
            let mut fields = BTreeMap::new();
            fields.insert("index".to_owned(), u64::from(candidate.index).into());
            fields.insert("decode_succeeded".to_owned(), false.into());
            report.add_observation(
                "qr.code.decode_result",
                format!("QR #{} decode result", candidate.index),
                fields,
            );
            report.qr_codes.push(QrCodeReport {
                index: candidate.index,
                decode_succeeded: false,
                payload: None,
                url_analysis: None,
                limitations: vec![limitation],
            });
            report.mark_partial();
            return;
        }
    };

    if payload_bytes.len() > MAX_QR_PAYLOAD_BYTES {
        let limitation = Limitation {
            code: "qr.payload_size_limit".to_owned(),
            explanation: format!(
                "QR #{} decoded to more than 8 KiB; its payload was rejected without truncating it into a successful result.",
                candidate.index
            ),
        };
        let mut fields = BTreeMap::new();
        fields.insert("index".to_owned(), u64::from(candidate.index).into());
        fields.insert("decode_succeeded".to_owned(), true.into());
        fields.insert(
            "payload_bytes".to_owned(),
            u64::try_from(payload_bytes.len())
                .unwrap_or(u64::MAX)
                .into(),
        );
        fields.insert("accepted".to_owned(), false.into());
        report.add_observation(
            "qr.payload.rejected",
            format!("QR #{} payload exceeds limit", candidate.index),
            fields,
        );
        report.qr_codes.push(QrCodeReport {
            index: candidate.index,
            decode_succeeded: true,
            payload: None,
            url_analysis: None,
            limitations: vec![limitation],
        });
        report.mark_partial();
        return;
    }

    let mut classified = classify_payload(&payload_bytes);
    let mut fields = BTreeMap::new();
    fields.insert("index".to_owned(), u64::from(candidate.index).into());
    fields.insert("decode_succeeded".to_owned(), true.into());
    fields.insert(
        "byte_length".to_owned(),
        classified.payload.byte_length.into(),
    );
    fields.insert(
        "valid_utf8".to_owned(),
        classified.payload.valid_utf8.into(),
    );
    fields.insert("type".to_owned(), classified.payload.kind.as_str().into());
    fields.insert(
        "display".to_owned(),
        classified.payload.display.clone().into(),
    );
    fields.insert(
        "display_truncated".to_owned(),
        classified.payload.display_truncated.into(),
    );
    if let Some(hexadecimal) = &classified.payload.hexadecimal {
        fields.insert("hexadecimal".to_owned(), hexadecimal.clone().into());
        fields.insert(
            "hexadecimal_truncated".to_owned(),
            classified.payload.hexadecimal_truncated.into(),
        );
    }
    let payload_id = report.add_observation(
        "qr.payload",
        format!("QR #{} decoded payload", candidate.index),
        fields,
    );

    if classified
        .payload
        .wifi
        .as_ref()
        .is_some_and(|wifi| wifi.password_present)
    {
        report.add_finding(
            "qr.wifi_password_present",
            Severity::Attention,
            "Wi-Fi QR payload contains password material",
            "The password is not retained in the report and is redacted from human and JSON output.",
            vec![payload_id],
        );
    }

    if let Some(url_report) = &classified.url_analysis {
        match url_report.metadata.analysis_state() {
            AnalysisState::Complete => {}
            AnalysisState::Partial => {
                classified.limitations.push(Limitation {
                    code: "qr.url_analysis_partial".to_owned(),
                    explanation: format!(
                        "QR #{} decoded successfully, but its nested URL analysis was partial.",
                        candidate.index
                    ),
                });
                report.mark_partial();
            }
            AnalysisState::Failed => {
                classified.limitations.push(Limitation {
                    code: "qr.url_analysis_failed".to_owned(),
                    explanation: format!(
                        "QR #{} decoded successfully, but its URL-like text could not be fully parsed.",
                        candidate.index
                    ),
                });
                report.mark_partial();
            }
        }
    }

    report.qr_codes.push(QrCodeReport {
        index: candidate.index,
        decode_succeeded: true,
        payload: Some(classified.payload),
        url_analysis: classified.url_analysis,
        limitations: classified.limitations,
    });
}

fn classify_payload(bytes: &[u8]) -> ClassifiedPayload {
    let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let Ok(text) = std::str::from_utf8(bytes) else {
        let (hexadecimal, hexadecimal_truncated) = hexadecimal_preview(bytes);
        let mut limitations = Vec::new();
        if hexadecimal_truncated {
            limitations.push(Limitation {
                code: "qr.binary_display_limit".to_owned(),
                explanation:
                    "The binary payload hexadecimal preview is limited to the first 256 bytes."
                        .to_owned(),
            });
        }
        return ClassifiedPayload {
            payload: QrPayload {
                byte_length,
                valid_utf8: false,
                kind: QrPayloadKind::Binary,
                display: "<binary QR payload>".to_owned(),
                display_truncated: false,
                hexadecimal: Some(hexadecimal),
                hexadecimal_truncated,
                wifi: None,
            },
            url_analysis: None,
            limitations,
        };
    };

    if text
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("WIFI:"))
    {
        return ClassifiedPayload {
            payload: QrPayload {
                byte_length,
                valid_utf8: true,
                kind: QrPayloadKind::WifiConfiguration,
                display: "WIFI configuration payload (password redacted)".to_owned(),
                display_truncated: false,
                hexadecimal: None,
                hexadecimal_truncated: false,
                wifi: Some(parse_wifi_payload(text)),
            },
            url_analysis: None,
            limitations: Vec::new(),
        };
    }

    if let Some(scheme) = obvious_scheme(text) {
        let kind = match scheme.as_str() {
            "mailto" => QrPayloadKind::EmailUri,
            "tel" => QrPayloadKind::TelephoneUri,
            "sms" | "smsto" => QrPayloadKind::SmsUri,
            "http" | "https" | "javascript" | "data" | "vbscript" | "file" => QrPayloadKind::Url,
            _ => QrPayloadKind::CustomScheme,
        };
        let url_analysis = inspect_url(text);
        let (display, display_truncated) = bounded_text(
            &url_analysis.subject.display,
            MAX_PAYLOAD_DISPLAY_CHARACTERS,
        );
        return ClassifiedPayload {
            payload: QrPayload {
                byte_length,
                valid_utf8: true,
                kind,
                display,
                display_truncated,
                hexadecimal: None,
                hexadecimal_truncated: false,
                wifi: None,
            },
            url_analysis: Some(Box::new(url_analysis)),
            limitations: Vec::new(),
        };
    }

    let (display, display_truncated) = bounded_text(text, MAX_PAYLOAD_DISPLAY_CHARACTERS);
    let limitations = if display_truncated {
        vec![Limitation {
            code: "qr.text_display_limit".to_owned(),
            explanation: "The textual payload display is limited to 2,048 Unicode scalar values."
                .to_owned(),
        }]
    } else {
        Vec::new()
    };
    ClassifiedPayload {
        payload: QrPayload {
            byte_length,
            valid_utf8: true,
            kind: QrPayloadKind::Text,
            display,
            display_truncated,
            hexadecimal: None,
            hexadecimal_truncated: false,
            wifi: None,
        },
        url_analysis: None,
        limitations,
    }
}

fn obvious_scheme(input: &str) -> Option<String> {
    let colon = input.find(':')?;
    let scheme = input.get(..colon)?;
    let mut characters = scheme.chars();
    let first = characters.next()?;
    if !first.is_ascii_alphabetic()
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return None;
    }
    Some(scheme.to_ascii_lowercase())
}

fn parse_wifi_payload(input: &str) -> WifiPayload {
    let body = input.get(5..).unwrap_or_default();
    let mut authentication_type = None;
    let mut ssid = None;
    let mut password_present = false;
    let mut hidden = None;

    for raw_field in split_wifi_fields(body) {
        let Some((raw_key, raw_value)) = split_wifi_key_value(&raw_field) else {
            continue;
        };
        let key = unescape_wifi_value(raw_key);
        if key.eq_ignore_ascii_case("P") {
            password_present = true;
            continue;
        }

        if key.eq_ignore_ascii_case("T") && authentication_type.is_none() {
            authentication_type = Some(unescape_wifi_value(raw_value));
        } else if key.eq_ignore_ascii_case("S") && ssid.is_none() {
            ssid = Some(unescape_wifi_value(raw_value));
        } else if key.eq_ignore_ascii_case("H") && hidden.is_none() {
            let value = unescape_wifi_value(raw_value);
            if value.eq_ignore_ascii_case("true") {
                hidden = Some(true);
            } else if value.eq_ignore_ascii_case("false") {
                hidden = Some(false);
            }
        }
    }

    WifiPayload {
        authentication_type,
        ssid,
        password_present,
        hidden,
    }
}

fn split_wifi_fields(input: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            current.push('\\');
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ';' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

fn split_wifi_key_value(field: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (index, character) in field.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            return Some((field.get(..index)?, field.get(index.saturating_add(1)..)?));
        }
    }
    None
}

fn unescape_wifi_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            result.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            result.push(character);
        }
    }
    if escaped {
        result.push('\\');
    }
    result
}

fn hexadecimal_preview(bytes: &[u8]) -> (String, bool) {
    let preview_length = bytes.len().min(MAX_BINARY_HEX_BYTES);
    let mut output = String::with_capacity(preview_length.saturating_mul(3));
    for (index, byte) in bytes.iter().take(preview_length).enumerate() {
        if index != 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02X}"));
    }
    (output, bytes.len() > preview_length)
}

fn bounded_text(input: &str, maximum_characters: usize) -> (String, bool) {
    let mut characters = input.chars();
    let mut output: String = characters.by_ref().take(maximum_characters).collect();
    let truncated = characters.next().is_some();
    if truncated {
        output.push('…');
    }
    (output, truncated)
}

fn append_qr_scope_limitations(report: &mut Report) {
    report.add_limitation(
        "qr.offline_scope",
        "M2 made no HTTP or DNS request, did not navigate to decoded content, and did not invoke an external application.",
    );
    report.add_limitation(
        "qr.decoder_scope",
        "QR detection and decoding are bounded parser observations, not proof that a payload or destination is safe.",
    );
}

#[cfg(test)]
mod tests {
    use super::{
        append_candidate_report, checked_pixel_count, classify_payload, inspect_qr_image,
        parse_wifi_payload, CandidateDecode, MAX_IMAGE_WIDTH, MAX_QR_CODES, MAX_QR_PAYLOAD_BYTES,
    };
    use crate::{
        AnalysisState, InputKind, ObservationValue, QrImageContext, QrPayloadKind, Report,
    };

    const TEXT_PNG: &[u8] = include_bytes!("../../../fixtures/qr/text.png");
    const URL_JPEG: &[u8] = include_bytes!("../../../fixtures/qr/url.jpg");
    const MULTIPLE_PNG: &[u8] = include_bytes!("../../../fixtures/qr/multiple.png");
    const NEAR_LIMIT_PNG: &[u8] = include_bytes!("../../../fixtures/qr/near-limit.png");
    const OVER_LIMIT_MULTIPLE_PNG: &[u8] =
        include_bytes!("../../../fixtures/qr/over-limit-multiple.png");
    const NO_CODE_PNG: &[u8] = include_bytes!("../../../fixtures/qr/no-code.png");
    const CORRUPT_QR_PNG: &[u8] = include_bytes!("../../../fixtures/qr/corrupt-qr.png");
    const TRUNCATED_PNG: &[u8] = include_bytes!("../../../fixtures/qr/truncated.png");
    const TRUNCATED_JPEG: &[u8] = include_bytes!("../../../fixtures/qr/truncated.jpg");

    fn inspect_fixture(bytes: &[u8], filename: &str) -> Report {
        inspect_qr_image(
            bytes,
            QrImageContext::new(filename, u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
        )
    }

    fn has_limitation(report: &Report, code: &str) -> bool {
        report
            .limitations
            .iter()
            .any(|limitation| limitation.code == code)
            || report.qr_codes.iter().any(|qr| {
                qr.limitations
                    .iter()
                    .any(|limitation| limitation.code == code)
            })
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut checksum = u32::MAX;
        for byte in bytes {
            checksum ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(checksum & 1);
                checksum = (checksum >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !checksum
    }

    fn png_with_dimensions(width: u32, height: u32) -> Vec<u8> {
        let mut encoded = TEXT_PNG.to_vec();
        assert!(encoded.len() >= 33);
        encoded[16..20].copy_from_slice(&width.to_be_bytes());
        encoded[20..24].copy_from_slice(&height.to_be_bytes());
        let checksum = crc32(&encoded[12..29]);
        encoded[29..33].copy_from_slice(&checksum.to_be_bytes());
        encoded
    }

    #[test]
    fn checked_pixel_count_rejects_overflow() {
        assert_eq!(checked_pixel_count(8_192, 8_192), Some(67_108_864));
        assert_eq!(checked_pixel_count(u64::MAX, 2), None);
    }

    #[test]
    fn binary_payload_uses_bounded_hexadecimal() {
        let payload = vec![0xff_u8; 300];
        let classified = classify_payload(&payload);
        assert!(classified.payload.kind == QrPayloadKind::Binary);
        assert!(classified.payload.hexadecimal_truncated);
        assert!(classified
            .payload
            .hexadecimal
            .as_ref()
            .is_some_and(|value| value.len() <= 256 * 3));
    }

    #[test]
    fn wifi_parser_never_retains_password() {
        let wifi = parse_wifi_payload(r"WIFI:T:WPA;S:Cafe\;Guest;P:BYO_WIFI_SECRET;H:true;;");
        assert_eq!(wifi.authentication_type.as_deref(), Some("WPA"));
        assert_eq!(wifi.ssid.as_deref(), Some("Cafe;Guest"));
        assert!(wifi.password_present);
        assert_eq!(wifi.hidden, Some(true));
    }

    #[test]
    fn url_payload_reuses_offline_url_analyzer_and_redacts_password() {
        let secret = "BYO_QR_URL_SECRET";
        let input = format!("https://user:{secret}@xn--bcher-kva.example/?utm_source=qr");
        let classified = classify_payload(input.as_bytes());
        assert!(classified.payload.kind == QrPayloadKind::Url);
        assert!(!classified.payload.display.contains(secret));
        let nested = classified.url_analysis.as_ref();
        assert!(nested.is_some_and(|report| {
            !report.metadata.network_activity()
                && report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "url.tracking_parameter")
        }));
    }

    #[test]
    fn oversized_payload_is_rejected_without_successful_truncation() {
        let mut report = Report::new(InputKind::QrImage, None, "synthetic.png");
        append_candidate_report(
            &mut report,
            CandidateDecode {
                index: 1,
                payload: Ok(vec![b'A'; MAX_QR_PAYLOAD_BYTES.saturating_add(1)]),
            },
        );

        assert!(report.metadata.analysis_state() == AnalysisState::Partial);
        assert_eq!(report.qr_codes.len(), 1);
        assert!(report.qr_codes[0].payload.is_none());
        assert!(has_limitation(&report, "qr.payload_size_limit"));
    }

    #[test]
    fn failed_nested_url_analysis_makes_the_parent_partial() {
        let mut report = Report::new(InputKind::QrImage, None, "synthetic.png");
        append_candidate_report(
            &mut report,
            CandidateDecode {
                index: 1,
                payload: Ok(b"http:".to_vec()),
            },
        );

        assert!(report.metadata.analysis_state() == AnalysisState::Partial);
        assert!(has_limitation(&report, "qr.url_analysis_failed"));
        assert!(report.qr_codes[0]
            .url_analysis
            .as_ref()
            .is_some_and(|nested| nested.metadata.analysis_state() == AnalysisState::Failed));
    }

    #[test]
    fn png_and_jpeg_fixtures_decode_raw_payloads() {
        let png = inspect_fixture(TEXT_PNG, "text.png");
        assert!(png.metadata.analysis_state() == AnalysisState::Complete);
        assert_eq!(png.qr_codes.len(), 1);
        assert_eq!(
            png.qr_codes[0]
                .payload
                .as_ref()
                .map(|payload| payload.display.as_str()),
            Some("Hello from BYO")
        );

        let jpeg = inspect_fixture(URL_JPEG, "url.jpg");
        assert!(jpeg.metadata.analysis_state() == AnalysisState::Complete);
        assert_eq!(jpeg.qr_codes.len(), 1);
        assert!(jpeg.qr_codes[0].url_analysis.is_some());

        let near_limit = inspect_fixture(NEAR_LIMIT_PNG, "near-limit.png");
        assert_eq!(
            near_limit.qr_codes[0]
                .payload
                .as_ref()
                .map(|payload| payload.byte_length),
            Some(2_900)
        );
        assert!(has_limitation(&near_limit, "qr.text_display_limit"));
    }

    #[test]
    fn obvious_text_payload_classes_are_distinct() {
        let cases = [
            ("mailto:person@example.com", QrPayloadKind::EmailUri),
            ("tel:+15550100", QrPayloadKind::TelephoneUri),
            ("sms:+15550100", QrPayloadKind::SmsUri),
            ("example-app:opaque", QrPayloadKind::CustomScheme),
            ("data:text/html,hello", QrPayloadKind::Url),
        ];
        for (payload, expected) in cases {
            assert!(classify_payload(payload.as_bytes()).payload.kind == expected);
        }
    }

    #[test]
    fn zero_multiple_and_bounded_multiple_codes_are_explicit() {
        let zero = inspect_fixture(NO_CODE_PNG, "no-code.png");
        assert!(zero.metadata.analysis_state() == AnalysisState::Complete);
        assert!(zero.qr_codes.is_empty());

        let multiple = inspect_fixture(MULTIPLE_PNG, "multiple.png");
        assert_eq!(multiple.qr_codes.len(), 2);

        let bounded = inspect_fixture(OVER_LIMIT_MULTIPLE_PNG, "many.png");
        assert_eq!(bounded.qr_codes.len(), MAX_QR_CODES);
        assert!(bounded.metadata.analysis_state() == AnalysisState::Partial);
        assert!(has_limitation(&bounded, "qr.code_count_limit"));
        assert!(bounded.observations.iter().any(|observation| {
            observation.code == "qr.detection"
                && observation.fields.get("codes_found") == Some(&ObservationValue::Unsigned(8))
        }));
    }

    #[test]
    fn malformed_images_and_qr_do_not_become_successful_decodes() {
        for (bytes, filename) in [
            (TRUNCATED_PNG, "truncated.png"),
            (TRUNCATED_JPEG, "truncated.jpg"),
        ] {
            let report = inspect_fixture(bytes, filename);
            assert!(report.metadata.analysis_state() == AnalysisState::Failed);
            assert!(report.qr_codes.is_empty());
        }

        let corrupt = inspect_fixture(CORRUPT_QR_PNG, "corrupt-qr.png");
        assert!(corrupt.metadata.analysis_state() == AnalysisState::Partial);
        assert_eq!(corrupt.qr_codes.len(), 1);
        assert!(!corrupt.qr_codes[0].decode_succeeded);
        assert!(has_limitation(&corrupt, "qr.code_decode_failed"));
    }

    #[test]
    fn width_and_pixel_limits_are_checked_before_raster_decode() {
        let too_wide = png_with_dimensions(MAX_IMAGE_WIDTH.saturating_add(1), 1);
        let width_report = inspect_fixture(&too_wide, "too-wide.png");
        assert!(width_report.metadata.analysis_state() == AnalysisState::Failed);
        assert!(has_limitation(&width_report, "qr.image.dimension_limit"));

        let too_tall = png_with_dimensions(1, super::MAX_IMAGE_HEIGHT.saturating_add(1));
        let height_report = inspect_fixture(&too_tall, "too-tall.png");
        assert!(height_report.metadata.analysis_state() == AnalysisState::Failed);
        assert!(has_limitation(&height_report, "qr.image.dimension_limit"));

        let too_many_pixels = png_with_dimensions(8_000, 4_001);
        let pixel_report = inspect_fixture(&too_many_pixels, "too-many-pixels.png");
        assert!(pixel_report.metadata.analysis_state() == AnalysisState::Failed);
        assert!(has_limitation(&pixel_report, "qr.image.pixel_limit"));
    }

    #[test]
    fn unsupported_raster_format_is_an_explicit_failure() {
        let report = inspect_fixture(b"GIF89a synthetic test", "image.gif");
        assert!(report.metadata.analysis_state() == AnalysisState::Failed);
        assert!(has_limitation(&report, "qr.image.unsupported_format"));
    }
}
