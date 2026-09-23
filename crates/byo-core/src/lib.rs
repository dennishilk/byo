//! Platform-neutral, fully offline analysis for BYO — Before You Open.
//!
//! The core treats supplied names, bytes, and URLs as hostile data. It does not
//! discover paths, invoke operating-system integrations, launch content, or
//! perform network activity.

#![forbid(unsafe_code)]

mod display;
mod file_analysis;
mod filename;
mod qr_analysis;
mod report;
mod signature;
mod url_analysis;

pub use display::{escape_for_terminal, escape_json_invisibles};
pub use file_analysis::{inspect_file, FileContext, MAX_HEADER_BYTES, NON_STREAMING_FILE_LIMIT};
pub use filename::{
    analyze_filename, CharacterKind, FilenameAnalysis, FilenameAnalysisError, SpecialCharacter,
    EXECUTABLE_EXTENSIONS, MAX_FILENAME_BYTES,
};
pub use qr_analysis::{
    inspect_qr_image, QrImageContext, MAX_DECODED_IMAGE_PIXELS, MAX_ENCODED_IMAGE_BYTES,
    MAX_IMAGE_HEIGHT, MAX_IMAGE_WIDTH, MAX_QR_CODES, MAX_QR_PAYLOAD_BYTES,
};
pub use report::{
    AnalysisState, Finding, InputKind, InputSubject, Limitation, Observation, ObservationValue,
    QrCodeReport, QrPayload, QrPayloadKind, Report, ReportMetadata, Severity, WifiPayload,
    ANALYZER_VERSION, REPORT_SCHEMA_VERSION,
};
pub use signature::{detect_signatures, DetectedSignature, SignatureKind};
pub use url_analysis::{inspect_url, MAX_URL_INPUT_BYTES};

/// The product name shared by all BYO frontends.
pub const PRODUCT_NAME: &str = "BYO — Before You Open";

/// The current public project status.
pub const PROJECT_STATUS: &str = "PRE-ALPHA";

#[cfg(test)]
mod tests {
    use super::{PRODUCT_NAME, PROJECT_STATUS};

    #[test]
    fn project_identity_is_stable() {
        assert_eq!(PRODUCT_NAME, "BYO — Before You Open");
        assert_eq!(PROJECT_STATUS, "PRE-ALPHA");
    }
}
