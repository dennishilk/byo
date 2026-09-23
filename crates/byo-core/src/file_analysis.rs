use std::collections::BTreeMap;
use std::io::{ErrorKind, Read};

use sha2::{Digest, Sha256};

use crate::filename::{append_filename_report, MAX_FILENAME_BYTES};
use crate::signature::{detect_signatures, SignatureKind};
use crate::{InputKind, ObservationValue, Report, Severity};

pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const NON_STREAMING_FILE_LIMIT: u64 = 1024 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct FileContext {
    pub filename: String,
    pub declared_size: u64,
    pub filename_was_lossy: bool,
    pub selected_via_symlink: bool,
}

impl FileContext {
    pub fn new(filename: impl Into<String>, declared_size: u64) -> Self {
        Self {
            filename: filename.into(),
            declared_size,
            filename_was_lossy: false,
            selected_via_symlink: false,
        }
    }
}

pub fn inspect_file<R: Read>(reader: &mut R, context: FileContext) -> Report {
    let filename_for_report = if context.filename.len() <= MAX_FILENAME_BYTES {
        context.filename.clone()
    } else {
        "<filename omitted: exceeds analysis limit>".to_owned()
    };
    let original_filename =
        (context.filename.len() <= MAX_FILENAME_BYTES).then(|| context.filename.clone());
    let mut report = Report::new(
        InputKind::File,
        original_filename,
        filename_for_report.clone(),
    );

    let mut name_fields = BTreeMap::new();
    name_fields.insert(
        "value".to_owned(),
        ObservationValue::from(filename_for_report),
    );
    report.add_observation("file.name", "Selected filename", name_fields);

    let mut size_fields = BTreeMap::new();
    size_fields.insert(
        "declared_bytes".to_owned(),
        ObservationValue::from(context.declared_size),
    );
    report.add_observation("file.size", "File size from opened handle", size_fields);

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
            "file.path.symlink",
            "Selected path is a symbolic link",
            fields,
        );
        report.add_limitation(
            "file.path.symlink_target",
            "The opened regular-file target was inspected; path canonicalization was not treated as evidence of trust.",
        );
    }

    let filename_evidence = append_filename_report(&mut report, &context.filename);

    if context.declared_size > NON_STREAMING_FILE_LIMIT {
        report.add_limitation(
            "file.non_streaming_size_limit",
            "The declared size exceeds the 1 GiB non-streaming ceiling. M1 performed only streaming hashing and bounded header inspection.",
        );
        report.mark_partial();
    }

    let header_capacity = match usize::try_from(
        context
            .declared_size
            .min(u64::try_from(MAX_HEADER_BYTES).unwrap_or(u64::MAX)),
    ) {
        Ok(value) => value,
        Err(_) => MAX_HEADER_BYTES,
    };
    let mut header = Vec::with_capacity(header_capacity);
    let mut buffer = [0_u8; MAX_HEADER_BYTES];
    let mut hasher = Sha256::new();
    let mut bytes_hashed = 0_u64;
    let mut read_error = false;

    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                read_error = true;
                report.add_limitation(
                    "file.read_error",
                    "Reading stopped before a clean end of input; the reported digest covers only the bytes read.",
                );
                report.mark_partial();
                break;
            }
        };

        if bytes_read > buffer.len() {
            report.add_limitation(
                "file.reader_contract_violation",
                "The input reader reported more bytes than the supplied buffer could contain.",
            );
            report.mark_failed();
            return report;
        }

        let Ok(increment) = u64::try_from(bytes_read) else {
            report.add_limitation(
                "file.byte_count_overflow",
                "The byte count could not be represented safely.",
            );
            report.mark_failed();
            return report;
        };
        let Some(updated_total) = bytes_hashed.checked_add(increment) else {
            report.add_limitation(
                "file.byte_count_overflow",
                "The byte count overflowed during streaming analysis.",
            );
            report.mark_failed();
            return report;
        };
        bytes_hashed = updated_total;
        hasher.update(&buffer[..bytes_read]);

        if header.len() < MAX_HEADER_BYTES {
            let remaining = MAX_HEADER_BYTES.saturating_sub(header.len());
            let copy_count = remaining.min(bytes_read);
            if let Some(prefix) = buffer.get(..copy_count) {
                header.extend_from_slice(prefix);
            }
        }
    }

    let digest = format!("{:x}", hasher.finalize());
    let hash_complete = !read_error && bytes_hashed == context.declared_size;
    let mut hash_fields = BTreeMap::new();
    hash_fields.insert("algorithm".to_owned(), "SHA-256".into());
    hash_fields.insert("digest".to_owned(), digest.into());
    hash_fields.insert("bytes_hashed".to_owned(), bytes_hashed.into());
    hash_fields.insert("complete_file".to_owned(), hash_complete.into());
    report.add_observation("file.sha256", "Streaming SHA-256 digest", hash_fields);

    if bytes_hashed != context.declared_size {
        report.add_limitation(
            "file.size_changed_or_incomplete",
            "The number of bytes read differed from the size reported by the opened handle.",
        );
        report.mark_partial();
    }

    let mut header_fields = BTreeMap::new();
    header_fields.insert(
        "bytes_read".to_owned(),
        ObservationValue::from(u64::try_from(header.len()).unwrap_or(u64::MAX)),
    );
    header_fields.insert(
        "maximum_bytes".to_owned(),
        ObservationValue::from(u64::try_from(MAX_HEADER_BYTES).unwrap_or(u64::MAX)),
    );
    report.add_observation(
        "file.header_window",
        "Bounded header inspection window",
        header_fields,
    );

    let signatures = detect_signatures(&header);
    if signatures.is_empty() {
        let mut fields = BTreeMap::new();
        fields.insert("recognized".to_owned(), false.into());
        report.add_observation(
            "file.signature.unknown",
            "No supported header signature identified",
            fields,
        );
        report.add_limitation(
            "file.signature_unknown",
            "M1 recognizes only a bounded set of common header signatures; unknown does not mean benign.",
        );
    } else {
        for signature in signatures {
            append_signature_report(
                &mut report,
                &signature.kind,
                &signature.evidence,
                filename_evidence.analysis.as_ref(),
                &filename_evidence.extension_observation_id,
            );
        }
    }

    report.add_limitation(
        "file.header_not_full_validation",
        "Header signatures are type evidence only. M1 does not validate the complete internal structure of the detected format.",
    );

    report
}

fn append_signature_report(
    report: &mut Report,
    kind: &SignatureKind,
    evidence: &str,
    filename: Option<&crate::FilenameAnalysis>,
    extension_observation_id: &str,
) {
    let mut fields = BTreeMap::new();
    fields.insert("format".to_owned(), kind.display_name().into());
    fields.insert("evidence".to_owned(), evidence.into());
    let signature_id = report.add_observation(kind.code(), "Detected header signature", fields);

    if kind.is_executable_format() {
        report.add_finding(
            "file.executable_format",
            Severity::Attention,
            "Header indicates an executable or script format",
            "This is a format observation, not a determination that the file is malicious.",
            vec![signature_id.clone()],
        );
    }

    if kind.is_archive_or_container() {
        report.add_limitation(
            "file.container_contents_not_inspected",
            "Archive and container contents were not opened, extracted, or recursively inspected in M1.",
        );
    }

    let Some(final_extension) = filename.and_then(|analysis| analysis.final_extension.as_deref())
    else {
        return;
    };

    if !kind.extension_is_compatible(final_extension) {
        report.add_finding(
            "file.extension_signature_mismatch",
            Severity::Warning,
            "Filename extension and detected header signature differ",
            "The final filename extension is not normally associated with the detected header signature. This inconsistency is not a malware verdict.",
            vec![extension_observation_id.to_owned(), signature_id],
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{inspect_file, FileContext};

    fn inspect(name: &str, bytes: &[u8]) -> crate::Report {
        let mut reader = Cursor::new(bytes);
        inspect_file(
            &mut reader,
            FileContext::new(name, u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
        )
    }

    fn has_finding(report: &crate::Report, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    fn sha256(report: &crate::Report) -> Option<&str> {
        report
            .observations
            .iter()
            .find(|observation| observation.code == "file.sha256")
            .and_then(|observation| observation.fields.get("digest"))
            .and_then(|value| match value {
                crate::ObservationValue::Text(text) => Some(text.as_str()),
                _ => None,
            })
    }

    #[test]
    fn sha256_matches_known_vectors() {
        let empty = inspect("empty.bin", b"");
        assert_eq!(
            sha256(&empty),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        let abc = inspect("abc.txt", b"abc");
        assert_eq!(
            sha256(&abc),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn extension_and_signature_comparison_is_explainable() {
        let png = b"\x89PNG\r\n\x1a\nrest";
        assert!(!has_finding(
            &inspect("cat.png", png),
            "file.extension_signature_mismatch"
        ));
        assert!(has_finding(
            &inspect("report.pdf", png),
            "file.extension_signature_mismatch"
        ));

        let mut pe = vec![0_u8; 132];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&128_u32.to_le_bytes());
        pe[128..132].copy_from_slice(b"PE\0\0");
        assert!(has_finding(
            &inspect("photo.jpg", &pe),
            "file.extension_signature_mismatch"
        ));
    }

    #[test]
    fn zip_backed_office_extension_is_not_called_a_mismatch() {
        let report = inspect("report.docx", b"PK\x03\x04tiny synthetic data");
        assert!(!has_finding(&report, "file.extension_signature_mismatch"));
        assert!(report
            .limitations
            .iter()
            .any(|item| item.code == "file.container_contents_not_inspected"));
    }
}
