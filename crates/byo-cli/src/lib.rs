#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use byo_core::{
    escape_for_terminal, escape_json_invisibles, inspect_file, inspect_qr_image, AnalysisState,
    FileContext, InputKind, ObservationValue, QrImageContext, Report, MAX_ENCODED_IMAGE_BYTES,
    MAX_FILENAME_BYTES,
};

pub fn inspect_file_path(path: &Path) -> Report {
    let filename_os = path.file_name().unwrap_or(path.as_os_str());
    let filename_was_lossy = filename_os.to_str().is_none();
    let filename = filename_os.to_string_lossy().into_owned();

    let selected_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return failed_file_report(
                filename,
                "file.path.metadata_failed",
                "Metadata for the selected path could not be read.",
            )
        }
    };
    let selected_via_symlink = selected_metadata.file_type().is_symlink();

    let target_metadata = if selected_via_symlink {
        match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => {
                return failed_file_report(
                    filename,
                    "file.path.symlink_target_failed",
                    "The symbolic-link target could not be inspected.",
                )
            }
        }
    } else {
        selected_metadata
    };

    if target_metadata.is_dir() {
        return failed_file_report(
            filename,
            "file.path.directory_rejected",
            "Directories are not file-analysis inputs in M1.",
        );
    }
    if !target_metadata.file_type().is_file() {
        return failed_file_report(
            filename,
            "file.path.special_file_rejected",
            "The selected path is not a regular file; devices, sockets, pipes, and other special files are rejected by default.",
        );
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            return failed_file_report(
                filename,
                "file.path.open_failed",
                "The selected file could not be opened read-only.",
            )
        }
    };
    let opened_metadata = match file.metadata() {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return failed_file_report(
                filename,
                "file.path.changed_type",
                "The opened handle did not refer to a regular file.",
            )
        }
        Err(_) => {
            return failed_file_report(
                filename,
                "file.path.opened_metadata_failed",
                "Metadata for the opened read-only handle could not be read.",
            )
        }
    };

    let initial_size = target_metadata.len();
    let opened_size = opened_metadata.len();
    let opened_modified = opened_metadata.modified().ok();
    let mut context = FileContext::new(filename, opened_size);
    context.filename_was_lossy = filename_was_lossy;
    context.selected_via_symlink = selected_via_symlink;
    let mut report = inspect_file(&mut file, context);

    if initial_size != opened_size {
        report.add_limitation(
            "file.path.changed_before_open",
            "The target size changed between initial path metadata and the opened read-only handle.",
        );
        report.mark_partial();
    }

    match file.metadata() {
        Ok(after) => {
            let modified_changed = match (opened_modified, after.modified().ok()) {
                (Some(before), Some(current)) => before != current,
                _ => false,
            };
            if after.len() != opened_size || modified_changed {
                report.add_limitation(
                    "file.path.changed_during_analysis",
                    "File metadata changed while analysis was running; observations may describe different moments.",
                );
                report.mark_partial();
            }
        }
        Err(_) => {
            report.add_limitation(
                "file.path.final_metadata_failed",
                "Final metadata could not be read, so concurrent file changes could not be checked.",
            );
            report.mark_partial();
        }
    }

    report
}

pub fn inspect_qr_path(path: &Path) -> Report {
    let filename_os = path.file_name().unwrap_or(path.as_os_str());
    let filename_was_lossy = filename_os.to_str().is_none();
    let filename = filename_os.to_string_lossy().into_owned();

    let selected_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return failed_qr_report(
                filename,
                "qr.path.metadata_failed",
                "Metadata for the selected QR image path could not be read.",
            )
        }
    };
    let selected_via_symlink = selected_metadata.file_type().is_symlink();
    let target_metadata = if selected_via_symlink {
        match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => {
                return failed_qr_report(
                    filename,
                    "qr.path.symlink_target_failed",
                    "The symbolic-link target could not be inspected.",
                )
            }
        }
    } else {
        selected_metadata
    };

    if target_metadata.is_dir() {
        return failed_qr_report(
            filename,
            "qr.path.directory_rejected",
            "Directories are not QR image-analysis inputs.",
        );
    }
    if !target_metadata.file_type().is_file() {
        return failed_qr_report(
            filename,
            "qr.path.special_file_rejected",
            "The selected path is not a regular file; devices, sockets, pipes, and other special files are rejected by default.",
        );
    }
    if target_metadata.len() > MAX_ENCODED_IMAGE_BYTES {
        return failed_qr_report(
            filename,
            "qr.image.encoded_size_limit",
            "QR image decoding was refused before reading because the encoded source exceeded the 32 MiB limit.",
        );
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            return failed_qr_report(
                filename,
                "qr.path.open_failed",
                "The selected QR image could not be opened read-only.",
            )
        }
    };
    let opened_metadata = match file.metadata() {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return failed_qr_report(
                filename,
                "qr.path.changed_type",
                "The opened handle did not refer to a regular file.",
            )
        }
        Err(_) => {
            return failed_qr_report(
                filename,
                "qr.path.opened_metadata_failed",
                "Metadata for the opened read-only QR image handle could not be read.",
            )
        }
    };
    if opened_metadata.len() > MAX_ENCODED_IMAGE_BYTES {
        return failed_qr_report(
            filename,
            "qr.image.encoded_size_limit",
            "QR image decoding was refused before reading because the opened source exceeded the 32 MiB limit.",
        );
    }

    let opened_size = opened_metadata.len();
    let opened_modified = opened_metadata.modified().ok();
    let read_limit = MAX_ENCODED_IMAGE_BYTES.saturating_add(1);
    let mut encoded = Vec::new();
    if (&mut file)
        .take(read_limit)
        .read_to_end(&mut encoded)
        .is_err()
    {
        return failed_qr_report(
            filename,
            "qr.path.read_failed",
            "The selected QR image could not be read completely.",
        );
    }
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_ENCODED_IMAGE_BYTES {
        return failed_qr_report(
            filename,
            "qr.image.encoded_size_limit",
            "QR image decoding was refused because the source grew beyond the 32 MiB limit while being read.",
        );
    }

    let mut context = QrImageContext::new(filename, opened_size);
    context.filename_was_lossy = filename_was_lossy;
    context.selected_via_symlink = selected_via_symlink;
    let mut report = inspect_qr_image(&encoded, context);

    if target_metadata.len() != opened_size {
        report.add_limitation(
            "qr.path.changed_before_open",
            "The target size changed between initial path metadata and the opened read-only handle.",
        );
        report.mark_partial();
    }
    match file.metadata() {
        Ok(after) => {
            let modified_changed = match (opened_modified, after.modified().ok()) {
                (Some(before), Some(current)) => before != current,
                _ => false,
            };
            if after.len() != opened_size || modified_changed {
                report.add_limitation(
                    "qr.path.changed_during_analysis",
                    "QR image metadata changed while analysis was running; observations may describe different moments.",
                );
                report.mark_partial();
            }
        }
        Err(_) => {
            report.add_limitation(
                "qr.path.final_metadata_failed",
                "Final metadata could not be read, so concurrent QR image changes could not be checked.",
            );
            report.mark_partial();
        }
    }

    report
}

fn failed_file_report(filename: String, code: &str, explanation: &str) -> Report {
    let stored_filename = (filename.len() <= MAX_FILENAME_BYTES).then(|| filename.clone());
    let display = if stored_filename.is_some() {
        filename
    } else {
        "<filename omitted: exceeds analysis limit>".to_owned()
    };
    let mut report = Report::new(InputKind::File, stored_filename, display);
    report.add_limitation(code, explanation);
    report.mark_failed();
    report
}

fn failed_qr_report(filename: String, code: &str, explanation: &str) -> Report {
    let stored_filename = (filename.len() <= MAX_FILENAME_BYTES).then(|| filename.clone());
    let display = if stored_filename.is_some() {
        filename
    } else {
        "<filename omitted: exceeds analysis limit>".to_owned()
    };
    let mut report = Report::new(InputKind::QrImage, stored_filename, display);
    report.add_limitation(code, explanation);
    report.add_limitation(
        "qr.offline_scope",
        "No image content was opened externally, executed, transmitted, or navigated to.",
    );
    report.mark_failed();
    report
}

pub fn render_human(report: &Report) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "BYO — Before You Open\n");
    let _ = writeln!(output, "Input");
    let _ = writeln!(output, "  Type: {}", report.subject.kind.as_str());
    let _ = writeln!(
        output,
        "  Value: {}",
        escape_for_terminal(&report.subject.display)
    );

    let _ = writeln!(output, "\nObservations");
    if report.observations.is_empty() {
        let _ = writeln!(output, "  (none)");
    } else {
        for observation in &report.observations {
            let _ = writeln!(
                output,
                "  [{}] {} ({})",
                escape_for_terminal(&observation.id),
                escape_for_terminal(&observation.title),
                escape_for_terminal(&observation.code)
            );
            for (name, value) in &observation.fields {
                let _ = writeln!(
                    output,
                    "    {}: {}",
                    escape_for_terminal(name),
                    render_observation_value(value)
                );
            }
        }
    }

    if report.subject.kind == InputKind::QrImage {
        render_qr_codes(&mut output, report);
    }

    let _ = writeln!(output, "\nFindings");
    if report.findings.is_empty() {
        let _ = writeln!(output, "  (none)");
    } else {
        for finding in &report.findings {
            let _ = writeln!(
                output,
                "  [{}] {} ({})",
                finding.severity.as_str().to_ascii_uppercase(),
                escape_for_terminal(&finding.title),
                escape_for_terminal(&finding.code)
            );
            let _ = writeln!(output, "    {}", escape_for_terminal(&finding.explanation));
            if !finding.observation_ids.is_empty() {
                let evidence = finding
                    .observation_ids
                    .iter()
                    .map(|id| escape_for_terminal(id))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(output, "    Evidence: {evidence}");
            }
        }
    }

    let _ = writeln!(output, "\nLimitations");
    if report.limitations.is_empty() {
        let _ = writeln!(output, "  (none)");
    } else {
        for limitation in &report.limitations {
            let _ = writeln!(
                output,
                "  - {} ({}): {}",
                escape_for_terminal(&limitation.code),
                report.metadata.analysis_state().as_str(),
                escape_for_terminal(&limitation.explanation)
            );
        }
    }

    let _ = writeln!(output, "\nAnalysis");
    let _ = writeln!(
        output,
        "  State: {}",
        report.metadata.analysis_state().as_str()
    );
    let _ = writeln!(
        output,
        "  Local: {}",
        if report.metadata.is_local() {
            "yes"
        } else {
            "no"
        }
    );
    let _ = writeln!(
        output,
        "  Network activity: {}",
        if report.metadata.network_activity() {
            "present"
        } else {
            "none"
        }
    );
    let _ = writeln!(
        output,
        "  Report schema: {}",
        escape_for_terminal(&report.metadata.schema_version)
    );
    let _ = writeln!(
        output,
        "  Analyzer: {}",
        escape_for_terminal(&report.metadata.analyzer_version)
    );

    output
}

fn render_qr_codes(output: &mut String, report: &Report) {
    let _ = writeln!(output, "\nQR codes");
    if report.qr_codes.is_empty() {
        let _ = writeln!(output, "  (none detected or decoded)");
        return;
    }

    for code in &report.qr_codes {
        let _ = writeln!(output, "  QR #{}", code.index);
        let _ = writeln!(
            output,
            "    Decode: {}",
            if code.decode_succeeded {
                "succeeded"
            } else {
                "failed"
            }
        );
        if let Some(payload) = &code.payload {
            let _ = writeln!(output, "    Payload bytes: {}", payload.byte_length);
            let _ = writeln!(
                output,
                "    Valid UTF-8: {}",
                if payload.valid_utf8 { "yes" } else { "no" }
            );
            let _ = writeln!(output, "    Type: {}", payload.kind.as_str());
            let _ = writeln!(
                output,
                "    Payload: {}",
                escape_for_terminal(&payload.display)
            );
            if let Some(hexadecimal) = &payload.hexadecimal {
                let _ = writeln!(
                    output,
                    "    Hexadecimal: {}",
                    escape_for_terminal(hexadecimal)
                );
            }
            if let Some(wifi) = &payload.wifi {
                if let Some(authentication_type) = &wifi.authentication_type {
                    let _ = writeln!(
                        output,
                        "    Wi-Fi authentication: {}",
                        escape_for_terminal(authentication_type)
                    );
                }
                if let Some(ssid) = &wifi.ssid {
                    let _ = writeln!(output, "    Wi-Fi SSID: {}", escape_for_terminal(ssid));
                }
                let _ = writeln!(
                    output,
                    "    Wi-Fi password present: {}",
                    if wifi.password_present { "yes" } else { "no" }
                );
                if let Some(hidden) = wifi.hidden {
                    let _ = writeln!(
                        output,
                        "    Wi-Fi hidden network: {}",
                        if hidden { "yes" } else { "no" }
                    );
                }
            }
        }

        if let Some(url_report) = &code.url_analysis {
            let _ = writeln!(output, "\n    URL analysis");
            let _ = writeln!(
                output,
                "      Value: {}",
                escape_for_terminal(&url_report.subject.display)
            );
            for observation in &url_report.observations {
                let _ = writeln!(
                    output,
                    "      [{}] {} ({})",
                    escape_for_terminal(&observation.id),
                    escape_for_terminal(&observation.title),
                    escape_for_terminal(&observation.code)
                );
                for (name, value) in &observation.fields {
                    let _ = writeln!(
                        output,
                        "        {}: {}",
                        escape_for_terminal(name),
                        render_observation_value(value)
                    );
                }
            }
            if !url_report.findings.is_empty() {
                let _ = writeln!(output, "      Findings");
                for finding in &url_report.findings {
                    let _ = writeln!(
                        output,
                        "        [{}] {} ({})",
                        finding.severity.as_str().to_ascii_uppercase(),
                        escape_for_terminal(&finding.title),
                        escape_for_terminal(&finding.code)
                    );
                    let _ = writeln!(
                        output,
                        "          {}",
                        escape_for_terminal(&finding.explanation)
                    );
                }
            }
            if !url_report.limitations.is_empty() {
                let _ = writeln!(output, "      Limitations");
                for limitation in &url_report.limitations {
                    let _ = writeln!(
                        output,
                        "        - {}: {}",
                        escape_for_terminal(&limitation.code),
                        escape_for_terminal(&limitation.explanation)
                    );
                }
            }
        }

        for limitation in &code.limitations {
            let _ = writeln!(
                output,
                "    Limitation: {}: {}",
                escape_for_terminal(&limitation.code),
                escape_for_terminal(&limitation.explanation)
            );
        }
    }
}

fn render_observation_value(value: &ObservationValue) -> String {
    match value {
        ObservationValue::Text(text) => escape_for_terminal(text),
        ObservationValue::Boolean(value) => {
            if *value {
                "yes".to_owned()
            } else {
                "no".to_owned()
            }
        }
        ObservationValue::Unsigned(value) => value.to_string(),
        ObservationValue::TextList(values) => {
            if values.is_empty() {
                "(none)".to_owned()
            } else {
                values
                    .iter()
                    .map(|value| escape_for_terminal(value))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        }
    }
}

pub fn render_json(report: &Report) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report).map(|json| escape_json_invisibles(&json))
}

pub const fn report_exit_code(report: &Report) -> u8 {
    match report.metadata.analysis_state() {
        AnalysisState::Failed => 1,
        AnalysisState::Complete | AnalysisState::Partial => 0,
    }
}

#[cfg(test)]
mod tests {
    use byo_core::{inspect_url, InputKind, Report};

    use super::{render_human, render_json};

    #[test]
    fn human_renderer_escapes_hostile_subject_text() {
        let report = Report::new(
            InputKind::File,
            Some("bad\n\u{001b}[31m.txt".to_owned()),
            "bad\n\u{001b}[31m.txt",
        );
        let rendered = render_human(&report);
        assert!(rendered.contains("bad\\n\\x1B[31m.txt"));
        assert!(!rendered.contains("bad\n\u{001b}"));
    }

    #[test]
    fn ordinary_output_and_json_do_not_expose_url_password() {
        let secret = "cli-test-secret";
        let report = inspect_url(&format!("https://user:{secret}@example.com/"));
        let human = render_human(&report);
        assert!(!human.contains(secret));
        let json = match render_json(&report) {
            Ok(value) => value,
            Err(error) => panic!("JSON serialization failed: {error}"),
        };
        assert!(!json.contains(secret));
        assert!(json.contains("network_activity"));
    }

    #[test]
    fn json_renderer_does_not_emit_raw_bidi_controls() {
        let report = Report::new(
            InputKind::File,
            Some("photo\u{202e}gpj.exe".to_owned()),
            "photo\u{202e}gpj.exe",
        );
        let json = match render_json(&report) {
            Ok(value) => value,
            Err(error) => panic!("JSON serialization failed: {error}"),
        };
        assert!(!json.contains('\u{202e}'));
        assert!(json.contains("\\u202E"));
    }
}
