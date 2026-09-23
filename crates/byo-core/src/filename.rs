use std::collections::BTreeMap;

use crate::display::{is_bidi_control, is_security_invisible};
use crate::{ObservationValue, Report, Severity};

pub const MAX_FILENAME_BYTES: usize = 4096;
const MAX_REPORTED_EXTENSIONS: usize = 16;
const MAX_REPORTED_SPECIAL_CHARACTERS: usize = 64;

/// Extensions whose final position can make a file executable, scriptable, or
/// directly launchable on common desktop systems. Presence is not a malware
/// verdict; it is a property worth showing accurately.
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "com", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "msi", "lnk",
    "desktop", "sh",
];

const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "jpg", "jpeg", "png",
    "gif", "webp", "bmp", "svg", "zip", "7z", "rar", "gz", "tar", "mp3", "wav", "mp4", "mov",
    "avi",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CharacterKind {
    BidirectionalControl,
    Invisible,
    TerminalControl,
}

impl CharacterKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BidirectionalControl => "bidirectional control",
            Self::Invisible => "invisible character",
            Self::TerminalControl => "terminal control",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SpecialCharacter {
    pub code_point: u32,
    /// One-based Unicode scalar position in the logical filename.
    pub logical_position: usize,
    pub description: &'static str,
    pub kind: CharacterKind,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FilenameAnalysis {
    pub final_extension: Option<String>,
    pub preceding_extensions: Vec<String>,
    pub extensions_truncated: bool,
    pub executable_trailing_extension: bool,
    pub deceptive_double_extension: bool,
    pub special_characters: Vec<SpecialCharacter>,
    pub special_characters_truncated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilenameAnalysisError {
    TooLong,
}

pub fn analyze_filename(filename: &str) -> Result<FilenameAnalysis, FilenameAnalysisError> {
    if filename.len() > MAX_FILENAME_BYTES {
        return Err(FilenameAnalysisError::TooLong);
    }

    let (final_extension, preceding_extensions, extensions_truncated) = split_extensions(filename);
    let executable_trailing_extension = final_extension
        .as_deref()
        .is_some_and(|extension| contains_ascii_case_insensitive(EXECUTABLE_EXTENSIONS, extension));
    let deceptive_double_extension = executable_trailing_extension
        && preceding_extensions
            .last()
            .is_some_and(|extension| contains_ascii_case_insensitive(DECOY_EXTENSIONS, extension));

    let mut special_characters = Vec::new();
    let mut special_characters_truncated = false;
    for (index, character) in filename.chars().enumerate() {
        let kind = if is_bidi_control(character) {
            Some(CharacterKind::BidirectionalControl)
        } else if is_security_invisible(character) {
            Some(CharacterKind::Invisible)
        } else if character.is_control() {
            Some(CharacterKind::TerminalControl)
        } else {
            None
        };

        if let Some(kind) = kind {
            if special_characters.len() == MAX_REPORTED_SPECIAL_CHARACTERS {
                special_characters_truncated = true;
                break;
            }
            special_characters.push(SpecialCharacter {
                code_point: u32::from(character),
                logical_position: index.saturating_add(1),
                description: describe_character(character),
                kind,
            });
        }
    }

    Ok(FilenameAnalysis {
        final_extension,
        preceding_extensions,
        extensions_truncated,
        executable_trailing_extension,
        deceptive_double_extension,
        special_characters,
        special_characters_truncated,
    })
}

fn split_extensions(filename: &str) -> (Option<String>, Vec<String>, bool) {
    let single_leading_dot = filename
        .strip_prefix('.')
        .is_some_and(|remainder| !remainder.contains('.'));
    if filename.is_empty() || filename.ends_with('.') || single_leading_dot {
        return (None, Vec::new(), false);
    }

    let components: Vec<&str> = filename.split('.').collect();
    if components.len() < 2 {
        return (None, Vec::new(), false);
    }

    let final_extension = components
        .last()
        .filter(|component| !component.is_empty())
        .map(|component| component.to_ascii_lowercase());

    if final_extension.is_none() {
        return (None, Vec::new(), false);
    }

    let available_preceding = components.len().saturating_sub(2);
    let skip = available_preceding.saturating_sub(MAX_REPORTED_EXTENSIONS);
    let preceding_extensions = components
        .iter()
        .skip(1usize.saturating_add(skip))
        .take(available_preceding.min(MAX_REPORTED_EXTENSIONS))
        .filter(|component| !component.is_empty())
        .map(|component| component.to_ascii_lowercase())
        .collect();

    (
        final_extension,
        preceding_extensions,
        available_preceding > MAX_REPORTED_EXTENSIONS,
    )
}

fn contains_ascii_case_insensitive(haystack: &[&str], needle: &str) -> bool {
    haystack
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

const fn describe_character(character: char) -> &'static str {
    match character {
        '\n' => "LINE FEED",
        '\r' => "CARRIAGE RETURN",
        '\t' => "CHARACTER TABULATION",
        '\u{001b}' => "ESCAPE",
        '\u{007f}' => "DELETE",
        '\u{061c}' => "ARABIC LETTER MARK",
        '\u{00ad}' => "SOFT HYPHEN",
        '\u{00a0}' => "NO-BREAK SPACE",
        '\u{180e}' => "MONGOLIAN VOWEL SEPARATOR",
        '\u{200b}' => "ZERO WIDTH SPACE",
        '\u{200c}' => "ZERO WIDTH NON-JOINER",
        '\u{200d}' => "ZERO WIDTH JOINER",
        '\u{200e}' => "LEFT-TO-RIGHT MARK",
        '\u{200f}' => "RIGHT-TO-LEFT MARK",
        '\u{202a}' => "LEFT-TO-RIGHT EMBEDDING",
        '\u{202b}' => "RIGHT-TO-LEFT EMBEDDING",
        '\u{202c}' => "POP DIRECTIONAL FORMATTING",
        '\u{202d}' => "LEFT-TO-RIGHT OVERRIDE",
        '\u{202e}' => "RIGHT-TO-LEFT OVERRIDE",
        '\u{2028}' => "LINE SEPARATOR",
        '\u{2029}' => "PARAGRAPH SEPARATOR",
        '\u{202f}' => "NARROW NO-BREAK SPACE",
        '\u{2060}' => "WORD JOINER",
        '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
        '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
        '\u{2068}' => "FIRST STRONG ISOLATE",
        '\u{2069}' => "POP DIRECTIONAL ISOLATE",
        '\u{feff}' => "ZERO WIDTH NO-BREAK SPACE",
        '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}' => "VARIATION SELECTOR",
        _ => "CONTROL CHARACTER",
    }
}

pub(crate) struct FilenameEvidence {
    pub extension_observation_id: String,
    pub analysis: Option<FilenameAnalysis>,
}

pub(crate) fn append_filename_report(report: &mut Report, filename: &str) -> FilenameEvidence {
    let analysis = match analyze_filename(filename) {
        Ok(analysis) => analysis,
        Err(FilenameAnalysisError::TooLong) => {
            report.add_limitation(
                "filename.length_limit",
                "Filename analysis was skipped because the supplied name exceeded 4096 bytes.",
            );
            report.mark_partial();
            let mut fields = BTreeMap::new();
            fields.insert("analyzed".to_owned(), ObservationValue::from(false));
            let id = report.add_observation("filename.extension", "Filename extension", fields);
            return FilenameEvidence {
                extension_observation_id: id,
                analysis: None,
            };
        }
    };

    let mut extension_fields = BTreeMap::new();
    extension_fields.insert(
        "final".to_owned(),
        ObservationValue::from(
            analysis
                .final_extension
                .clone()
                .unwrap_or_else(|| "none".to_owned()),
        ),
    );
    extension_fields.insert(
        "preceding".to_owned(),
        ObservationValue::from(analysis.preceding_extensions.clone()),
    );
    extension_fields.insert(
        "has_extension".to_owned(),
        ObservationValue::from(analysis.final_extension.is_some()),
    );
    let extension_observation_id = report.add_observation(
        "filename.extension",
        "Filename extension structure",
        extension_fields,
    );

    if analysis.extensions_truncated {
        report.add_limitation(
            "filename.extension_count_limit",
            "Only the last 16 preceding extension components were retained.",
        );
        report.mark_partial();
    }

    if analysis.executable_trailing_extension {
        let mut fields = BTreeMap::new();
        if let Some(extension) = &analysis.final_extension {
            fields.insert(
                "extension".to_owned(),
                ObservationValue::from(extension.clone()),
            );
        }
        let executable_id = report.add_observation(
            "filename.executable_extension",
            "Executable or script-like trailing extension",
            fields,
        );

        if analysis.deceptive_double_extension {
            report.add_finding(
                "filename.trailing_executable_extension",
                Severity::Warning,
                "Document- or media-looking extension precedes an executable extension",
                "The final extension is executable or script-like; an earlier familiar extension does not determine the file's behavior.",
                vec![extension_observation_id.clone(), executable_id],
            );
        } else {
            report.add_finding(
                "filename.executable_extension",
                Severity::Attention,
                "Filename uses an executable or script-like extension",
                "This extension can represent launchable content on common systems. The extension alone does not establish intent.",
                vec![executable_id],
            );
        }
    }

    let mut bidi_ids = Vec::new();
    let mut invisible_ids = Vec::new();
    let mut terminal_ids = Vec::new();
    for special in &analysis.special_characters {
        let mut fields = BTreeMap::new();
        fields.insert(
            "code_point".to_owned(),
            ObservationValue::from(format!("U+{:04X}", special.code_point)),
        );
        fields.insert(
            "logical_position".to_owned(),
            ObservationValue::from(u64::try_from(special.logical_position).unwrap_or(u64::MAX)),
        );
        fields.insert(
            "description".to_owned(),
            ObservationValue::from(special.description),
        );
        fields.insert(
            "kind".to_owned(),
            ObservationValue::from(special.kind.as_str()),
        );

        let (code, title) = match special.kind {
            CharacterKind::BidirectionalControl => {
                ("filename.bidi_control", "Bidirectional display control")
            }
            CharacterKind::Invisible => (
                "filename.invisible_character",
                "Invisible filename character",
            ),
            CharacterKind::TerminalControl => {
                ("filename.terminal_control", "Terminal control in filename")
            }
        };
        let id = report.add_observation(code, title, fields);
        match special.kind {
            CharacterKind::BidirectionalControl => bidi_ids.push(id),
            CharacterKind::Invisible => invisible_ids.push(id),
            CharacterKind::TerminalControl => terminal_ids.push(id),
        }
    }

    if !bidi_ids.is_empty() {
        report.add_finding(
            "filename.bidi_control",
            Severity::Warning,
            "Filename contains bidirectional display controls",
            "These controls can make the displayed character order differ from the logical filename order.",
            bidi_ids,
        );
    }
    if !invisible_ids.is_empty() {
        report.add_finding(
            "filename.invisible_character",
            Severity::Attention,
            "Filename contains invisible formatting characters",
            "Invisible characters can make two different logical filenames appear similar.",
            invisible_ids,
        );
    }
    if !terminal_ids.is_empty() {
        report.add_finding(
            "filename.terminal_control",
            Severity::Warning,
            "Filename contains terminal control characters",
            "The characters are escaped for display so they cannot alter terminal formatting.",
            terminal_ids,
        );
    }

    if analysis.special_characters_truncated {
        report.add_limitation(
            "filename.special_character_limit",
            "More than 64 control or invisible characters were present; later occurrences were not individually reported.",
        );
        report.mark_partial();
    }

    FilenameEvidence {
        extension_observation_id,
        analysis: Some(analysis),
    }
}

#[cfg(test)]
mod tests {
    use super::{analyze_filename, CharacterKind};

    fn analysis(name: &str) -> super::FilenameAnalysis {
        match analyze_filename(name) {
            Ok(value) => value,
            Err(_) => panic!("test filename should remain inside the analyzer limit"),
        }
    }

    #[test]
    fn detects_deceptive_executable_extensions() {
        for name in ["invoice.pdf.exe", "photo.jpg.scr", "report.docx.js"] {
            let result = analysis(name);
            assert!(result.executable_trailing_extension);
            assert!(result.deceptive_double_extension);
        }
    }

    #[test]
    fn accepts_normal_compound_and_versioned_names() {
        for name in ["archive.tar.gz", "project.v1.2.txt"] {
            let result = analysis(name);
            assert!(!result.deceptive_double_extension);
        }
    }

    #[test]
    fn identifies_bidi_zero_width_and_terminal_controls() {
        let result = analysis("photo\u{202e}gpj.exe\u{200b}\n\u{001b}[31m");
        assert!(result
            .special_characters
            .iter()
            .any(|item| item.kind == CharacterKind::BidirectionalControl));
        assert!(result
            .special_characters
            .iter()
            .any(|item| item.kind == CharacterKind::Invisible));
        assert!(result
            .special_characters
            .iter()
            .any(|item| item.kind == CharacterKind::TerminalControl));
    }

    #[test]
    fn ordinary_non_ascii_filename_is_not_flagged() {
        let result = analysis("Katzenfoto-ä-猫.png");
        assert!(result.special_characters.is_empty());
    }

    #[test]
    fn reports_absent_extension() {
        assert!(analysis("README").final_extension.is_none());
        assert!(analysis(".bashrc").final_extension.is_none());
    }
}
