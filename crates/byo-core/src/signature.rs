#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    Pe,
    Elf,
    MachO,
    Pdf,
    Zip,
    Png,
    Jpeg,
    Gif,
    Gzip,
    SevenZip,
    Rar,
    WebP,
    ScriptShebang,
}

impl SignatureKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pe => "file.signature.pe",
            Self::Elf => "file.signature.elf",
            Self::MachO => "file.signature.macho",
            Self::Pdf => "file.signature.pdf",
            Self::Zip => "file.signature.zip",
            Self::Png => "file.signature.png",
            Self::Jpeg => "file.signature.jpeg",
            Self::Gif => "file.signature.gif",
            Self::Gzip => "file.signature.gzip",
            Self::SevenZip => "file.signature.7z",
            Self::Rar => "file.signature.rar",
            Self::WebP => "file.signature.webp",
            Self::ScriptShebang => "file.signature.shebang",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Pe => "PE / Windows executable",
            Self::Elf => "ELF executable or object",
            Self::MachO => "Mach-O executable or universal binary",
            Self::Pdf => "PDF document",
            Self::Zip => "ZIP-compatible container",
            Self::Png => "PNG image",
            Self::Jpeg => "JPEG image",
            Self::Gif => "GIF image",
            Self::Gzip => "gzip stream",
            Self::SevenZip => "7z archive",
            Self::Rar => "RAR archive",
            Self::WebP => "WebP image",
            Self::ScriptShebang => "script shebang",
        }
    }

    pub const fn is_executable_format(self) -> bool {
        matches!(
            self,
            Self::Pe | Self::Elf | Self::MachO | Self::ScriptShebang
        )
    }

    pub const fn is_archive_or_container(self) -> bool {
        matches!(self, Self::Zip | Self::Gzip | Self::SevenZip | Self::Rar)
    }

    pub(crate) fn extension_is_compatible(self, extension: &str) -> bool {
        let expected: &[&str] = match self {
            Self::Pe => &["exe", "dll", "sys", "scr", "cpl", "ocx"],
            Self::Elf => &["elf", "so", "bin", "run", "out"],
            Self::MachO => &["app", "dylib", "bundle", "bin"],
            Self::Pdf => &["pdf"],
            Self::Zip => &[
                "zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub",
            ],
            Self::Png => &["png"],
            Self::Jpeg => &["jpg", "jpeg", "jpe"],
            Self::Gif => &["gif"],
            Self::Gzip => &["gz", "tgz"],
            Self::SevenZip => &["7z"],
            Self::Rar => &["rar"],
            Self::WebP => &["webp"],
            Self::ScriptShebang => &["sh", "bash", "zsh", "py", "pl", "rb", "js"],
        };
        expected
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DetectedSignature {
    pub kind: SignatureKind,
    pub evidence: String,
}

pub fn detect_signatures(header: &[u8]) -> Vec<DetectedSignature> {
    let mut detected = Vec::new();

    if is_pe(header) {
        detected.push(signature(
            SignatureKind::Pe,
            "MZ header with a bounded PE signature reference",
        ));
    }
    if header.starts_with(b"\x7fELF") {
        detected.push(signature(SignatureKind::Elf, "7F 45 4C 46"));
    }
    if is_macho(header) {
        detected.push(signature(
            SignatureKind::MachO,
            "Mach-O or fat-binary magic",
        ));
    }
    if header.starts_with(b"%PDF-") {
        detected.push(signature(SignatureKind::Pdf, "25 50 44 46 2D"));
    }
    if is_zip(header) {
        detected.push(signature(SignatureKind::Zip, "PK ZIP-family header"));
    }
    if header.starts_with(b"\x89PNG\r\n\x1a\n") {
        detected.push(signature(SignatureKind::Png, "PNG eight-byte signature"));
    }
    if header.starts_with(b"\xff\xd8\xff") {
        detected.push(signature(SignatureKind::Jpeg, "FF D8 FF"));
    }
    if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
        detected.push(signature(SignatureKind::Gif, "GIF87a or GIF89a"));
    }
    if header.starts_with(b"\x1f\x8b") {
        detected.push(signature(SignatureKind::Gzip, "1F 8B"));
    }
    if header.starts_with(b"7z\xbc\xaf\x27\x1c") {
        detected.push(signature(SignatureKind::SevenZip, "37 7A BC AF 27 1C"));
    }
    if header.starts_with(b"Rar!\x1a\x07\x00") || header.starts_with(b"Rar!\x1a\x07\x01\x00") {
        detected.push(signature(SignatureKind::Rar, "RAR 4 or RAR 5 signature"));
    }
    if header.get(..4) == Some(b"RIFF") && header.get(8..12) == Some(b"WEBP") {
        detected.push(signature(SignatureKind::WebP, "RIFF container marked WEBP"));
    }
    if header.starts_with(b"#!") {
        let evidence = shebang_evidence(header);
        detected.push(DetectedSignature {
            kind: SignatureKind::ScriptShebang,
            evidence,
        });
    }

    detected
}

fn signature(kind: SignatureKind, evidence: &str) -> DetectedSignature {
    DetectedSignature {
        kind,
        evidence: evidence.to_owned(),
    }
}

fn is_pe(header: &[u8]) -> bool {
    if !header.starts_with(b"MZ") {
        return false;
    }

    let Some(offset_bytes) = header.get(0x3c..0x40) else {
        return false;
    };
    let Ok(offset_array) = <[u8; 4]>::try_from(offset_bytes) else {
        return false;
    };
    let Ok(pe_offset) = usize::try_from(u32::from_le_bytes(offset_array)) else {
        return false;
    };
    let Some(end) = pe_offset.checked_add(4) else {
        return false;
    };
    header.get(pe_offset..end) == Some(b"PE\0\0")
}

fn is_macho(header: &[u8]) -> bool {
    matches!(
        header.get(..4),
        Some(
            b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        )
    )
}

fn is_zip(header: &[u8]) -> bool {
    matches!(
        header.get(..4),
        Some(b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
    )
}

fn shebang_evidence(header: &[u8]) -> String {
    let capped = header.get(..header.len().min(258)).unwrap_or(header);
    let line_end = capped
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(capped.len());
    let line = capped.get(..line_end).unwrap_or(capped);
    String::from_utf8_lossy(line).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{detect_signatures, SignatureKind};

    fn has_kind(bytes: &[u8], expected: SignatureKind) -> bool {
        detect_signatures(bytes)
            .iter()
            .any(|signature| signature.kind == expected)
    }

    fn synthetic_pe() -> Vec<u8> {
        let mut bytes = vec![0_u8; 132];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&128_u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        bytes
    }

    #[test]
    fn detects_required_signatures() {
        assert!(has_kind(&synthetic_pe(), SignatureKind::Pe));
        assert!(has_kind(b"\x7fELFrest", SignatureKind::Elf));
        assert!(has_kind(b"%PDF-1.7", SignatureKind::Pdf));
        assert!(has_kind(b"\x89PNG\r\n\x1a\n", SignatureKind::Png));
        assert!(has_kind(b"\xff\xd8\xff\xe0", SignatureKind::Jpeg));
        assert!(has_kind(b"PK\x03\x04", SignatureKind::Zip));
    }

    #[test]
    fn rejects_truncated_and_unknown_signatures() {
        assert!(!has_kind(b"MZ", SignatureKind::Pe));
        assert!(detect_signatures(b"\x89PN").is_empty());
        assert!(detect_signatures(b"unknown").is_empty());
        assert!(detect_signatures(b"").is_empty());
    }
}
