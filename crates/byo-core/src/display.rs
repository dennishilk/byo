/// Escape untrusted text for a plain terminal without silently rewriting the
/// underlying value stored in the report.
pub fn escape_for_terminal(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len().min(4096));

    for character in input.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\0' => escaped.push_str("\\0"),
            '\u{001b}' => escaped.push_str("\\x1B"),
            value if value.is_control() || is_security_invisible(value) => {
                escaped.push_str("\\u{");
                escaped.push_str(&format!("{:04X}", u32::from(value)));
                escaped.push('}');
            }
            value => escaped.push(value),
        }
    }

    escaped
}

/// Keep pretty-printed JSON valid while preventing bidi and other invisible
/// formatting characters from reaching a terminal as raw code points.
pub fn escape_json_invisibles(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        if is_security_invisible(character) {
            let code_point = u32::from(character);
            if code_point <= 0xffff {
                escaped.push_str("\\u");
                escaped.push_str(&format!("{code_point:04X}"));
            } else {
                let supplementary = code_point.saturating_sub(0x1_0000);
                let high = 0xd800_u32.saturating_add(supplementary >> 10);
                let low = 0xdc00_u32.saturating_add(supplementary & 0x03ff);
                escaped.push_str(&format!("\\u{high:04X}\\u{low:04X}"));
            }
        } else {
            escaped.push(character);
        }
    }
    escaped
}

pub(crate) const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'
            | '\u{202b}'
            | '\u{202c}'
            | '\u{202d}'
            | '\u{202e}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}

pub(crate) const fn is_security_invisible(character: char) -> bool {
    is_bidi_control(character)
        || matches!(
            character,
            '\u{00ad}'
                | '\u{00a0}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{2060}'
                | '\u{feff}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{e0100}'..='\u{e01ef}'
        )
}

#[cfg(test)]
mod tests {
    use super::{escape_for_terminal, escape_json_invisibles};

    #[test]
    fn escapes_terminal_controls_and_invisibles() {
        let input = "name\n\u{001b}[31m\u{202e}txt\\end";
        assert_eq!(
            escape_for_terminal(input),
            "name\\n\\x1B[31m\\u{202E}txt\\\\end"
        );
    }

    #[test]
    fn preserves_ordinary_non_ascii_text() {
        assert_eq!(escape_for_terminal("Urlaub-猫-ä.txt"), "Urlaub-猫-ä.txt");
    }

    #[test]
    fn json_escape_keeps_unicode_but_quotes_invisible_controls() {
        assert_eq!(
            escape_json_invisibles("{\n  \"name\": \"猫\u{202e}txt\"\n}"),
            "{\n  \"name\": \"猫\\u202Etxt\"\n}"
        );
        assert_eq!(escape_json_invisibles("x\u{e0100}y"), "x\\uDB40\\uDD00y");
    }
}
