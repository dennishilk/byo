use std::collections::{BTreeMap, BTreeSet};

use url::{Host, Url};

use crate::display::is_security_invisible;
use crate::{InputKind, ObservationValue, Report, Severity};

pub const MAX_URL_INPUT_BYTES: usize = 64 * 1024;
const MAX_DISPLAY_CHARACTERS: usize = 2048;
const MAX_COMPONENT_CHARACTERS: usize = 512;
const MAX_QUERY_PAIRS: usize = 256;
const MAX_REPORTED_QUERY_NAMES: usize = 64;
const MAX_REPORTED_URL_CONTROLS: usize = 32;

const TRACKING_PARAMETERS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "gclid",
    "dclid",
    "fbclid",
    "msclkid",
    "ttclid",
    "twclid",
    "mc_cid",
    "mc_eid",
];

pub fn inspect_url(input: &str) -> Report {
    if input.len() > MAX_URL_INPUT_BYTES {
        let mut report = Report::new(
            InputKind::Url,
            None,
            bounded_text(
                "<URL omitted: exceeds 64 KiB analysis limit>",
                MAX_DISPLAY_CHARACTERS,
            ),
        );
        report.add_limitation(
            "url.input_size_limit",
            "URL parsing was refused because the supplied input exceeded 64 KiB.",
        );
        report.mark_failed();
        append_offline_limitation(&mut report);
        return report;
    }

    let parsed = Url::parse(input);
    let display = match &parsed {
        Ok(url) => redacted_url(url),
        Err(_) => conservative_redaction(input),
    };
    let mut report = Report::new(
        InputKind::Url,
        Some(input.to_owned()),
        bounded_text(&display, MAX_DISPLAY_CHARACTERS),
    );

    append_url_control_observations(&mut report, input);

    let parsed = match parsed {
        Ok(url) => url,
        Err(error) => {
            let mut fields = BTreeMap::new();
            fields.insert("success".to_owned(), false.into());
            fields.insert("error".to_owned(), error.to_string().into());
            report.add_observation("url.parse", "URL parse result", fields);
            report.add_limitation(
                "url.parse_failed",
                "The standards-based parser rejected the input, so URL components could not be inspected.",
            );
            report.mark_failed();
            append_offline_limitation(&mut report);
            return report;
        }
    };

    let mut parse_fields = BTreeMap::new();
    parse_fields.insert("success".to_owned(), true.into());
    parse_fields.insert(
        "serialized".to_owned(),
        bounded_text(&redacted_url(&parsed), MAX_DISPLAY_CHARACTERS).into(),
    );
    let parse_id = report.add_observation("url.parse", "URL parse result", parse_fields);

    let mut scheme_fields = BTreeMap::new();
    scheme_fields.insert("value".to_owned(), parsed.scheme().into());
    let scheme_id = report.add_observation("url.scheme", "URL scheme", scheme_fields);
    append_scheme_finding(&mut report, parsed.scheme(), scheme_id);

    let username_present = !parsed.username().is_empty();
    let password_present = parsed.password().is_some();
    let mut credential_fields = BTreeMap::new();
    credential_fields.insert("username_present".to_owned(), username_present.into());
    credential_fields.insert("password_present".to_owned(), password_present.into());
    let credential_id = report.add_observation(
        "url.embedded_credentials",
        "Embedded URL credentials",
        credential_fields,
    );
    if password_present {
        report.add_finding(
            "url.embedded_credentials",
            Severity::Warning,
            "URL contains embedded credential material",
            "A password is present in the authority component. Ordinary output redacts it, and BYO does not use or transmit it.",
            vec![credential_id],
        );
    } else if username_present {
        report.add_finding(
            "url.embedded_username",
            Severity::Attention,
            "URL contains an embedded username",
            "The authority component contains user information. BYO does not use or transmit it.",
            vec![credential_id],
        );
    }

    append_host_observations(&mut report, &parsed);

    let mut port_fields = BTreeMap::new();
    port_fields.insert("present".to_owned(), parsed.port().is_some().into());
    if let Some(port) = parsed.port() {
        port_fields.insert("value".to_owned(), u64::from(port).into());
    }
    report.add_observation("url.port", "Explicit non-default port", port_fields);

    let (path, path_truncated) = bounded_text_with_flag(parsed.path(), MAX_COMPONENT_CHARACTERS);
    let mut path_fields = BTreeMap::new();
    path_fields.insert("value".to_owned(), path.into());
    path_fields.insert("truncated_for_report".to_owned(), path_truncated.into());
    report.add_observation("url.path", "Parsed URL path", path_fields);
    if path_truncated {
        report.add_limitation(
            "url.path_display_limit",
            "The parsed path exceeded 512 characters and was truncated in report presentation.",
        );
    }

    let mut fragment_fields = BTreeMap::new();
    fragment_fields.insert("present".to_owned(), parsed.fragment().is_some().into());
    report.add_observation("url.fragment", "URL fragment", fragment_fields);

    append_query_observations(&mut report, &parsed, &parse_id);
    append_offline_limitation(&mut report);
    report
}

fn append_url_control_observations(report: &mut Report, input: &str) {
    let mut ids = Vec::new();
    let mut truncated = false;
    for (index, character) in input.chars().enumerate() {
        if !(character.is_control() || is_security_invisible(character)) {
            continue;
        }
        if ids.len() == MAX_REPORTED_URL_CONTROLS {
            truncated = true;
            break;
        }
        let mut fields = BTreeMap::new();
        fields.insert(
            "code_point".to_owned(),
            format!("U+{:04X}", u32::from(character)).into(),
        );
        fields.insert(
            "logical_position".to_owned(),
            u64::try_from(index.saturating_add(1))
                .unwrap_or(u64::MAX)
                .into(),
        );
        ids.push(report.add_observation(
            "url.control_character",
            "Control or invisible character in URL input",
            fields,
        ));
    }

    if !ids.is_empty() {
        report.add_finding(
            "url.control_character",
            Severity::Warning,
            "URL input contains control or invisible characters",
            "These characters can affect parsing or display and are escaped in terminal output.",
            ids,
        );
    }
    if truncated {
        report.add_limitation(
            "url.control_character_limit",
            "More than 32 control or invisible characters were present; later occurrences were not individually reported.",
        );
        report.mark_partial();
    }
}

fn append_scheme_finding(report: &mut Report, scheme: &str, scheme_id: String) {
    match scheme {
        "javascript" | "data" | "vbscript" => report.add_finding(
            "url.active_content_scheme",
            Severity::Warning,
            "Scheme can carry active or embedded content",
            "BYO parsed the scheme as data and did not navigate to or execute the URL.",
            vec![scheme_id],
        ),
        "file" => report.add_finding(
            "url.local_resource_scheme",
            Severity::Attention,
            "URL refers to a local file resource",
            "The file URL was parsed only; BYO did not open the referenced path.",
            vec![scheme_id],
        ),
        "http" | "https" => {}
        _ => report.add_finding(
            "url.non_web_scheme",
            Severity::Info,
            "URL uses a non-web scheme",
            "Custom schemes can have application-specific behavior. BYO did not invoke a registered handler.",
            vec![scheme_id],
        ),
    }
}

fn append_host_observations(report: &mut Report, parsed: &Url) {
    let Some(host) = parsed.host() else {
        let mut fields = BTreeMap::new();
        fields.insert("present".to_owned(), false.into());
        report.add_observation("url.hostname", "URL hostname", fields);
        return;
    };

    match host {
        Host::Domain(domain) => {
            let ascii = domain.to_owned();
            let (unicode, conversion_result) = idna::domain_to_unicode(&ascii);
            let mut fields = BTreeMap::new();
            fields.insert("present".to_owned(), true.into());
            fields.insert("kind".to_owned(), "domain".into());
            fields.insert("ascii".to_owned(), ascii.clone().into());
            fields.insert("unicode".to_owned(), unicode.clone().into());
            let host_id = report.add_observation("url.hostname", "URL hostname", fields);

            let has_punycode = ascii
                .split('.')
                .any(|label| label.to_ascii_lowercase().starts_with("xn--"));
            if has_punycode {
                report.add_finding(
                    "url.punycode_hostname",
                    Severity::Attention,
                    "Hostname uses internationalized Punycode labels",
                    "Both the ASCII and Unicode forms are shown. Internationalized domains are not inherently malicious.",
                    vec![host_id],
                );
                report.add_limitation(
                    "url.confusable_analysis_not_implemented",
                    "M1 does not claim robust mixed-script or visual-confusable detection for internationalized hostnames.",
                );
            }
            if conversion_result.is_err() {
                report.add_limitation(
                    "url.idna_display_conversion",
                    "The hostname produced errors during Unicode display conversion; replacement characters may be shown.",
                );
                report.mark_partial();
            }
        }
        Host::Ipv4(address) => append_ip_host(report, address.to_string(), "IPv4"),
        Host::Ipv6(address) => append_ip_host(report, address.to_string(), "IPv6"),
    }
}

fn append_ip_host(report: &mut Report, address: String, kind: &str) {
    let mut fields = BTreeMap::new();
    fields.insert("present".to_owned(), true.into());
    fields.insert("kind".to_owned(), kind.into());
    fields.insert("value".to_owned(), address.into());
    report.add_observation("url.ip_literal_host", "IP-literal URL host", fields);
}

fn append_query_observations(report: &mut Report, parsed: &Url, parse_id: &str) {
    let query_present = parsed.query().is_some();
    let mut names = BTreeSet::new();
    let mut tracking = BTreeSet::new();
    let mut kept_pairs = Vec::new();
    let mut pair_count = 0_usize;
    let mut pair_limit_reached = false;
    let mut name_limit_reached = false;

    if query_present {
        for (name, value) in parsed.query_pairs() {
            pair_count = pair_count.saturating_add(1);
            if pair_count > MAX_QUERY_PAIRS {
                pair_limit_reached = true;
                break;
            }

            let owned_name = bounded_text(&name, 128);
            if names.len() < MAX_REPORTED_QUERY_NAMES || names.contains(&owned_name) {
                names.insert(owned_name.clone());
            } else {
                name_limit_reached = true;
            }
            if is_tracking_parameter(&name) {
                tracking.insert(owned_name);
            } else {
                kept_pairs.push((name.into_owned(), value.into_owned()));
            }
        }
    }

    let mut query_fields = BTreeMap::new();
    query_fields.insert("present".to_owned(), query_present.into());
    query_fields.insert(
        "parameter_names".to_owned(),
        ObservationValue::from(names.into_iter().collect::<Vec<_>>()),
    );
    query_fields.insert(
        "pair_count_inspected".to_owned(),
        u64::try_from(pair_count.min(MAX_QUERY_PAIRS))
            .unwrap_or(u64::MAX)
            .into(),
    );
    let query_id = report.add_observation("url.query", "URL query", query_fields);

    if pair_limit_reached {
        report.add_limitation(
            "url.query_pair_limit",
            "Only the first 256 query pairs were inspected; no cleaned suggestion was generated.",
        );
        report.mark_partial();
    }
    if name_limit_reached {
        report.add_limitation(
            "url.query_name_limit",
            "Only the first 64 distinct query-parameter names were retained in the report.",
        );
        report.mark_partial();
    }

    if tracking.is_empty() {
        return;
    }

    let mut tracking_fields = BTreeMap::new();
    tracking_fields.insert(
        "names".to_owned(),
        ObservationValue::from(tracking.into_iter().collect::<Vec<_>>()),
    );
    let tracking_id = report.add_observation(
        "url.tracking_parameter",
        "Recognized tracking parameters",
        tracking_fields,
    );
    report.add_finding(
        "url.tracking_parameter",
        Severity::Attention,
        "URL contains recognized tracking parameters",
        "The original URL remains unchanged. Any cleaned form is a derived display suggestion only.",
        vec![parse_id.to_owned(), query_id, tracking_id],
    );

    if !pair_limit_reached {
        let mut cleaned = parsed.clone();
        if kept_pairs.is_empty() {
            cleaned.set_query(None);
        } else {
            cleaned.query_pairs_mut().clear().extend_pairs(
                kept_pairs
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            );
        }
        let mut fields = BTreeMap::new();
        fields.insert(
            "value".to_owned(),
            bounded_text(&redacted_url(&cleaned), MAX_DISPLAY_CHARACTERS).into(),
        );
        fields.insert("derived_only".to_owned(), true.into());
        report.add_observation(
            "url.cleaned_suggestion",
            "Derived URL without recognized tracking parameters",
            fields,
        );
    }
}

fn is_tracking_parameter(name: &str) -> bool {
    TRACKING_PARAMETERS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn redacted_url(url: &Url) -> String {
    if url.password().is_none() {
        return url.as_str().to_owned();
    }

    let mut redacted = url.clone();
    if redacted.set_password(Some("REDACTED")).is_ok() {
        redacted.into()
    } else {
        "<parsed URL with redacted credentials>".to_owned()
    }
}

fn conservative_redaction(input: &str) -> String {
    let Some(scheme_end) = input.find("://") else {
        return input.to_owned();
    };
    let authority_start = scheme_end.saturating_add(3);
    let Some(authority_and_rest) = input.get(authority_start..) else {
        return input.to_owned();
    };
    let authority_length = authority_and_rest
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_rest.len());
    let Some(authority) = authority_and_rest.get(..authority_length) else {
        return input.to_owned();
    };
    let Some(at_position) = authority.rfind('@') else {
        return input.to_owned();
    };
    let Some(credentials) = authority.get(..at_position) else {
        return input.to_owned();
    };
    let Some(colon_position) = credentials.find(':') else {
        return input.to_owned();
    };

    let password_start = authority_start
        .saturating_add(colon_position)
        .saturating_add(1);
    let password_end = authority_start.saturating_add(at_position);
    let (Some(prefix), Some(suffix)) = (input.get(..password_start), input.get(password_end..))
    else {
        return "<URL with redacted credentials>".to_owned();
    };
    format!("{prefix}REDACTED{suffix}")
}

fn bounded_text(input: &str, maximum_characters: usize) -> String {
    bounded_text_with_flag(input, maximum_characters).0
}

fn bounded_text_with_flag(input: &str, maximum_characters: usize) -> (String, bool) {
    let mut characters = input.chars();
    let mut output: String = characters.by_ref().take(maximum_characters).collect();
    let truncated = characters.next().is_some();
    if truncated {
        output.push('…');
    }
    (output, truncated)
}

fn append_offline_limitation(report: &mut Report) {
    report.add_limitation(
        "url.offline_scope",
        "M1 made no HTTP or DNS request and did not resolve redirects, ownership, reachability, or reputation.",
    );
}

#[cfg(test)]
mod tests {
    use crate::{inspect_url, AnalysisState, ObservationValue};

    fn has_finding(report: &crate::Report, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    fn observation_text<'a>(report: &'a crate::Report, code: &str, field: &str) -> Option<&'a str> {
        report
            .observations
            .iter()
            .find(|observation| observation.code == code)
            .and_then(|observation| observation.fields.get(field))
            .and_then(|value| match value {
                ObservationValue::Text(text) => Some(text.as_str()),
                _ => None,
            })
    }

    fn observation_boolean(report: &crate::Report, code: &str, field: &str) -> Option<bool> {
        report
            .observations
            .iter()
            .find(|observation| observation.code == code)
            .and_then(|observation| observation.fields.get(field))
            .and_then(|value| match value {
                ObservationValue::Boolean(value) => Some(*value),
                _ => None,
            })
    }

    fn observation_unsigned(report: &crate::Report, code: &str, field: &str) -> Option<u64> {
        report
            .observations
            .iter()
            .find(|observation| observation.code == code)
            .and_then(|observation| observation.fields.get(field))
            .and_then(|value| match value {
                ObservationValue::Unsigned(value) => Some(*value),
                _ => None,
            })
    }

    #[test]
    fn parses_ordinary_url_components_without_network() {
        let report = inspect_url("https://example.com:8443/path?q=1#part");
        assert!(report.metadata.analysis_state() == AnalysisState::Complete);
        assert!(!report.metadata.network_activity());
        assert_eq!(
            observation_text(&report, "url.scheme", "value"),
            Some("https")
        );
        assert_eq!(
            observation_text(&report, "url.hostname", "ascii"),
            Some("example.com")
        );
        assert_eq!(
            observation_text(&report, "url.path", "value"),
            Some("/path")
        );
        assert_eq!(
            observation_unsigned(&report, "url.port", "value"),
            Some(8443)
        );
        assert_eq!(
            observation_boolean(&report, "url.query", "present"),
            Some(true)
        );
        assert_eq!(
            observation_boolean(&report, "url.fragment", "present"),
            Some(true)
        );
    }

    #[test]
    fn malformed_url_is_failed_not_reassuring() {
        let report = inspect_url("not a URL");
        assert!(report.metadata.analysis_state() == AnalysisState::Failed);
        assert!(report
            .limitations
            .iter()
            .any(|limitation| limitation.code == "url.parse_failed"));
    }

    #[test]
    fn credentials_are_reported_and_password_is_redacted() {
        let secret = "known-secret-value";
        let report = inspect_url(&format!("https://user:{secret}@example.com/path"));
        assert!(has_finding(&report, "url.embedded_credentials"));
        assert_eq!(
            observation_boolean(&report, "url.embedded_credentials", "username_present"),
            Some(true)
        );
        assert_eq!(
            observation_boolean(&report, "url.embedded_credentials", "password_present"),
            Some(true)
        );
        assert!(!report.subject.display.contains(secret));
        assert!(report
            .subject
            .original()
            .is_some_and(|value| value.contains(secret)));
        for observation in &report.observations {
            for value in observation.fields.values() {
                if let ObservationValue::Text(text) = value {
                    assert!(!text.contains(secret));
                }
            }
        }
    }

    #[test]
    fn shows_ascii_and_unicode_idn_forms() {
        let report = inspect_url("https://xn--bcher-kva.example/");
        assert_eq!(
            observation_text(&report, "url.hostname", "ascii"),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            observation_text(&report, "url.hostname", "unicode"),
            Some("bücher.example")
        );
        assert!(has_finding(&report, "url.punycode_hostname"));
    }

    #[test]
    fn reports_tracking_and_active_schemes() {
        let tracked = inspect_url("https://example.com/?utm_source=test&item=1&fbclid=x");
        assert!(has_finding(&tracked, "url.tracking_parameter"));
        assert!(tracked
            .observations
            .iter()
            .any(|observation| observation.code == "url.cleaned_suggestion"));

        for value in [
            "javascript:alert(1)",
            "data:text/plain,hello",
            "vbscript:msgbox(1)",
        ] {
            assert!(has_finding(
                &inspect_url(value),
                "url.active_content_scheme"
            ));
        }
        assert!(has_finding(
            &inspect_url("file:///tmp/example"),
            "url.local_resource_scheme"
        ));
    }

    #[test]
    fn reports_ip_literal_hosts() {
        let report = inspect_url("https://127.0.0.1:9443/path");
        assert_eq!(
            observation_text(&report, "url.ip_literal_host", "kind"),
            Some("IPv4")
        );
        assert_eq!(
            observation_text(&report, "url.ip_literal_host", "value"),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn makes_url_controls_visible_whether_parser_accepts_them_or_not() {
        let report = inspect_url("https://example.com/\npath");
        assert!(has_finding(&report, "url.control_character"));
    }
}
