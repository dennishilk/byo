use std::collections::BTreeMap;

use serde::Serialize;

pub const REPORT_SCHEMA_VERSION: &str = "0.1.0-pre.1";
pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Info,
    Attention,
    Warning,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Attention => "Attention",
            Self::Warning => "Warning",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AnalysisState {
    Complete,
    Partial,
    Failed,
}

impl AnalysisState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "Complete",
            Self::Partial => "Partial",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    File,
    Url,
}

impl InputKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Url => "url",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct InputSubject {
    pub kind: InputKind,
    pub display: String,
    #[serde(skip_serializing)]
    original: Option<String>,
}

impl InputSubject {
    pub fn original(&self) -> Option<&str> {
        self.original.as_deref()
    }

    pub(crate) fn new(kind: InputKind, original: Option<String>, display: String) -> Self {
        Self {
            kind,
            display,
            original,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ReportMetadata {
    pub schema_version: String,
    pub analyzer_version: String,
    analysis_state: AnalysisState,
    local: bool,
    network_activity: bool,
    pub input_kind: InputKind,
}

impl ReportMetadata {
    fn new(input_kind: InputKind) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            analysis_state: AnalysisState::Complete,
            local: true,
            network_activity: false,
            input_kind,
        }
    }

    pub const fn analysis_state(&self) -> AnalysisState {
        self.analysis_state
    }

    pub const fn is_local(&self) -> bool {
        self.local
    }

    pub const fn network_activity(&self) -> bool {
        self.network_activity
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ObservationValue {
    Text(String),
    Boolean(bool),
    Unsigned(u64),
    TextList(Vec<String>),
}

impl From<String> for ObservationValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for ObservationValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<bool> for ObservationValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<u64> for ObservationValue {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl From<Vec<String>> for ObservationValue {
    fn from(value: Vec<String>) -> Self {
        Self::TextList(value)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub id: String,
    pub code: String,
    pub title: String,
    pub fields: BTreeMap<String, ObservationValue>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub observation_ids: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Limitation {
    pub code: String,
    pub explanation: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub metadata: ReportMetadata,
    pub subject: InputSubject,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<Limitation>,
    #[serde(skip_serializing)]
    next_observation_number: u32,
}

impl Report {
    pub fn new(kind: InputKind, original: Option<String>, display: impl Into<String>) -> Self {
        Self {
            metadata: ReportMetadata::new(kind),
            subject: InputSubject::new(kind, original, display.into()),
            observations: Vec::new(),
            findings: Vec::new(),
            limitations: Vec::new(),
            next_observation_number: 1,
        }
    }

    pub fn add_observation(
        &mut self,
        code: impl Into<String>,
        title: impl Into<String>,
        fields: BTreeMap<String, ObservationValue>,
    ) -> String {
        let id = format!("obs-{:04}", self.next_observation_number);
        self.next_observation_number = self.next_observation_number.saturating_add(1);
        self.observations.push(Observation {
            id: id.clone(),
            code: code.into(),
            title: title.into(),
            fields,
        });
        id
    }

    pub fn add_finding(
        &mut self,
        code: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        explanation: impl Into<String>,
        observation_ids: Vec<String>,
    ) {
        self.findings.push(Finding {
            code: code.into(),
            severity,
            title: title.into(),
            explanation: explanation.into(),
            observation_ids,
        });
    }

    pub fn add_limitation(&mut self, code: impl Into<String>, explanation: impl Into<String>) {
        self.limitations.push(Limitation {
            code: code.into(),
            explanation: explanation.into(),
        });
    }

    pub fn mark_partial(&mut self) {
        if self.metadata.analysis_state == AnalysisState::Complete {
            self.metadata.analysis_state = AnalysisState::Partial;
        }
    }

    pub fn mark_failed(&mut self) {
        self.metadata.analysis_state = AnalysisState::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisState, InputKind, Report, Severity};

    #[test]
    fn severity_vocabulary_is_exact() {
        let severities = [Severity::Info, Severity::Attention, Severity::Warning];
        let labels: Vec<&str> = severities
            .iter()
            .map(|severity| severity.as_str())
            .collect();
        assert_eq!(labels, ["Info", "Attention", "Warning"]);
    }

    #[test]
    fn every_report_is_local_and_offline() {
        let report = Report::new(InputKind::File, Some("test.txt".to_owned()), "test.txt");
        assert!(report.metadata.is_local());
        assert!(!report.metadata.network_activity());
    }

    #[test]
    fn partial_and_failed_states_are_preserved() {
        let mut partial = Report::new(InputKind::Url, Some("x:".to_owned()), "x:");
        partial.mark_partial();
        partial.mark_partial();
        assert!(partial.metadata.analysis_state() == AnalysisState::Partial);

        partial.mark_failed();
        partial.mark_partial();
        assert!(partial.metadata.analysis_state() == AnalysisState::Failed);
    }
}
