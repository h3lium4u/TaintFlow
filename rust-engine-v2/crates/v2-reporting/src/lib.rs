use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use v2_rules::Severity;

// ---------------------------------------------------------------------------
// 1. Finding Model
// ---------------------------------------------------------------------------

/// Unique identifier for a finding within a report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct FindingId(pub String);

/// Source location: file, method, instruction, line, column.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct SourceLocation {
    pub file: String,
    pub method: String,
    pub instruction_id: u32,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl SourceLocation {
    pub fn unknown() -> Self {
        Self {
            file: "<unknown>".to_string(),
            method: "<unknown>".to_string(),
            instruction_id: 0,
            line: None,
            column: None,
        }
    }

    pub fn display(&self) -> String {
        match (self.line, self.column) {
            (Some(l), Some(c)) => format!("{}:{}:{}", self.file, l, c),
            (Some(l), None) => format!("{}:{}", self.file, l),
            _ => format!("{} (inst:{})", self.file, self.instruction_id),
        }
    }
}

/// Sink location: same structure as SourceLocation.
pub type SinkLocation = SourceLocation;

/// A single step in a taint propagation trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct TraceStep {
    pub kind: TraceStepKind,
    pub description: String,
    pub location: SourceLocation,
}

/// The semantic role of a trace step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum TraceStepKind {
    Source,
    Assignment,
    HeapStore,
    HeapLoad,
    Call,
    Return,
    Sink,
    Parameter,
}

impl TraceStepKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Source => "Source",
            Self::Assignment => "Assignment",
            Self::HeapStore => "Store",
            Self::HeapLoad => "Load",
            Self::Call => "Call",
            Self::Return => "Return",
            Self::Sink => "Sink",
            Self::Parameter => "Parameter",
        }
    }
}

/// Ordered taint propagation trace from source to sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTrace {
    pub steps: Vec<TraceStep>,
}

impl FindingTrace {
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    pub fn push(&mut self, step: TraceStep) {
        self.steps.push(step);
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

impl Default for FindingTrace {
    fn default() -> Self {
        Self::new()
    }
}

/// Diagnostic message attached to a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticMessage {
    pub title: String,
    pub detail: String,
    pub remediation: Option<String>,
}

/// Metadata sourced from the matched rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub rule_id: String,
    pub rule_name: String,
    pub cwe: Option<u32>,
    pub severity: Severity,
    pub category: Option<String>,
    pub language: Option<String>,
    pub description: Option<String>,
}

/// Confidence level in a finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// Deterministic fingerprint for duplicate suppression.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct FindingFingerprint(pub String);

impl FindingFingerprint {
    /// Build a stable fingerprint from rule_id + source + sink + access_path.
    pub fn compute(
        rule_id: &str,
        source: &SourceLocation,
        sink: &SinkLocation,
        access_path: &str,
    ) -> Self {
        let raw = format!(
            "{}|{}|{}|{}",
            rule_id,
            source.display(),
            sink.display(),
            access_path,
        );
        Self(raw)
    }
}

/// A complete, structured vulnerability finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub fingerprint: FindingFingerprint,
    pub rule: RuleMetadata,
    pub confidence: Confidence,
    pub source: SourceLocation,
    pub sink: SinkLocation,
    pub access_path: String,
    pub trace: FindingTrace,
    pub message: DiagnosticMessage,
}

impl Finding {
    pub fn severity(&self) -> &Severity {
        &self.rule.severity
    }

    pub fn cwe_string(&self) -> String {
        self.rule.cwe
            .map(|n| format!("CWE-{}", n))
            .unwrap_or_else(|| "N/A".to_string())
    }
}

/// A collection of deduplicated findings with stable ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCollection {
    findings: Vec<Finding>,
    seen_fingerprints: HashSet<FindingFingerprint>,
}

impl FindingCollection {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            seen_fingerprints: HashSet::new(),
        }
    }

    /// Add a finding, skipping it if its fingerprint already exists (deduplication).
    pub fn add(&mut self, finding: Finding) {
        if self.seen_fingerprints.insert(finding.fingerprint.clone()) {
            self.findings.push(finding);
        }
    }

    /// Return deduplicated findings in a deterministic order
    /// (sorted by fingerprint string for stable output).
    pub fn findings_sorted(&self) -> Vec<&Finding> {
        let mut sorted: Vec<&Finding> = self.findings.iter().collect();
        sorted.sort_by_key(|f| &f.fingerprint);
        sorted
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

impl Default for FindingCollection {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 2. Trace Reconstruction
// ---------------------------------------------------------------------------

/// Reconstruct a finding trace from an ordered list of (step_kind, description, location).
pub struct TraceBuilder;

impl TraceBuilder {
    pub fn build(steps: Vec<(TraceStepKind, String, SourceLocation)>) -> FindingTrace {
        let mut trace = FindingTrace::new();
        for (kind, description, location) in steps {
            trace.push(TraceStep { kind, description, location });
        }
        trace
    }
}

// ---------------------------------------------------------------------------
// 3. Reporting API
// ---------------------------------------------------------------------------

/// Builder for constructing a `FindingCollection` fluently.
pub struct ReportBuilder {
    collection: FindingCollection,
    id_counter: u32,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            collection: FindingCollection::new(),
            id_counter: 0,
        }
    }

    /// Add a finding by supplying its components. Automatically assigns an ID and
    /// computes the fingerprint. Duplicate fingerprints are silently dropped.
    pub fn add_finding(
        &mut self,
        rule: RuleMetadata,
        confidence: Confidence,
        source: SourceLocation,
        sink: SinkLocation,
        access_path: String,
        trace: FindingTrace,
        message: DiagnosticMessage,
    ) -> &mut Self {
        let fingerprint = FindingFingerprint::compute(
            &rule.rule_id,
            &source,
            &sink,
            &access_path,
        );
        self.id_counter += 1;
        let id = FindingId(format!("F-{:04}", self.id_counter));

        self.collection.add(Finding {
            id,
            fingerprint,
            rule,
            confidence,
            source,
            sink,
            access_path,
            trace,
            message,
        });
        self
    }

    pub fn build(self) -> FindingCollection {
        self.collection
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 4. Formatters
// ---------------------------------------------------------------------------

/// Human-readable CLI formatter.
pub struct ConsoleFormatter;

impl ConsoleFormatter {
    pub fn format(collection: &FindingCollection) -> String {
        let mut out = String::new();
        let findings = collection.findings_sorted();

        if findings.is_empty() {
            out.push_str("No findings.\n");
            return out;
        }

        for finding in findings {
            let sev = format!("{:?}", finding.rule.severity).to_uppercase();
            let cwe = finding.cwe_string();
            let _ = writeln!(out, "{} {} {}", sev, cwe, finding.message.title);
            let _ = writeln!(out, "  Rule   : {} ({})", finding.rule.rule_name, finding.rule.rule_id);
            let _ = writeln!(out, "  Source : {}", finding.source.display());
            let _ = writeln!(out, "  Sink   : {}", finding.sink.display());
            let _ = writeln!(out, "  Path   : {}", finding.access_path);
            let _ = writeln!(out, "  Confidence: {}", finding.confidence.as_str());

            if !finding.trace.is_empty() {
                let _ = writeln!(out, "  Trace  :");
                for step in &finding.trace.steps {
                    let _ = writeln!(out, "    [{}] {} @ {}", step.kind.label(), step.description, step.location.display());
                }
            }
            out.push('\n');
        }

        out
    }
}

/// JSON formatter: serializes the sorted finding list as a stable JSON array.
pub struct JsonExporter;

impl JsonExporter {
    pub fn export(collection: &FindingCollection) -> String {
        let sorted: Vec<&Finding> = collection.findings_sorted();
        serde_json::to_string_pretty(&sorted).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

/// SARIF 2.1.0 exporter.
pub struct SarifExporter;

impl SarifExporter {
    pub fn export(collection: &FindingCollection, tool_name: &str, tool_version: &str) -> String {
        let findings = collection.findings_sorted();

        // Build rules list (deduplicated by rule_id)
        let mut seen_rules: HashMap<String, serde_json::Value> = HashMap::new();
        for f in &findings {
            seen_rules.entry(f.rule.rule_id.clone()).or_insert_with(|| {
                let mut rule = serde_json::json!({
                    "id": f.rule.rule_id,
                    "name": f.rule.rule_name,
                    "shortDescription": { "text": f.rule.rule_name },
                    "helpUri": format!("https://cwe.mitre.org/data/definitions/{}.html",
                        f.rule.cwe.unwrap_or(0)),
                    "properties": {
                        "severity": format!("{:?}", f.rule.severity),
                        "category": f.rule.category.clone().unwrap_or_default(),
                    }
                });
                if let Some(cwe) = f.rule.cwe {
                    rule["properties"]["cwe"] = serde_json::json!(format!("CWE-{}", cwe));
                }
                rule
            });
        }
        let mut rules_list: Vec<serde_json::Value> = seen_rules.into_values().collect();
        rules_list.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

        // Build results
        let results: Vec<serde_json::Value> = findings.iter().map(|f| {
            let mut code_flows: Vec<serde_json::Value> = Vec::new();
            if !f.trace.is_empty() {
                let thread_flow_locations: Vec<serde_json::Value> = f.trace.steps.iter().map(|step| {
                    serde_json::json!({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": { "uri": step.location.file },
                                "region": {
                                    "startLine": step.location.line.unwrap_or(1),
                                    "startColumn": step.location.column.unwrap_or(1),
                                }
                            },
                            "message": { "text": format!("[{}] {}", step.kind.label(), step.description) }
                        }
                    })
                }).collect();

                code_flows.push(serde_json::json!({
                    "threadFlows": [{
                        "locations": thread_flow_locations
                    }]
                }));
            }

            serde_json::json!({
                "ruleId": f.rule.rule_id,
                "level": sarif_level(&f.rule.severity),
                "message": { "text": f.message.detail },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.sink.file },
                        "region": {
                            "startLine": f.sink.line.unwrap_or(1),
                            "startColumn": f.sink.column.unwrap_or(1),
                        }
                    }
                }],
                "fingerprints": {
                    "taintflow/v1": f.fingerprint.0
                },
                "codeFlows": code_flows,
                "properties": {
                    "confidence": f.confidence.as_str(),
                    "accessPath": f.access_path,
                }
            })
        }).collect();

        let sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/taintflow",
                        "rules": rules_list,
                    }
                },
                "results": results,
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Top-level reporting facade.
pub struct Reporter {
    pub collection: FindingCollection,
}

impl Reporter {
    pub fn new(collection: FindingCollection) -> Self {
        Self { collection }
    }

    pub fn to_console(&self) -> String {
        ConsoleFormatter::format(&self.collection)
    }

    pub fn to_json(&self) -> String {
        JsonExporter::export(&self.collection)
    }

    pub fn to_sarif(&self, tool_name: &str, tool_version: &str) -> String {
        SarifExporter::export(&self.collection, tool_name, tool_version)
    }
}

pub fn init() {
    println!("v2-reporting initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use v2_rules::Severity;

    // ----- Helpers -----

    fn make_source_loc(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: file.to_string(),
            method: "main".to_string(),
            instruction_id: 1,
            line: Some(line),
            column: Some(1),
        }
    }

    fn make_sink_loc(file: &str, line: usize) -> SinkLocation {
        SinkLocation {
            file: file.to_string(),
            method: "main".to_string(),
            instruction_id: 5,
            line: Some(line),
            column: Some(1),
        }
    }

    fn make_rule(rule_id: &str, severity: Severity, cwe: Option<u32>) -> RuleMetadata {
        RuleMetadata {
            rule_id: rule_id.to_string(),
            rule_name: format!("{} rule", rule_id),
            cwe,
            severity,
            category: Some("injection".to_string()),
            language: Some("python".to_string()),
            description: Some("Test rule".to_string()),
        }
    }

    fn make_trace(steps: &[(&str, TraceStepKind, &str, usize)]) -> FindingTrace {
        TraceBuilder::build(
            steps.iter().map(|(desc, kind, file, line)| {
                (kind.clone(), desc.to_string(), make_source_loc(file, *line))
            }).collect()
        )
    }

    fn make_finding(rule_id: &str, src_line: usize, sink_line: usize, path: &str, trace: FindingTrace) -> Finding {
        let source = make_source_loc("app.py", src_line);
        let sink = make_sink_loc("app.py", sink_line);
        let rule = make_rule(rule_id, Severity::High, Some(78));
        let fingerprint = FindingFingerprint::compute(&rule.rule_id, &source, &sink, path);
        Finding {
            id: FindingId("F-0001".to_string()),
            fingerprint,
            rule,
            confidence: Confidence::High,
            source,
            sink,
            access_path: path.to_string(),
            trace,
            message: DiagnosticMessage {
                title: "Command Injection".to_string(),
                detail: format!("Tainted value '{}' reaches os.system()", path),
                remediation: Some("Sanitize user input with shlex.quote".to_string()),
            },
        }
    }

    // ------------------------------------------------------------------
    // Trace Reconstruction
    // ------------------------------------------------------------------

    #[test]
    fn test_trace_reconstruction() {
        let trace = make_trace(&[
            ("input()", TraceStepKind::Source, "app.py", 10),
            ("user = input()", TraceStepKind::Assignment, "app.py", 10),
            ("cmd = user", TraceStepKind::Assignment, "app.py", 20),
            ("os.system(cmd)", TraceStepKind::Sink, "app.py", 45),
        ]);
        assert_eq!(trace.steps.len(), 4);
        assert_eq!(trace.steps[0].kind, TraceStepKind::Source);
        assert_eq!(trace.steps[3].kind, TraceStepKind::Sink);
    }

    #[test]
    fn test_trace_step_labels() {
        assert_eq!(TraceStepKind::Source.label(), "Source");
        assert_eq!(TraceStepKind::Sink.label(), "Sink");
        assert_eq!(TraceStepKind::Call.label(), "Call");
        assert_eq!(TraceStepKind::Return.label(), "Return");
    }

    // ------------------------------------------------------------------
    // Multiple Findings
    // ------------------------------------------------------------------

    #[test]
    fn test_multiple_findings() {
        let mut builder = ReportBuilder::new();
        let trace1 = make_trace(&[("input()", TraceStepKind::Source, "app.py", 10)]);
        let trace2 = make_trace(&[("getenv()", TraceStepKind::Source, "app.py", 5)]);

        builder.add_finding(
            make_rule("py-sink-001", Severity::High, Some(78)),
            Confidence::High,
            make_source_loc("app.py", 10),
            make_sink_loc("app.py", 45),
            "cmd".to_string(),
            trace1,
            DiagnosticMessage { title: "CmdInjection".to_string(), detail: "...".to_string(), remediation: None },
        );
        builder.add_finding(
            make_rule("py-sink-002", Severity::High, Some(95)),
            Confidence::Medium,
            make_source_loc("app.py", 5),
            make_sink_loc("app.py", 30),
            "user".to_string(),
            trace2,
            DiagnosticMessage { title: "CodeInjection".to_string(), detail: "...".to_string(), remediation: None },
        );

        let collection = builder.build();
        assert_eq!(collection.len(), 2);
    }

    // ------------------------------------------------------------------
    // Duplicate Suppression
    // ------------------------------------------------------------------

    #[test]
    fn test_duplicate_suppression() {
        let mut collection = FindingCollection::new();
        let trace = FindingTrace::new();
        let f1 = make_finding("py-sink-001", 10, 45, "cmd", trace.clone());
        let f2 = make_finding("py-sink-001", 10, 45, "cmd", trace.clone());
        assert_eq!(f1.fingerprint, f2.fingerprint);
        collection.add(f1);
        collection.add(f2);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_different_findings_not_deduplicated() {
        let mut collection = FindingCollection::new();
        let f1 = make_finding("py-sink-001", 10, 45, "cmd", FindingTrace::new());
        let f2 = make_finding("py-sink-001", 10, 45, "user", FindingTrace::new()); // different access path
        assert_ne!(f1.fingerprint, f2.fingerprint);
        collection.add(f1);
        collection.add(f2);
        assert_eq!(collection.len(), 2);
    }

    // ------------------------------------------------------------------
    // Fingerprint Stability
    // ------------------------------------------------------------------

    #[test]
    fn test_fingerprint_stability() {
        let src = make_source_loc("app.py", 10);
        let sink = make_sink_loc("app.py", 45);
        let fp1 = FindingFingerprint::compute("py-sink-001", &src, &sink, "cmd");
        let fp2 = FindingFingerprint::compute("py-sink-001", &src, &sink, "cmd");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_differs_on_path() {
        let src = make_source_loc("app.py", 10);
        let sink = make_sink_loc("app.py", 45);
        let fp1 = FindingFingerprint::compute("py-sink-001", &src, &sink, "cmd");
        let fp2 = FindingFingerprint::compute("py-sink-001", &src, &sink, "user");
        assert_ne!(fp1, fp2);
    }

    // ------------------------------------------------------------------
    // Stable Deterministic Ordering
    // ------------------------------------------------------------------

    #[test]
    fn test_stable_deterministic_ordering() {
        let mut collection = FindingCollection::new();
        let fa = make_finding("py-sink-002", 5, 30, "user", FindingTrace::new());
        let fb = make_finding("py-sink-001", 10, 45, "cmd", FindingTrace::new());
        collection.add(fa);
        collection.add(fb);
        let sorted = collection.findings_sorted();
        // Should be sorted by fingerprint string
        assert!(sorted[0].fingerprint <= sorted[1].fingerprint);
    }

    // ------------------------------------------------------------------
    // CLI Formatting
    // ------------------------------------------------------------------

    #[test]
    fn test_cli_formatting() {
        let trace = make_trace(&[
            ("input()", TraceStepKind::Source, "app.py", 10),
            ("os.system(cmd)", TraceStepKind::Sink, "app.py", 45),
        ]);
        let f = make_finding("py-sink-001", 10, 45, "cmd", trace);
        let mut collection = FindingCollection::new();
        collection.add(f);
        let output = ConsoleFormatter::format(&collection);
        assert!(output.contains("HIGH"));
        assert!(output.contains("CWE-78"));
        assert!(output.contains("app.py:10"));
        assert!(output.contains("app.py:45"));
        assert!(output.contains("cmd"));
        assert!(output.contains("Source"));
        assert!(output.contains("Sink"));
    }

    #[test]
    fn test_cli_formatting_empty() {
        let collection = FindingCollection::new();
        let output = ConsoleFormatter::format(&collection);
        assert!(output.contains("No findings."));
    }

    // ------------------------------------------------------------------
    // JSON Serialization
    // ------------------------------------------------------------------

    #[test]
    fn test_json_serialization() {
        let f = make_finding("py-sink-001", 10, 45, "cmd", FindingTrace::new());
        let mut collection = FindingCollection::new();
        collection.add(f);
        let json_str = JsonExporter::export(&collection);
        assert!(json_str.contains("py-sink-001"));
        assert!(json_str.contains("app.py"));
        assert!(json_str.contains("cmd"));
        // Valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_json_empty_collection() {
        let collection = FindingCollection::new();
        let json_str = JsonExporter::export(&collection);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    // ------------------------------------------------------------------
    // SARIF Serialization
    // ------------------------------------------------------------------

    #[test]
    fn test_sarif_serialization() {
        let trace = make_trace(&[
            ("input()", TraceStepKind::Source, "app.py", 10),
            ("os.system(cmd)", TraceStepKind::Sink, "app.py", 45),
        ]);
        let f = make_finding("py-sink-001", 10, 45, "cmd", trace);
        let mut collection = FindingCollection::new();
        collection.add(f);
        let sarif_str = SarifExporter::export(&collection, "TaintFlow", "0.1.0");
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();

        // Check SARIF schema
        assert_eq!(parsed["version"], "2.1.0");
        let runs = parsed["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "TaintFlow");

        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "py-sink-001");
        assert_eq!(results[0]["level"], "error");

        // codeFlows present
        let code_flows = results[0]["codeFlows"].as_array().unwrap();
        assert!(!code_flows.is_empty());
    }

    #[test]
    fn test_sarif_empty_collection() {
        let collection = FindingCollection::new();
        let sarif_str = SarifExporter::export(&collection, "TaintFlow", "0.1.0");
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    // ------------------------------------------------------------------
    // Rule Metadata Preservation
    // ------------------------------------------------------------------

    #[test]
    fn test_rule_metadata_preservation() {
        let f = make_finding("py-sink-001", 10, 45, "cmd", FindingTrace::new());
        assert_eq!(f.rule.rule_id, "py-sink-001");
        assert_eq!(f.rule.cwe, Some(78));
        assert_eq!(f.rule.severity, Severity::High);
        assert_eq!(f.rule.language.as_deref(), Some("python"));
        assert_eq!(f.rule.category.as_deref(), Some("injection"));
        assert_eq!(f.cwe_string(), "CWE-78");
    }

    // ------------------------------------------------------------------
    // Reporter facade
    // ------------------------------------------------------------------

    #[test]
    fn test_reporter_facade() {
        let f = make_finding("py-sink-001", 10, 45, "cmd", FindingTrace::new());
        let mut collection = FindingCollection::new();
        collection.add(f);
        let reporter = Reporter::new(collection);
        // Console output
        let console = reporter.to_console();
        assert!(console.contains("HIGH"));
        // JSON output
        let json = reporter.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        // SARIF output
        let sarif = reporter.to_sarif("TaintFlow", "0.1.0");
        let parsed_sarif: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed_sarif["version"], "2.1.0");
    }

    // ------------------------------------------------------------------
    // Source Mapping / SourceLocation
    // ------------------------------------------------------------------

    #[test]
    fn test_source_location_display_with_line_col() {
        let loc = SourceLocation {
            file: "main.py".to_string(),
            method: "main".to_string(),
            instruction_id: 1,
            line: Some(42),
            column: Some(5),
        };
        assert_eq!(loc.display(), "main.py:42:5");
    }

    #[test]
    fn test_source_location_display_with_line_only() {
        let loc = SourceLocation {
            file: "main.py".to_string(),
            method: "main".to_string(),
            instruction_id: 1,
            line: Some(42),
            column: None,
        };
        assert_eq!(loc.display(), "main.py:42");
    }

    #[test]
    fn test_source_location_unknown() {
        let loc = SourceLocation::unknown();
        assert!(loc.display().contains("<unknown>"));
    }
}
