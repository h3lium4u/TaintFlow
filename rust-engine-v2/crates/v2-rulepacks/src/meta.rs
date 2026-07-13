use serde::{Deserialize, Serialize};
use v2_rules::Severity;

// ---------------------------------------------------------------------------
// OWASP Top-10 (2021) Categories
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspCategory {
    /// A01:2021 – Broken Access Control
    A01BrokenAccessControl,
    /// A02:2021 – Cryptographic Failures
    A02CryptographicFailures,
    /// A03:2021 – Injection
    A03Injection,
    /// A04:2021 – Insecure Design
    A04InsecureDesign,
    /// A05:2021 – Security Misconfiguration
    A05SecurityMisconfiguration,
    /// A06:2021 – Vulnerable and Outdated Components
    A06VulnerableOutdatedComponents,
    /// A07:2021 – Identification and Authentication Failures
    A07IdentificationAuthFailures,
    /// A08:2021 – Software and Data Integrity Failures
    A08SoftwareDataIntegrityFailures,
    /// A09:2021 – Security Logging and Monitoring Failures
    A09SecurityLoggingMonitoringFailures,
    /// A10:2021 – Server-Side Request Forgery
    A10SSRF,
}

impl OwaspCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl           => "A01:2021 – Broken Access Control",
            Self::A02CryptographicFailures          => "A02:2021 – Cryptographic Failures",
            Self::A03Injection                      => "A03:2021 – Injection",
            Self::A04InsecureDesign                 => "A04:2021 – Insecure Design",
            Self::A05SecurityMisconfiguration       => "A05:2021 – Security Misconfiguration",
            Self::A06VulnerableOutdatedComponents   => "A06:2021 – Vulnerable and Outdated Components",
            Self::A07IdentificationAuthFailures     => "A07:2021 – Identification and Authentication Failures",
            Self::A08SoftwareDataIntegrityFailures  => "A08:2021 – Software and Data Integrity Failures",
            Self::A09SecurityLoggingMonitoringFailures => "A09:2021 – Security Logging and Monitoring Failures",
            Self::A10SSRF                           => "A10:2021 – Server-Side Request Forgery",
        }
    }
}

// ---------------------------------------------------------------------------
// CWE Knowledge Base
// ---------------------------------------------------------------------------

/// Full metadata for a single CWE entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweMetadata {
    pub cwe_id: u32,
    pub name: String,
    pub description: String,
    pub owasp: Option<OwaspCategory>,
    pub severity_default: Severity,
    pub references: Vec<String>,
}

impl CweMetadata {
    pub fn cwe_string(&self) -> String {
        format!("CWE-{}", self.cwe_id)
    }
}

/// The full CWE knowledge base — all CWEs covered by TaintFlow V2.
pub struct CweKnowledgeBase;

impl CweKnowledgeBase {
    /// Return metadata for every CWE in the knowledge base.
    pub fn all() -> Vec<CweMetadata> {
        vec![
            CweMetadata {
                cwe_id: 22,
                name: "Path Traversal".to_string(),
                description: "Improper limitation of a pathname to a restricted directory.".to_string(),
                owasp: Some(OwaspCategory::A01BrokenAccessControl),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/22.html".to_string()],
            },
            CweMetadata {
                cwe_id: 78,
                name: "OS Command Injection".to_string(),
                description: "Improper neutralization of special elements used in an OS command.".to_string(),
                owasp: Some(OwaspCategory::A03Injection),
                severity_default: Severity::Critical,
                references: vec!["https://cwe.mitre.org/data/definitions/78.html".to_string()],
            },
            CweMetadata {
                cwe_id: 79,
                name: "Cross-Site Scripting".to_string(),
                description: "Improper neutralization of input during web page generation.".to_string(),
                owasp: Some(OwaspCategory::A03Injection),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/79.html".to_string()],
            },
            CweMetadata {
                cwe_id: 89,
                name: "SQL Injection".to_string(),
                description: "Improper neutralization of special elements in SQL commands.".to_string(),
                owasp: Some(OwaspCategory::A03Injection),
                severity_default: Severity::Critical,
                references: vec!["https://cwe.mitre.org/data/definitions/89.html".to_string()],
            },
            CweMetadata {
                cwe_id: 94,
                name: "Code Injection".to_string(),
                description: "Improper control of generation of code.".to_string(),
                owasp: Some(OwaspCategory::A03Injection),
                severity_default: Severity::Critical,
                references: vec!["https://cwe.mitre.org/data/definitions/94.html".to_string()],
            },
            CweMetadata {
                cwe_id: 95,
                name: "Eval Injection".to_string(),
                description: "Improper neutralization of directives in dynamically evaluated code.".to_string(),
                owasp: Some(OwaspCategory::A03Injection),
                severity_default: Severity::Critical,
                references: vec!["https://cwe.mitre.org/data/definitions/95.html".to_string()],
            },
            CweMetadata {
                cwe_id: 200,
                name: "Exposure of Sensitive Information".to_string(),
                description: "The product exposes sensitive information to an unauthorized actor.".to_string(),
                owasp: Some(OwaspCategory::A05SecurityMisconfiguration),
                severity_default: Severity::Medium,
                references: vec!["https://cwe.mitre.org/data/definitions/200.html".to_string()],
            },
            CweMetadata {
                cwe_id: 259,
                name: "Use of Hard-coded Password".to_string(),
                description: "The software contains a hard-coded password.".to_string(),
                owasp: Some(OwaspCategory::A07IdentificationAuthFailures),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/259.html".to_string()],
            },
            CweMetadata {
                cwe_id: 319,
                name: "Cleartext Transmission of Sensitive Information".to_string(),
                description: "The software transmits sensitive information in cleartext.".to_string(),
                owasp: Some(OwaspCategory::A02CryptographicFailures),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/319.html".to_string()],
            },
            CweMetadata {
                cwe_id: 327,
                name: "Use of a Broken or Risky Cryptographic Algorithm".to_string(),
                description: "The use of a broken or risky cryptographic algorithm is an unnecessary risk.".to_string(),
                owasp: Some(OwaspCategory::A02CryptographicFailures),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/327.html".to_string()],
            },
            CweMetadata {
                cwe_id: 352,
                name: "Cross-Site Request Forgery".to_string(),
                description: "The web application does not verify that a request was intentionally provided by the user.".to_string(),
                owasp: Some(OwaspCategory::A01BrokenAccessControl),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/352.html".to_string()],
            },
            CweMetadata {
                cwe_id: 502,
                name: "Deserialization of Untrusted Data".to_string(),
                description: "The application deserializes untrusted data without sufficient verification.".to_string(),
                owasp: Some(OwaspCategory::A08SoftwareDataIntegrityFailures),
                severity_default: Severity::Critical,
                references: vec!["https://cwe.mitre.org/data/definitions/502.html".to_string()],
            },
            CweMetadata {
                cwe_id: 601,
                name: "URL Redirection to Untrusted Site (Open Redirect)".to_string(),
                description: "A web application accepts a user-controlled input that specifies a link.".to_string(),
                owasp: Some(OwaspCategory::A01BrokenAccessControl),
                severity_default: Severity::Medium,
                references: vec!["https://cwe.mitre.org/data/definitions/601.html".to_string()],
            },
            CweMetadata {
                cwe_id: 611,
                name: "Improper Restriction of XML External Entity Reference (XXE)".to_string(),
                description: "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.".to_string(),
                owasp: Some(OwaspCategory::A05SecurityMisconfiguration),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/611.html".to_string()],
            },
            CweMetadata {
                cwe_id: 798,
                name: "Use of Hard-coded Credentials".to_string(),
                description: "The software contains hard-coded credentials.".to_string(),
                owasp: Some(OwaspCategory::A07IdentificationAuthFailures),
                severity_default: Severity::Critical,
                references: vec!["https://cwe.mitre.org/data/definitions/798.html".to_string()],
            },
            CweMetadata {
                cwe_id: 918,
                name: "Server-Side Request Forgery (SSRF)".to_string(),
                description: "The web server receives a URL from an upstream component and retrieves it without validating the URL.".to_string(),
                owasp: Some(OwaspCategory::A10SSRF),
                severity_default: Severity::High,
                references: vec!["https://cwe.mitre.org/data/definitions/918.html".to_string()],
            },
        ]
    }

    /// Look up a single CWE entry by ID.
    pub fn get(cwe_id: u32) -> Option<CweMetadata> {
        Self::all().into_iter().find(|c| c.cwe_id == cwe_id)
    }
}

// ---------------------------------------------------------------------------
// Confidence Level
// ---------------------------------------------------------------------------

/// Analyst confidence level for findings generated by a rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Broad heuristic, requires analyst review.
    Low,
    /// Good heuristic, occasional false positives.
    Medium,
    /// Known-reliable pattern, very few false positives.
    High,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High   => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low    => "LOW",
        }
    }
}

// ---------------------------------------------------------------------------
// ExtendedRuleEntry — Rule + full metadata
// ---------------------------------------------------------------------------

/// A `v2_rules::Rule` enriched with enterprise metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRuleEntry {
    /// Core rule used by the taint engine.
    pub rule: v2_rules::Rule,
    /// OWASP Top-10 category, if applicable.
    pub owasp: Option<OwaspCategory>,
    /// Analyst confidence level for findings from this rule.
    pub confidence: ConfidenceLevel,
    /// Example CVE identifiers illustrating real-world exploits.
    pub cve_examples: Vec<String>,
    /// Links to advisories, NIST, MITRE, etc.
    pub references: Vec<String>,
    /// Free-form tags for filtering and reporting.
    pub tags: Vec<String>,
}

impl ExtendedRuleEntry {
    pub fn rule_id(&self) -> &str {
        &self.rule.id
    }

    pub fn cwe_string(&self) -> String {
        self.rule.cwe
            .map(|n| format!("CWE-{}", n))
            .unwrap_or_else(|| "N/A".to_string())
    }
}
