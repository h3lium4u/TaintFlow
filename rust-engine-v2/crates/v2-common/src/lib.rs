use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    pub file_path: String,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Cwe {
    Cwe22,  // Path Traversal
    Cwe78,  // Command Injection
    Cwe79,  // XSS
    Cwe89,  // SQL Injection
    Cwe113, // HTTP Response Splitting
    Cwe327, // Weak Crypto
    Cwe502, // Unsafe Deserialization
    Cwe614, // Sensitive Cookie Without 'Secure'
    Cwe798, // Hardcoded Credentials
    Cwe918, // SSRF
}

impl Cwe {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cwe22 => "CWE-22",
            Self::Cwe78 => "CWE-78",
            Self::Cwe79 => "CWE-79",
            Self::Cwe89 => "CWE-89",
            Self::Cwe113 => "CWE-113",
            Self::Cwe327 => "CWE-327",
            Self::Cwe502 => "CWE-502",
            Self::Cwe614 => "CWE-614",
            Self::Cwe798 => "CWE-798",
            Self::Cwe918 => "CWE-918",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub cwe: Cwe,
    pub severity: Severity,
    pub location: Location,
    pub description: String,
    pub recommendation: String,
}

pub fn init() {
    println!("v2-common initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }
}
