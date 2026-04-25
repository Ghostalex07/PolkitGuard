use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Low
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "Action")]
    pub action: Option<String>,
    #[serde(rename = "Identity")]
    pub identity: Option<String>,
    #[serde(rename = "ResultAny")]
    pub result_any: Option<String>,
    #[serde(rename = "ResultActive")]
    pub result_active: Option<String>,
    #[serde(rename = "ResultInactive")]
    pub result_inactive: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "Severity")]
    pub severity: Severity,
    #[serde(rename = "File")]
    pub file: Option<String>,
    #[serde(rename = "RuleName")]
    pub rule_name: Option<String>,
    #[serde(rename = "RuleID")]
    pub rule_id: Option<String>,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Message")]
    pub message: Option<String>,
    #[serde(rename = "Impact")]
    pub impact: Option<String>,
    #[serde(rename = "Recommendation")]
    pub recommendation: Option<String>,
    #[serde(rename = "Score")]
    pub score: Option<i32>,
    #[serde(rename = "CVE")]
    pub cve: Option<String>,
    #[serde(rename = "Rule")]
    pub rule: Option<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    #[serde(rename = "files_scanned")]
    pub files_scanned: i32,
    #[serde(rename = "rules_found")]
    pub rules_found: i32,
    #[serde(rename = "critical")]
    pub critical: i32,
    #[serde(rename = "high")]
    pub high: i32,
    #[serde(rename = "medium")]
    pub medium: i32,
    #[serde(rename = "low")]
    pub low: i32,
    #[serde(rename = "total")]
    pub total: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(rename = "findings")]
    pub findings: Vec<Finding>,
    #[serde(rename = "scanner")]
    pub scanner: String,
    #[serde(rename = "stats")]
    pub stats: Stats,
    #[serde(rename = "version")]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub overall: f64,
    pub level: String,
    pub criticality: f64,
    pub likelihood: f64,
    pub impact: f64,
    pub trend: String,
    pub recommendations: Vec<String>,
}

impl RiskScore {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let counts = counts_by_severity(findings);
        let total = findings.len().max(1) as f64;

        let score = (counts.critical as f64 * 10.0
            + counts.high as f64 * 7.0
            + counts.medium as f64 * 4.0
            + counts.low as f64 * 1.0)
            / total;

        let level = match score as i32 {
            8..=10 => "CRITICAL",
            6..=7 => "HIGH",
            4..=5 => "MEDIUM",
            2..=3 => "LOW",
            _ => "MINIMAL",
        };

        let mut recommendations = Vec::new();
        if counts.critical > 0 {
            recommendations.push("URGENT: Critical issues found. Immediate action required.".to_string());
        }
        if counts.high > 0 {
            recommendations.push("High priority: Review and remediate within 24 hours.".to_string());
        }

        RiskScore {
            overall: score,
            level: level.to_string(),
            criticality: counts.critical as f64 / total * 10.0,
            likelihood: counts.high as f64 / total * 10.0,
            impact: (counts.critical + counts.high) as f64 / total * 10.0,
            trend: String::new(),
            recommendations,
        }
    }
}

#[derive(Debug, Default)]
struct Counts {
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
}

fn counts_by_severity(findings: &[Finding]) -> Counts {
    let mut counts = Counts::default();
    for f in findings {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
        }
    }
    counts
}