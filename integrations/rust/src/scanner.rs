use std::process::Command;
use std::time::Duration;

use crate::error::PolkitGuardError;
use crate::models::{RiskScore, ScanResult};

pub struct Scanner {
    binary_path: String,
    timeout: Duration,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            binary_path: find_binary(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_path(path: impl Into<String>) -> Self {
        Self {
            binary_path: path.into(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn scan(&self, path: Option<&str>, severity: &str) -> Result<ScanResult, PolkitGuardError> {
        let output = tokio::process::Command::new(&self.binary_path)
            .args(["--format", "json", "--severity", severity])
            .args(path.map(|p| ["--path", p]).into_iter().flatten())
            .output()
            .await
            .map_err(|e| PolkitGuardError::ScanFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PolkitGuardError::ScanFailed(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&stdout).map_err(|e| PolkitGuardError::ParseError(e.to_string()))
    }

    pub fn scan_sync(&self, path: Option<&str>, severity: &str) -> Result<ScanResult, PolkitGuardError> {
        let output = Command::new(&self.binary_path)
            .args(["--format", "json", "--severity", severity])
            .args(path.map(|p| ["--path", p]).into_iter().flatten())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PolkitGuardError::ScanFailed(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&stdout).map_err(|e| PolkitGuardError::ParseError(e.to_string()))
    }

    pub fn calculate_risk_score(&self, findings: &[crate::models::Finding]) -> RiskScore {
        RiskScore::from_findings(findings)
    }

    pub fn version(&self) -> &str {
        "1.18.0"
    }
}

fn find_binary() -> String {
    let paths = [
        "/usr/local/bin/polkitguard",
        "/usr/bin/polkitguard",
    ];

    for path in paths {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }

    "polkitguard".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_calculation() {
        let findings = vec![
            crate::models::Finding {
                severity: crate::models::Severity::Critical,
                ..Default::default()
            },
            crate::models::Finding {
                severity: crate::models::Severity::High,
                ..Default::default()
            },
        ];

        let score = RiskScore::from_findings(&findings);
        assert!(score.overall > 0.0);
    }
}