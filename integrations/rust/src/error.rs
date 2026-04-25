use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolkitGuardError {
    #[error("Binary not found: {0}")]
    BinaryNotFound(String),

    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Timeout exceeded")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}