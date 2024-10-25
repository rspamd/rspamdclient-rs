use thiserror::Error;

#[derive(Error, Debug)]
pub enum RspamdError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("Serialization/Deserialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Unknown error")]
    Unknown,

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("URL parsing error: {0}")]
    ParseError(#[from] url::ParseError),

    #[error("Encrypption error: {0}")]
    EncryptionError(String),
}