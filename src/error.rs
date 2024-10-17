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

    #[error("Async HTTP request failed: {0}")]
    AsyncHttpError(String),

    #[error("Async Serialization/Deserialization error: {0}")]
    AsyncSerdeError(#[from] reqwest::Error),
}