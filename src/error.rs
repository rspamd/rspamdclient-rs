//! Error handling for the Rspamd API client.

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

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("UTF8 process error: {0}")]
    UTF8Error(#[from] std::str::Utf8Error),

    #[cfg(feature = "async")]
    #[error("Invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[cfg(feature = "async")]
    #[error("Invalid HTTP header name: {0}")]
    InvalidHeaderName(#[from] reqwest::header::InvalidHeaderName),

    #[cfg(feature = "async")]
    #[error("HTTP error: {0}")]
    HTTPError(#[from] reqwest::Error),

    #[cfg(feature = "sync")]
    #[error("Invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[from] attohttpc::header::InvalidHeaderValue),

    #[cfg(feature = "sync")]
    #[error("Invalid HTTP header name: {0}")]
    InvalidHeaderName(#[from] attohttpc::header::InvalidHeaderName),

    #[cfg(feature = "sync")]
    #[error("HTTP error: {0}")]
    HTTPError(#[from] attohttpc::Error),
}
