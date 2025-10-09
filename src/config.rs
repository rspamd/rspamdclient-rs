//!
//! ## Configuration for rspamd-client
//!
//! The `Config` struct allows you to customize various aspects of the client, including the base URL, proxy settings, and TLS settings.
//!

use std::collections::HashMap;
use std::iter::IntoIterator;
use typed_builder::TypedBuilder;

/// Custom TLS settings for the Rspamd client
#[derive(Debug, Clone, PartialEq)]
pub struct TlsSettings {
    /// Path to the TLS certificate file
    pub cert_path: String,

    /// Path to the TLS key file
    pub key_path: String,

    /// Optional path to the TLS CA file
    pub ca_path: Option<String>,
}

/// Proxy configuration for the Rspamd client
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyConfig {
    /// Proxy server URL
    pub proxy_url: String,

    /// Optional username for proxy authentication
    pub username: Option<String>,

    /// Optional password for proxy authentication
    pub password: Option<String>,
}

#[derive(TypedBuilder, Debug, PartialEq, Default)]
pub struct EnvelopeData {
    /// Sender email address
    #[builder(default, setter(strip_option))]
    pub from: Option<String>,

    /// Recipients email addresses
    #[builder(default)]
    pub rcpt: Vec<String>,

    /// Optional IP address of the sender
    #[builder(default, setter(strip_option))]
    pub ip: Option<String>,

    /// Optional IP of the sender
    #[builder(default, setter(strip_option))]
    pub user: Option<String>,

    /// Optional HELO string
    #[builder(default, setter(strip_option))]
    pub helo: Option<String>,

    /// Optional hostname
    #[builder(default, setter(strip_option))]
    pub hostname: Option<String>,

    /// Optional file path for local file scanning (File header)
    /// When set, the message body is not transmitted and Rspamd reads the file directly from disk
    /// This is a significant optimization when client and server are on the same host
    #[builder(default, setter(strip_option))]
    pub file_path: Option<String>,

    /// Optional additional headers
    #[builder(default)]
    pub additional_headers: HashMap<String, String>,
}

impl IntoIterator for EnvelopeData {
    type Item = (String, String);
    type IntoIter = std::collections::hash_map::IntoIter<String, String>;

    /// Convert the EnvelopeData struct into an iterator
    fn into_iter(mut self) -> Self::IntoIter {
        // We add all options to the additional headers
        if let Some(from) = self.from {
            self.additional_headers.insert("From".to_string(), from);
        }
        if let Some(ip) = self.ip {
            self.additional_headers.insert("IP".to_string(), ip);
        }
        if let Some(user) = self.user {
            self.additional_headers.insert("User".to_string(), user);
        }
        if let Some(helo) = self.helo {
            self.additional_headers.insert("Helo".to_string(), helo);
        }
        if let Some(hostname) = self.hostname {
            self.additional_headers.insert("Hostname".to_string(), hostname);
        }
        if let Some(file_path) = self.file_path {
            self.additional_headers.insert("File".to_string(), file_path);
        }
        for rcpt in self.rcpt {
            self.additional_headers.insert("Rcpt".to_string(), rcpt);
        }
        self.additional_headers.into_iter()
    }
}

/// Configuration for Rspamd client
#[derive(TypedBuilder,Debug, PartialEq)]
pub struct Config {
    /// Base URL of Rspamd server
    pub base_url: String,

    /// Optional API key for authentication
    #[builder(default, setter(strip_option))]
    pub password: Option<String>,

    /// Timeout duration for requests
    #[builder(default=30.0)]
    pub timeout: f64,

    /// Number of retries for requests
    #[builder(default=1)]
    pub retries: u32,

    /// Custom TLS settings for the asynchronous client
    #[builder(default, setter(strip_option))]
    pub tls_settings: Option<TlsSettings>,

    /// Proxy configuration for the asynchronous client
    #[builder(default, setter(strip_option))]
    pub proxy_config: Option<ProxyConfig>,

    /// Use zstd compression
    #[builder(default=true)]
    pub zstd: bool,

    /// Encryption key if using native HTTPCrypt encryption (must be in Rspamd base32 format)
    #[builder(default, setter(strip_option))]
    pub encryption_key: Option<String>,
}