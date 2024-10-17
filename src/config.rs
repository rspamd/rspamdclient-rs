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


    /// Custom TLS settings for the asynchronous client
    #[builder(default, setter(strip_option))]
    pub tls_settings: Option<TlsSettings>,

    /// Proxy configuration for the asynchronous client
    #[builder(default, setter(strip_option))]
    pub proxy_config: Option<ProxyConfig>
}