# Rspamd Client for Rust

This crate provides an HTTP client for interacting with the Rspamd service in Rust. It supports both synchronous and asynchronous operations using the `attohttpc` and `reqwest` libraries, respectively.

## Features

- **Sync**: Synchronous client using `attohttpc`.
- **Async**: Asynchronous client using `reqwest`.
- Easily configurable with support for proxy and custom TLS settings.
- Supports scanning emails for spam scores and other metrics.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
rspamd-client = { version = "0.1", features = ["async"] }
```

Enable the `sync` and/or `async` features based on your requirements.

## Usage

### Synchronous Client

This example demonstrates how to scan an email using the synchronous client.

```rust
use rspamd_client::{Config, scan_sync};

fn main() {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();
    let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";

    match scan_sync(&config, email) {
        Ok(response) => println!("Scan result: {:?}", response),
        Err(e) => eprintln!("Error scanning email: {}", e),
    }
}
```

### Asynchronous Client

This example demonstrates how to scan an email using the asynchronous client.

```rust
use rspamd_client::{Config, scan_async};
use tokio;

#[tokio::main]
async fn main() {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();
    let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";

    match scan_async(&config, email).await {
        Ok(response) => println!("Scan result: {:?}", response),
        Err(e) => eprintln!("Error scanning email: {}", e),
    }
}
```

### Scan File Example

You can scan a file by reading its content into a `bytes::Bytes` object and sending it to Rspamd.

```rust
use rspamd_client::{Config, scan_sync};
use bytes::Bytes;
use std::fs;

fn main() {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();
    let file_content = fs::read("path/to/email.eml")
        .expect("Unable to read file");
    let email = Bytes::from(file_content);

    match scan_sync(&config, &email) {
        Ok(response) => println!("Scan result: {:?}", response),
        Err(e) => eprintln!("Error scanning email: {}", e),
    }
}
```

### Configuration

The `Config` struct allows you to customize various aspects of the client, including the base URL, proxy settings, and TLS settings.

```rust
#[derive(Debug)]
pub struct Config<'a> {
    pub base_url: &'a str,
    pub password: Option<String>,
    pub timeout: f64,
    pub retries: u32,
    pub zstd: bool,
    pub proxy_config: Option<ProxyConfig>,
    pub tls_settings: Option<TlsSettings>,
}

impl<'a> Config<'a> {
    pub fn builder() -> ConfigBuilder<'a> {
        ConfigBuilder::default()
    }
}

#[derive(Debug)]
pub struct ProxyConfig {
    pub proxy_url: String,
}

#[derive(Debug)]
pub struct TlsSettings {
    pub ca_path: Option<String>,
}
```

### Response Structures

The following structures are used to deserialize the responses from Rspamd:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct RspamdScanReply {
    #[serde(default)]
    pub is_skipped: bool,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub required_score: f64,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub thresholds: HashMap<String, f64>,
    #[serde(default)]
    pub symbols: HashMap<String, Symbol>,
    #[serde(default)]
    pub messages: HashMap<String, String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(rename = "message-id", default)]
    pub message_id: String,
    #[serde(default)]
    pub time_real: f64,
    #[serde(default)]
    pub milter: Option<Milter>,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub scan_time: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Symbol {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub metric_score: f64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Milter {
    #[serde(default)]
    pub add_headers: HashMap<String, MailHeader>,
    #[serde(default)]
    pub remove_headers: HashMap<String, i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailHeader {
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub order: i32,
}
```

## License

This project is licensed under the Apache 2.0 License.

## Contributing

Contributions are welcome! Please open a pull request or issue on GitHub.

---
For more information, please refer to the [Rust documentation](https://doc.rust-lang.org/) and [Rspamd documentation](https://rspamd.com/doc/).