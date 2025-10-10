# Rspamd Client for Rust

This crate provides an HTTP client for interacting with the Rspamd service in Rust. It supports both synchronous and asynchronous operations using the `attohttpc` and `reqwest` libraries, respectively.

## Features

- **Sync/Async**: Choose between synchronous (`attohttpc`) or asynchronous (`reqwest`) client
- **Mutually Exclusive**: Async and sync features are mutually exclusive by design
- **Encryption**: Native HTTPCrypt encryption support
- **Compression**: ZSTD compression for requests and responses
- **Local File Scanning**: Scan files on the same host without transferring body (`File` header)
- **Body Rewriting**: Receive rewritten message bodies (`body_block` flag)
- **Envelope Data**: Configure sender, recipients, IP, HELO, hostname, and custom headers
- **Proxy Support**: HTTP proxy configuration
- **TLS**: Custom TLS settings

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
rspamd-client = { version = "0.4", features = ["async"] }
```

Enable either the `sync` or `async` feature (but not both):
- `async` (default): Uses `reqwest` and `tokio`
- `sync`: Uses `attohttpc`

## Usage

### Asynchronous Client

```rust
use rspamd_client::{Config, EnvelopeData, scan_async};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();

    let envelope = EnvelopeData::builder()
        .from("sender@example.com".to_string())
        .rcpt(vec!["recipient@example.com".to_string()])
        .ip("127.0.0.1".to_string())
        .build();

    let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";

    let response = scan_async(&config, email, envelope).await?;
    println!("Score: {}, Action: {}", response.score, response.action);
    Ok(())
}
```

### Synchronous Client

```rust
use rspamd_client::{Config, EnvelopeData, scan_sync};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();

    let envelope = EnvelopeData::builder()
        .from("sender@example.com".to_string())
        .build();

    let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";

    let response = scan_sync(&config, email, envelope)?;
    println!("Score: {}, Action: {}", response.score, response.action);
    Ok(())
}
```

## Advanced Features

### Local File Scanning (File Header)

When the client and Rspamd server are on the same host, you can scan files without transferring the body by using the `file_path` option. This is a significant performance optimization:

```rust
use rspamd_client::{Config, EnvelopeData, scan_async};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();

    let envelope = EnvelopeData::builder()
        .from("sender@example.com".to_string())
        .file_path("/var/mail/message.eml".to_string())  // Rspamd reads file directly
        .build();

    // Empty body - file is read by Rspamd from disk
    let response = scan_async(&config, "", envelope).await?;
    println!("Scanned file with score: {}", response.score);
    Ok(())
}
```

### Body Block (Rewritten Message)

Request the rewritten message body from Rspamd when modifications are applied (e.g., subject rewriting, header changes):

```rust
use rspamd_client::{Config, EnvelopeData, scan_async};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .base_url("http://localhost:11333".to_string())
        .build();

    let envelope = EnvelopeData::builder()
        .from("sender@example.com".to_string())
        .body_block(true)  // Request rewritten body if modified
        .build();

    let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nBody content.";

    let response = scan_async(&config, email, envelope).await?;

    if let Some(rewritten_body) = response.rewritten_body {
        println!("Message was rewritten, new body size: {} bytes", rewritten_body.len());
        // Use rewritten_body instead of original
    }
    Ok(())
}
```

### Encryption (HTTPCrypt)

Use native Rspamd HTTPCrypt encryption:

```rust
let config = Config::builder()
    .base_url("http://localhost:11333".to_string())
    .encryption_key("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay".to_string())
    .build();
```

The encryption key must be in Rspamd base32 format and match the server's public key.

### Compression

ZSTD compression is enabled by default. To disable:

```rust
let config = Config::builder()
    .base_url("http://localhost:11333".to_string())
    .zstd(false)
    .build();
```

### Proxy Configuration

```rust
use rspamd_client::{Config, ProxyConfig};

let proxy = ProxyConfig {
    proxy_url: "http://proxy.example.com:8080".to_string(),
    username: Some("user".to_string()),
    password: Some("pass".to_string()),
};

let config = Config::builder()
    .base_url("http://localhost:11333".to_string())
    .proxy_config(proxy)
    .build();
```

## Configuration

### Config Options

- `base_url`: Rspamd server URL (required)
- `password`: Optional authentication password
- `timeout`: Request timeout in seconds (default: 30.0)
- `retries`: Number of retry attempts (default: 1)
- `zstd`: Enable ZSTD compression (default: true)
- `encryption_key`: HTTPCrypt encryption key (optional)
- `proxy_config`: HTTP proxy settings (optional)
- `tls_settings`: Custom TLS configuration (optional)

### EnvelopeData Options

- `from`: Sender email address
- `rcpt`: List of recipient email addresses
- `ip`: Sender IP address
- `user`: Authenticated username
- `helo`: SMTP HELO string
- `hostname`: Resolved hostname
- `file_path`: Local file path for scanning (instead of body transfer)
- `body_block`: Request rewritten body in response
- `additional_headers`: Custom HTTP headers

## Response Structure

```rust
pub struct RspamdScanReply {
    pub score: f64,                              // Spam score
    pub action: String,                          // Action to take (e.g., "reject", "add header")
    pub symbols: HashMap<String, Symbol>,        // Detected symbols
    pub messages: HashMap<String, String>,       // Messages from Rspamd
    pub urls: Vec<String>,                       // Extracted URLs
    pub emails: Vec<String>,                     // Extracted emails
    pub message_id: String,                      // Message ID
    pub time_real: f64,                          // Scan time
    pub milter: Option<Milter>,                  // Milter actions (headers to add/remove)
    pub rewritten_body: Option<Vec<u8>>,         // Rewritten message body (if body_block enabled)
    // ... other fields
}
```

## License

This project is licensed under the Apache 2.0 License.

## Contributing

Contributions are welcome! Please open a pull request or issue on [GitHub](https://github.com/rspamd/rspamdclient-rs).

## Links

- [Crates.io](https://crates.io/crates/rspamd-client)
- [Documentation](https://docs.rs/rspamd-client)
- [Rspamd Documentation](https://rspamd.com/doc/)
- [Rspamd Protocol](https://docs.rspamd.com/developers/protocol/)
