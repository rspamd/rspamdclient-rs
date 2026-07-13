//!# Rspamd Client for Rust
//!
//! This crate provides an HTTP client for interacting with the Rspamd service in Rust.
//! It supports both synchronous and asynchronous operations using the `attohttpc` and
//! `reqwest` libraries, respectively.
//!
//! ## Features
//!
//! - **Sync**: Synchronous client using `attohttpc`.
//! - **Async**: Asynchronous client using `reqwest`.
//! - Persistent clients with connection pooling (async backend).
//! - Easily configurable with support for proxy, encryption, TLS and ZSTD compression.
//! - Supports scanning emails for spam scores and other metrics.

// Ensure async and sync features are mutually exclusive
#[cfg(all(feature = "async", feature = "sync"))]
compile_error!("Features 'async' and 'sync' are mutually exclusive. Please enable only one.");

#[cfg(not(any(feature = "async", feature = "sync")))]
compile_error!("Either 'async' or 'sync' feature must be enabled.");

pub mod config;
pub mod error;
pub mod protocol;

pub mod backend;

pub use config::{Config, EnvelopeData, ProxyConfig, TlsSettings};
pub use protocol::{RspamdLearnReply, RspamdScanReply};

/// ### Synchronous Client
///
/// This example demonstrates how to scan emails using the persistent
/// synchronous client.
///
/// ```rust,no_run
/// use rspamd_client::{config, RspamdSyncClient};
///
/// let config = config::Config::builder()
///     .base_url("http://localhost:11333".to_string())
///     .build();
/// let client = RspamdSyncClient::new(config).expect("cannot create client");
/// let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
///
/// match client.scan(email, Default::default()) {
///     Ok(response) => println!("Scan result: {:?}", response),
///     Err(e) => eprintln!("Error scanning email: {}", e),
/// }
/// ```
#[cfg(feature = "sync")]
pub use backend::sync_client::RspamdSyncClient;

#[cfg(feature = "sync")]
#[allow(deprecated)]
pub use backend::sync_client::{scan_sync, sync_client, SyncClient};

/// ### Asynchronous Client
///
/// This example demonstrates how to scan emails using the persistent
/// asynchronous client. The underlying connection is pooled and reused
/// across calls.
///
/// ```rust,no_run
/// use rspamd_client::{config, RspamdAsyncClient};
/// # use tokio;
///
/// # #[tokio::main]
/// # async fn main() {
/// let config = config::Config::builder()
///     .base_url("http://localhost:11333".to_string())
///     .build();
/// let client = RspamdAsyncClient::new(config).expect("cannot create client");
/// let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
///
/// match client.scan(email, Default::default()).await {
///     Ok(response) => println!("Scan result: {:?}", response),
///     Err(e) => eprintln!("Error scanning email: {}", e),
/// }
/// # }
/// ```
#[cfg(feature = "async")]
pub use backend::async_client::RspamdAsyncClient;

#[cfg(feature = "async")]
#[allow(deprecated)]
pub use backend::async_client::{async_client, scan_async, AsyncClient};
