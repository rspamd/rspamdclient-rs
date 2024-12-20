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
//! - Easily configurable with support for proxy, encryption, TLS and ZSTD compression.
//! - Supports scanning emails for spam scores and other metrics.

pub mod config;
pub mod error;
pub mod protocol;

pub mod backend;

/// ### Synchronous Client
///
/// This example demonstrates how to scan an email using the synchronous client.
///
/// ```rust
/// use rspamd_client::{config, scan_sync};
///
/// fn main() {
///    let config = config::Config::builder()
///         .base_url("http://localhost:11333".to_string())
///         .build();
///     let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
///
///     match scan_sync(&config, email, Default::default()) {
///         Ok(response) => println!("Scan result: {:?}", response),
///         Err(e) => eprintln!("Error scanning email: {}", e),
///     }
/// }
/// ```
///
#[cfg(feature = "sync")]
pub use backend::sync_client::SyncClient;
#[cfg(feature = "sync")]
pub use backend::sync_client::scan_sync;

/// ### Asynchronous Client
///
/// This example demonstrates how to scan an email using the asynchronous client.
///
/// ```rust
/// use rspamd_client::{config, scan_async};
/// use tokio;
///
/// #[tokio::main]
/// async fn main() {
///     let config = config::Config::builder()
///         .base_url("http://localhost:11333".to_string())
///         .build();
///     let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
///
///     match scan_async(&config, email, Default::default()).await {
///         Ok(response) => println!("Scan result: {:?}", response),
///         Err(e) => eprintln!("Error scanning email: {}", e),
///     }
/// }
/// ```
#[cfg(feature = "async")]
pub use backend::async_client::AsyncClient;
#[cfg(feature = "async")]
pub use backend::async_client::scan_async;