
pub mod config;
pub mod error;
pub mod protocol;

pub mod backend;

#[cfg(feature = "sync")]
pub use backend::sync_client::SyncClient;
#[cfg(feature = "sync")]
pub use backend::sync_client::scan_sync;

#[cfg(feature = "async")]
pub use backend::async_client::AsyncClient;

#[cfg(feature = "async")]
pub use backend::async_client::scan_async;