# Changelog

## 0.7.0 - 2026-07-13

### Added

- **Persistent clients with connection pooling.** New `RspamdAsyncClient`
  (async) and `RspamdSyncClient` (sync) own the underlying HTTP client, so it
  is created once and reused across calls. With the async backend this means
  TCP (and TLS) connections are pooled and kept alive between scans instead of
  paying a fresh handshake per message. Both types are cheap to clone,
  `Send + Sync + 'static`, and suitable for caching (e.g. in an LRU keyed by
  `Config`).
- Client methods for all commands: `scan`, `learn_spam`, `learn_ham`,
  `fuzzy_add`, `fuzzy_del` (the latter two are new `RspamdCommand` variants
  targeting `/fuzzyadd` and `/fuzzydel`); learn/fuzzy replies are parsed into
  the new `RspamdLearnReply` type.
- HTTPCrypt: the peer public key is now decoded and its `Key`-header short id
  precomputed once at client construction (`HttpCryptContext`) instead of on
  every request. Ephemeral key generation and the shared-secret derivation
  remain per-request.
- Convenience re-exports at the crate root: `Config`, `EnvelopeData`,
  `ProxyConfig`, `TlsSettings`, `RspamdScanReply`, `RspamdLearnReply`.

### Changed (breaking)

- `Config::timeout` is now `std::time::Duration` instead of `f64` seconds.
- `Config` now derives `Clone`, `Eq` and `Hash` (enabled by the timeout type
  change), so it can be used directly as a cache key; `TlsSettings` and
  `ProxyConfig` derive `Eq`/`Hash` as well.
- `ReqwestRequest` and `AttoRequest` no longer borrow the configuration and
  lost their lifetime parameter; they take the new owned client types.

### Deprecated

- `scan_async(&Config, ...)` and `scan_sync(&Config, ...)`: still work as
  one-shot wrappers (constructing a throwaway client per call), but prefer
  `RspamdAsyncClient`/`RspamdSyncClient` for connection reuse.
- `async_client()`/`sync_client()` constructors and the `AsyncClient`/
  `SyncClient` aliases: use `RspamdAsyncClient::new`/`RspamdSyncClient::new`.

## 0.6.0

- fix: send one Rcpt header per recipient instead of collapsing into a single
  key
- dependency updates
