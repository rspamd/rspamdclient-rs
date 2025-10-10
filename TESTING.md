# Testing Guide

This document describes how to run tests for the rspamd-client crate.

## Prerequisites

- Docker and Docker Compose installed
- Rust toolchain (stable, beta, or nightly)

## Running Tests

### 1. Start Rspamd Test Server

The test suite requires a running Rspamd instance with encryption support. Start it using Docker Compose:

```bash
docker compose up -d
```

This will start an Rspamd container with:
- HTTP API on port 11333
- Controller API on port 11334
- Encryption keys configured for testing
- All necessary modules enabled

### 2. Wait for Rspamd to be Ready

The container includes a health check. You can verify it's ready:

```bash
docker compose ps
# Wait until rspamd-test shows "healthy" status
```

Or manually test:

```bash
curl http://localhost:11333/ping
# Should return: pong
```

### 3. Prepare Test File (for File Header Tests)

Create a test email file and copy it into the container:

```bash
echo "From: test@example.com
To: user@example.com
Subject: Test

Test email body" > /tmp/test_email.eml

docker cp /tmp/test_email.eml rspamd-test:/tmp/test_email.eml
```

### 4. Run Tests

Run tests with either the `async` or `sync` feature:

```bash
# Test async client
cargo test --features async

# Test sync client
cargo test --features sync

# Run all tests with verbose output
cargo test --features async --verbose
```

### 5. Run Clippy and Format Checks

```bash
# Check code formatting
cargo fmt -- --check

# Run clippy linter
cargo clippy --features async --all-targets -- -D warnings
cargo clippy --features sync --all-targets -- -D warnings
```

### 6. Stop Rspamd

When done testing:

```bash
docker compose down
```

## Test Configuration

The Rspamd test instance uses the following configuration:

- **Encryption Key** (for HTTPCrypt tests):
  - Public key: `k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay`
  - Private key: `oqqm9kkt7c1ws638cyf41apar3in1wuyx647gzrx88hhd94ehm3y`

- **Custom Configuration**: Located in `tests/rspamd-config/`
  - `worker-normal.inc` - Normal worker settings
  - `worker-controller.inc` - Controller settings with encryption
  - `options.inc` - General options

## Continuous Integration

The CI pipeline automatically:
1. Starts Rspamd container
2. Waits for health check
3. Creates test files
4. Runs tests on multiple Rust versions (stable, beta, nightly)
5. Tests both async and sync features
6. Runs clippy and rustfmt checks
7. Cleans up containers

## Troubleshooting

### Container fails to start

Check Docker logs:
```bash
docker compose logs rspamd
```

### Tests fail with connection errors

Ensure Rspamd is running and healthy:
```bash
docker compose ps
curl http://localhost:11333/ping
```

### Encryption tests fail

Verify the encryption key in tests matches the configuration in `tests/rspamd-config/worker-*.inc`.

### File header tests fail

Ensure the test file exists inside the container:
```bash
docker compose exec rspamd ls -la /tmp/test_email.eml
```
