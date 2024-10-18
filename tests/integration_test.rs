#[cfg(test)]
mod tests {
    use rspamd_client::config::Config;
    use rspamd_client::scan_async;

    #[cfg(feature = "sync")]
    #[test]
    fn test_sync_process() {
        let config = Config::builder()
            .base_url("http://localhost:11333".to_string())
            .build();
        let client = SyncClient::new(config).unwrap();

        let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
        let response = client.check(email).unwrap();

        assert!(response.symbols.len() > 0);
        // Add more assertions based on expected response
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_async_process() {
        let config = Config::builder()
            .base_url("http://localhost:11333".to_string())
            .build();

        let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
        let response = scan_async(&config, email).await.unwrap();
        assert!(response.symbols.len() > 0);
    }
}