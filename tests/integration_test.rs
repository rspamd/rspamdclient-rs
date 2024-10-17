#[cfg(test)]
mod tests {
    use rspamd_client::config::Config;
    use rspamd_client::backend::Request;
    use rspamd_client::protocol::commands::RspamdCommand;
    use rspamd_client::protocol::RspamdScanReply;

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
        let client = rspamd_client::client(&config).unwrap();

        let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
        let request = rspamd_client::backend::async_client::ReqwestRequest::new(client, email, RspamdCommand::Scan).await.unwrap();
        let response = request.response().await.unwrap();
        let response = response.text().await.unwrap();
        let response = serde_json::from_str::<RspamdScanReply>(&response).unwrap();
        assert!(response.symbols.len() > 0);
    }
}