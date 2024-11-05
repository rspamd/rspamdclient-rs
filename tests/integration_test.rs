#[cfg(test)]
mod tests {
    use rspamd_client::config::{Config, EnvelopeData};
    #[cfg(feature = "async")]
    use rspamd_client::scan_async;
    #[cfg(feature = "sync")]
    use rspamd_client::scan_sync;

    #[cfg(feature = "sync")]
    #[test]
    fn test_sync_process() {
        let config = Config::builder()
            .base_url("http://localhost:11333".to_string())
            .encryption_key("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay".to_string())
            .build();
        let envelope = EnvelopeData::builder()
            .from("тест@example.com".to_string())
            .build();
        let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
        let response = scan_sync(&config, email, envelope).unwrap();
        assert!(response.symbols.len() > 0);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_async_encrypted_process() {
        // Rspamd config side:
        // keypair {
        //     privkey = "oqqm9kkt7c1ws638cyf41apar3in1wuyx647gzrx88hhd94ehm3y";
        //     id = "onztu3dmoms7i7panf5mdc6hqfb3dxore8etfpftmkcy85e6jr6pujn4fgskukjfa868oceoun485rcfrywk8ihug6g1i3b8g8aj8ay";
        //     pubkey = "k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay";
        //     type = "kex";
        //     algorithm = "curve25519";
        //     encoding = "base32";
        // }
        let config = Config::builder()
            .base_url("http://localhost:11333".to_string())
            .encryption_key("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay".to_string())
            .build();
        let envelope = EnvelopeData::builder()
            .from("тест@example.com".to_string())
            .build();
        let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
        let response = scan_async(&config, email, envelope).await.unwrap();
        assert!(response.symbols.len() > 0);
    }
}