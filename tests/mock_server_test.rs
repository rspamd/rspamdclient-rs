//! Self-contained tests against a minimal in-process HTTP/1.1 mock server.
//! Unlike `integration_test.rs`, these do not require a running Rspamd.

const EMAIL: &str =
    "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
const SCAN_REPLY: &str = r#"{"action":"no action","score":1.5,"required_score":15.0,"symbols":{"MOCK_SYMBOL":{"name":"MOCK_SYMBOL","score":1.5}},"message-id":"mock"}"#;
const LEARN_REPLY: &str = r#"{"success":true}"#;

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn reply_for(head: &str) -> String {
    let reply = if head.starts_with("POST /learn") || head.starts_with("POST /fuzzy") {
        LEARN_REPLY
    } else {
        SCAN_REPLY
    };
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        reply.len(),
        reply
    )
}

#[cfg(feature = "async")]
mod async_tests {
    use super::*;
    use rspamd_client::config::Config;
    use rspamd_client::RspamdAsyncClient;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn handle_connection(mut sock: TcpStream) {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            // Read until the end of the request headers
            let hdr_end = loop {
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    break pos + 4;
                }
                let mut chunk = [0u8; 4096];
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };

            let head = String::from_utf8_lossy(&buf[..hdr_end]).to_string();
            let total = hdr_end + content_length(&head);
            while buf.len() < total {
                let mut chunk = [0u8; 4096];
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            buf.drain(..total);

            if sock.write_all(reply_for(&head).as_bytes()).await.is_err() {
                return;
            }
        }
    }

    /// Minimal keep-alive HTTP/1.1 server counting accepted TCP connections
    async fn spawn_mock_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(handle_connection(sock));
            }
        });
        (format!("http://{}", addr), connections)
    }

    #[tokio::test]
    async fn persistent_client_scans_sequentially() {
        let (url, _connections) = spawn_mock_server().await;
        let config = Config::builder().base_url(url).build();
        let client = RspamdAsyncClient::new(config).unwrap();
        for _ in 0..5 {
            let reply = client.scan(EMAIL, Default::default()).await.unwrap();
            assert_eq!(reply.action, "no action");
            assert!(reply.symbols.contains_key("MOCK_SYMBOL"));
        }
    }

    #[tokio::test]
    async fn persistent_client_reuses_one_connection() {
        let (url, connections) = spawn_mock_server().await;
        let config = Config::builder().base_url(url).build();
        let client = RspamdAsyncClient::new(config).unwrap();
        for _ in 0..5 {
            client.scan(EMAIL, Default::default()).await.unwrap();
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn one_shot_scans_open_a_connection_each() {
        let (url, connections) = spawn_mock_server().await;
        let config = Config::builder().base_url(url).build();
        for _ in 0..3 {
            #[allow(deprecated)]
            rspamd_client::scan_async(&config, EMAIL, Default::default())
                .await
                .unwrap();
        }
        assert_eq!(connections.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cloned_client_shares_the_connection_pool() {
        let (url, connections) = spawn_mock_server().await;
        let config = Config::builder().base_url(url).build();
        let client = RspamdAsyncClient::new(config).unwrap();
        for _ in 0..3 {
            let clone = client.clone();
            clone.scan(EMAIL, Default::default()).await.unwrap();
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn learn_commands_parse_success_reply() {
        let (url, _connections) = spawn_mock_server().await;
        let config = Config::builder().base_url(url).build();
        let client = RspamdAsyncClient::new(config).unwrap();
        assert!(
            client
                .learn_spam(EMAIL, Default::default())
                .await
                .unwrap()
                .success
        );
        assert!(
            client
                .learn_ham(EMAIL, Default::default())
                .await
                .unwrap()
                .success
        );
        assert!(
            client
                .fuzzy_add(EMAIL, Default::default())
                .await
                .unwrap()
                .success
        );
    }

    #[test]
    fn client_is_cacheable() {
        fn assert_bounds<T: Clone + Send + Sync + 'static>() {}
        assert_bounds::<RspamdAsyncClient>();
    }
}

#[cfg(feature = "sync")]
mod sync_tests {
    use super::*;
    use rspamd_client::config::Config;
    use rspamd_client::RspamdSyncClient;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn handle_connection(mut sock: TcpStream) {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let hdr_end = loop {
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    break pos + 4;
                }
                let mut chunk = [0u8; 4096];
                match sock.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };

            let head = String::from_utf8_lossy(&buf[..hdr_end]).to_string();
            let total = hdr_end + content_length(&head);
            while buf.len() < total {
                let mut chunk = [0u8; 4096];
                match sock.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            buf.drain(..total);

            if sock.write_all(reply_for(&head).as_bytes()).is_err() {
                return;
            }
        }
    }

    fn spawn_mock_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((sock, _)) = listener.accept() {
                std::thread::spawn(move || handle_connection(sock));
            }
        });
        format!("http://{}", addr)
    }

    #[test]
    fn persistent_client_scans_sequentially() {
        let url = spawn_mock_server();
        let config = Config::builder().base_url(url).build();
        let client = RspamdSyncClient::new(config).unwrap();
        for _ in 0..5 {
            let reply = client.scan(EMAIL, Default::default()).unwrap();
            assert_eq!(reply.action, "no action");
            assert!(reply.symbols.contains_key("MOCK_SYMBOL"));
        }
    }

    #[test]
    fn learn_commands_parse_success_reply() {
        let url = spawn_mock_server();
        let config = Config::builder().base_url(url).build();
        let client = RspamdSyncClient::new(config).unwrap();
        assert!(
            client
                .learn_spam(EMAIL, Default::default())
                .unwrap()
                .success
        );
        assert!(client.fuzzy_del(EMAIL, Default::default()).unwrap().success);
    }

    #[test]
    fn client_is_cacheable() {
        fn assert_bounds<T: Clone + Send + Sync + 'static>() {}
        assert_bounds::<RspamdSyncClient>();
    }
}
