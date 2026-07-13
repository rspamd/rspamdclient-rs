use crate::backend::traits::*;
use crate::config::{Config, EnvelopeData};
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};
use crate::protocol::encryption::{httpcrypt_decrypt, HttpCryptContext};
use crate::protocol::scan::parse_scan_reply;
use crate::protocol::{RspamdLearnReply, RspamdScanReply};
use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Client;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;
use zstd::zstd_safe::WriteBuf;

/// Persistent asynchronous Rspamd client.
///
/// Owns the underlying `reqwest::Client`, so TCP (and TLS, when enabled)
/// connections are pooled and reused across calls, unlike the one-shot
/// [`scan_async`] wrapper which pays a fresh connection setup on every call.
///
/// Cheap to clone (`reqwest::Client` is internally reference-counted and the
/// configuration is shared through an `Arc`); `Send + Sync + 'static`, so it
/// is suitable for stashing in a static or an LRU cache keyed by [`Config`].
///
/// ```rust,no_run
/// use rspamd_client::config::Config;
/// use rspamd_client::RspamdAsyncClient;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), rspamd_client::error::RspamdError> {
/// let config = Config::builder()
///     .base_url("http://localhost:11333".to_string())
///     .build();
/// let client = RspamdAsyncClient::new(config)?;
/// for email in ["first message", "second message"] {
///     let reply = client.scan(email, Default::default()).await?;
///     println!("action: {}", reply.action);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct RspamdAsyncClient {
    inner: Client,
    config: Arc<Config>,
    crypt: Option<Arc<HttpCryptContext>>,
}

impl RspamdAsyncClient {
    /// Create a persistent client from a configuration.
    pub fn new(config: Config) -> Result<Self, RspamdError> {
        let client = Client::builder().timeout(config.timeout);

        let client = if let Some(ref proxy) = config.proxy_config {
            let proxy = reqwest::Proxy::all(proxy.proxy_url.clone())
                .map_err(|e| RspamdError::HttpError(e.to_string()))?;
            client.proxy(proxy)
        } else {
            client
        };
        let client = if let Some(ref tls) = config.tls_settings {
            if let Some(ca_path) = tls.ca_path.as_ref() {
                client.add_root_certificate(
                    reqwest::Certificate::from_pem(
                        &std::fs::read(std::fs::canonicalize(ca_path.as_str()).unwrap())
                            .map_err(|e| RspamdError::ConfigError(e.to_string()))?,
                    )
                    .map_err(|e| RspamdError::HttpError(e.to_string()))?,
                )
            } else {
                client
            }
        } else {
            client
        };

        let crypt = config
            .encryption_key
            .as_deref()
            .map(HttpCryptContext::new)
            .transpose()?
            .map(Arc::new);

        Ok(Self {
            inner: client
                .build()
                .map_err(|e| RspamdError::HttpError(e.to_string()))?,
            config: Arc::new(config),
            crypt,
        })
    }

    /// The configuration this client was built from.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Scan an email, returning the parsed scan reply.
    pub async fn scan<B: AsRef<[u8]> + Send>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdScanReply, RspamdError> {
        let (headers, body) = self.execute(RspamdCommand::Scan, body, envelope_data).await?;

        // Check for Message-Offset header to handle body_block feature
        let message_offset = headers
            .get("Message-Offset")
            .map(|v| {
                v.to_str().map_err(|e| {
                    RspamdError::HttpError(format!("Invalid Message-Offset header: {}", e))
                })
            })
            .transpose()?;
        parse_scan_reply(message_offset, body.as_ref())
    }

    /// Learn an email as spam (requires the controller endpoint and password).
    pub async fn learn_spam<B: AsRef<[u8]> + Send>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::Learnspam, body, envelope_data)
            .await
    }

    /// Learn an email as ham (requires the controller endpoint and password).
    pub async fn learn_ham<B: AsRef<[u8]> + Send>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::Learnham, body, envelope_data)
            .await
    }

    /// Add an email to fuzzy storage; pass `Flag`/`Weight` via
    /// `EnvelopeData::additional_headers`.
    pub async fn fuzzy_add<B: AsRef<[u8]> + Send>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::FuzzyAdd, body, envelope_data)
            .await
    }

    /// Remove an email from fuzzy storage; pass `Flag` via
    /// `EnvelopeData::additional_headers`.
    pub async fn fuzzy_del<B: AsRef<[u8]> + Send>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::FuzzyDel, body, envelope_data)
            .await
    }

    async fn learn<B: AsRef<[u8]> + Send>(
        &self,
        command: RspamdCommand,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        let (_headers, body) = self.execute(command, body, envelope_data).await?;
        Ok(serde_json::from_slice(body.as_ref())?)
    }

    async fn execute<B: AsRef<[u8]> + Send>(
        &self,
        command: RspamdCommand,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<(reqwest::header::HeaderMap, Bytes), RspamdError> {
        let request = ReqwestRequest::new(self.clone(), body, command, envelope_data).await?;
        request.response().await
    }
}

#[cfg(feature = "async")]
#[deprecated(since = "0.7.0", note = "use RspamdAsyncClient::new for connection pooling")]
pub fn async_client(options: &Config) -> Result<RspamdAsyncClient, RspamdError> {
    RspamdAsyncClient::new(options.clone())
}

/// Deprecated alias kept for backwards compatibility; the client no longer
/// borrows the configuration, so the lifetime parameter is ignored.
#[deprecated(since = "0.7.0", note = "use RspamdAsyncClient instead")]
pub type AsyncClient<'a> = RspamdAsyncClient;

// Temporary structure for making a request
pub struct ReqwestRequest<B> {
    endpoint: RspamdEndpoint<'static>,
    client: RspamdAsyncClient,
    body: B,
    envelope_data: Option<EnvelopeData>,
}

#[maybe_async::maybe_async]
impl<B: AsRef<[u8]> + Send> Request for ReqwestRequest<B> {
    type Body = Bytes;
    type HeaderMap = reqwest::header::HeaderMap;

    async fn response(mut self) -> Result<(Self::HeaderMap, Self::Body), RspamdError> {
        let mut retry_cnt = self.client.config.retries;
        let mut maybe_sk = Default::default();
        let extra_hdrs: Vec<(String, String)> =
            self.envelope_data.take().unwrap().into_iter().collect();

        let response = loop {
            // Check if File header is present - if so, we don't need to send the body
            let has_file_header = extra_hdrs.iter().any(|(k, _)| k == "File");
            let need_body = self.endpoint.need_body && !has_file_header;
            let method = if need_body {
                reqwest::Method::POST
            } else {
                reqwest::Method::GET
            };

            let mut url = Url::from_str(self.client.config.base_url.as_str())
                .map_err(|e| RspamdError::HttpError(e.to_string()))?;
            url.set_path(self.endpoint.url);
            let mut req = self.client.inner.request(method, url.clone());

            if let Some(ref password) = self.client.config.password {
                req = req.header("Password", password);
            }

            if self.client.config.zstd && need_body {
                req = req.header("Content-Encoding", "zstd");
                req = req.header("Compression", "zstd");
            }

            for (k, v) in extra_hdrs.iter() {
                req = req.header(k, v);
            }

            if let Some(ref crypt) = self.client.crypt {
                let inner_req = req
                    .build()
                    .map_err(|e| RspamdError::HttpError(e.to_string()))?;
                let body = if need_body {
                    if self.client.config.zstd {
                        zstd::encode_all(self.body.as_ref(), 0)?
                    } else {
                        self.body.as_ref().to_vec()
                    }
                } else {
                    Vec::new()
                };
                let encrypted = crypt.encrypt(url.path(), body.as_slice(), inner_req.headers())?;
                req = self.client.inner.request(reqwest::Method::POST, url);
                req = req.header("Key", crypt.key_header(encrypted.peer_key.as_str()));
                req = req.body(encrypted.body);
                maybe_sk = Some(encrypted.shared_key);
            } else if need_body {
                req = if self.client.config.zstd {
                    req.body(reqwest::Body::from(zstd::encode_all(
                        self.body.as_ref(),
                        0,
                    )?))
                } else {
                    req.body(Bytes::copy_from_slice(self.body.as_ref()))
                };
            }

            let req = req.timeout(self.client.config.timeout);
            let req = req
                .build()
                .map_err(|e| RspamdError::HttpError(e.to_string()))?;

            match self.client.inner.execute(req).await {
                Ok(v) => break Ok(v),
                Err(e) => {
                    if (retry_cnt - 1) == 0 {
                        break Err(e);
                    }
                    retry_cnt -= 1;
                    tokio::time::sleep(self.client.config.timeout).await;
                    continue;
                }
            };
        }
        .map_err(|e| RspamdError::HttpError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(RspamdError::HttpError(format!(
                "Status: {}",
                response.status()
            )));
        }

        if let Some(sk) = maybe_sk {
            let mut body = BytesMut::from(
                response
                    .bytes()
                    .await
                    .map_err(|e| RspamdError::HttpError(e.to_string()))?,
            );
            let decrypted_offset = httpcrypt_decrypt(body.as_mut(), sk)?;
            let mut hdrs = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Response::new(&mut hdrs);

            let body_offset = parsed
                .parse(&body.as_slice()[decrypted_offset..])
                .map_err(|s| RspamdError::HttpError(s.to_string()))?;
            let mut output_hdrs = reqwest::header::HeaderMap::with_capacity(parsed.headers.len());
            for hdr in parsed.headers.iter_mut() {
                output_hdrs.insert(
                    HeaderName::from_str(hdr.name)?,
                    HeaderValue::from_str(std::str::from_utf8(hdr.value)?)?,
                );
            }
            let body = if output_hdrs
                .get("Compression")
                .is_some_and(|hv| hv == "zstd")
            {
                zstd::decode_all(&body.as_slice()[body_offset.unwrap() + decrypted_offset..])?
            } else {
                body.as_slice()[body_offset.unwrap() + decrypted_offset..].to_vec()
            };
            Ok((output_hdrs, body.into()))
        } else {
            Ok((response.headers().clone(), response.bytes().await?))
        }
    }
}

#[maybe_async::maybe_async]
impl<B: AsRef<[u8]> + Send> ReqwestRequest<B> {
    pub async fn new(
        client: RspamdAsyncClient,
        body: B,
        command: RspamdCommand,
        envelope_data: EnvelopeData,
    ) -> Result<ReqwestRequest<B>, RspamdError> {
        Ok(Self {
            endpoint: RspamdEndpoint::from_command(command),
            client,
            body,
            envelope_data: Some(envelope_data),
        })
    }
}

/// Scan an email asynchronously, returning the parsed reply or error.
///
/// This is a one-shot helper: it builds a new client (and therefore a new
/// connection) on every call. Prefer [`RspamdAsyncClient`] to reuse
/// connections across scans.
///
/// Example:
/// ```rust,no_run
/// use rspamd_client::config::Config;
/// use rspamd_client::scan_async;
/// use rspamd_client::error::RspamdError;
///
///	#[tokio::main]
/// async fn main() -> Result<(), RspamdError> {
/// 	let config = Config::builder()
/// 		.base_url("http://localhost:11333".to_string())
/// 		.build();
/// 	let envelope = Default::default();
/// 	let email = "...";
/// 	let response = scan_async(&config, email, envelope).await?;
/// 	Ok(())
/// }
/// ```
#[deprecated(since = "0.7.0", note = "use RspamdAsyncClient for connection pooling")]
#[maybe_async::maybe_async]
pub async fn scan_async<B: AsRef<[u8]> + Send>(
    options: &Config,
    body: B,
    envelope_data: EnvelopeData,
) -> Result<RspamdScanReply, RspamdError> {
    let client = RspamdAsyncClient::new(options.clone())?;
    client.scan(body, envelope_data).await
}
