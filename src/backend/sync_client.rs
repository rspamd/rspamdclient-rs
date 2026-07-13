use crate::backend::traits::*;
use crate::config::{Config, EnvelopeData};
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};
use crate::protocol::encryption::{httpcrypt_decrypt, HttpCryptContext};
use crate::protocol::scan::parse_scan_reply;
use crate::protocol::{RspamdLearnReply, RspamdScanReply};
use attohttpc::header::{HeaderMap, HeaderName, HeaderValue};
use attohttpc::{self, ProxySettingsBuilder, Session};
use bytes::Bytes;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

/// Persistent synchronous Rspamd client.
///
/// Owns the underlying `attohttpc::Session`, so per-call setup (TLS root
/// certificates, proxy settings, HTTPCrypt peer key parsing) is done once at
/// construction. Note that `attohttpc` does not pool connections, so unlike
/// [`RspamdAsyncClient`](crate::RspamdAsyncClient) each request still opens a
/// fresh TCP connection.
///
/// Cheap to clone (the configuration is shared through an `Arc`);
/// `Send + Sync + 'static`, so it can be cached and shared between threads.
#[derive(Clone)]
pub struct RspamdSyncClient {
    inner: Session,
    config: Arc<Config>,
    crypt: Option<Arc<HttpCryptContext>>,
}

impl RspamdSyncClient {
    /// Create a persistent client from a configuration.
    pub fn new(config: Config) -> Result<Self, RspamdError> {
        let mut client = Session::new();
        client.timeout(config.timeout);

        if let Some(ref proxy) = config.proxy_config {
            let proxy = ProxySettingsBuilder::new()
                .http_proxy(Url::from_str(&proxy.proxy_url)?)
                .build();
            client.proxy_settings(proxy);
        }

        if let Some(ref tls) = config.tls_settings {
            if let Some(ca_path) = tls.ca_path.as_ref() {
                let ca_data = fs::read(
                    fs::canonicalize(ca_path.as_str())
                        .map_err(|e| RspamdError::ConfigError(e.to_string()))?,
                )
                .map_err(|e| RspamdError::ConfigError(e.to_string()))?;
                let ca_cert = native_tls::Certificate::from_pem(&ca_data)
                    .map_err(|e| RspamdError::HttpError(e.to_string()))?;
                client.add_root_certificate(ca_cert);
            }
        }

        let crypt = config
            .encryption_key
            .as_deref()
            .map(HttpCryptContext::new)
            .transpose()?
            .map(Arc::new);

        Ok(Self {
            inner: client,
            config: Arc::new(config),
            crypt,
        })
    }

    /// The configuration this client was built from.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Scan an email, returning the parsed scan reply.
    pub fn scan<B: AsRef<[u8]>>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdScanReply, RspamdError> {
        let (headers, body) = self.execute(RspamdCommand::Scan, body, envelope_data)?;

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
    pub fn learn_spam<B: AsRef<[u8]>>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::Learnspam, body, envelope_data)
    }

    /// Learn an email as ham (requires the controller endpoint and password).
    pub fn learn_ham<B: AsRef<[u8]>>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::Learnham, body, envelope_data)
    }

    /// Add an email to fuzzy storage; pass `Flag`/`Weight` via
    /// `EnvelopeData::additional_headers`.
    pub fn fuzzy_add<B: AsRef<[u8]>>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::FuzzyAdd, body, envelope_data)
    }

    /// Remove an email from fuzzy storage; pass `Flag` via
    /// `EnvelopeData::additional_headers`.
    pub fn fuzzy_del<B: AsRef<[u8]>>(
        &self,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        self.learn(RspamdCommand::FuzzyDel, body, envelope_data)
    }

    fn learn<B: AsRef<[u8]>>(
        &self,
        command: RspamdCommand,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<RspamdLearnReply, RspamdError> {
        let (_headers, body) = self.execute(command, body, envelope_data)?;
        Ok(serde_json::from_slice(body.as_ref())?)
    }

    fn execute<B: AsRef<[u8]>>(
        &self,
        command: RspamdCommand,
        body: B,
        envelope_data: EnvelopeData,
    ) -> Result<(HeaderMap, Bytes), RspamdError> {
        let request = AttoRequest::new(self.clone(), body, command, envelope_data)?;
        request.response()
    }
}

#[deprecated(since = "0.7.0", note = "use RspamdSyncClient::new instead")]
pub fn sync_client(options: &Config) -> Result<RspamdSyncClient, RspamdError> {
    RspamdSyncClient::new(options.clone())
}

/// Deprecated alias kept for backwards compatibility; the client no longer
/// borrows the configuration, so the lifetime parameter is ignored.
#[deprecated(since = "0.7.0", note = "use RspamdSyncClient instead")]
pub type SyncClient<'a> = RspamdSyncClient;

pub struct AttoRequest<B> {
    endpoint: RspamdEndpoint<'static>,
    client: RspamdSyncClient,
    body: B,
    envelope_data: Option<EnvelopeData>,
}

impl<B: AsRef<[u8]>> Request for AttoRequest<B> {
    type Body = Bytes;
    type HeaderMap = HeaderMap;

    fn response(mut self) -> Result<(Self::HeaderMap, Self::Body), RspamdError> {
        let mut retry_cnt = self.client.config.retries;
        let mut maybe_sk = Default::default();
        let extra_hdrs: Vec<(String, String)> =
            self.envelope_data.take().unwrap().into_iter().collect();

        let response = loop {
            // Check if File header is present - if so, we don't need to send the body
            let has_file_header = extra_hdrs.iter().any(|(k, _)| k == "File");
            let need_body = self.endpoint.need_body && !has_file_header;

            let mut url = Url::from_str(self.client.config.base_url.as_str())
                .map_err(|e| RspamdError::HttpError(e.to_string()))?;
            url.set_path(self.endpoint.url);

            let body = if need_body {
                if self.client.config.zstd {
                    zstd::encode_all(self.body.as_ref(), 0)
                        .map_err(|e| RspamdError::HttpError(e.to_string()))?
                } else {
                    self.body.as_ref().to_vec()
                }
            } else {
                Vec::new()
            };

            let mut req = if need_body {
                self.client.inner.post(url.clone())
            } else {
                self.client.inner.get(url.clone())
            }
            .bytes(body);

            for (k, v) in extra_hdrs.iter() {
                // header_append keeps repeated keys (e.g. one Rcpt per recipient),
                // while header() would overwrite the previous value
                req = req.header_append(HeaderName::from_str(k.as_str()).unwrap(), v.clone());
            }

            if let Some(ref password) = self.client.config.password {
                req = req.header("Password", password);
            }

            if self.client.config.zstd && need_body {
                req = req.header("Content-Encoding", "zstd");
                req = req.header("Compression", "zstd");
            }

            if let Some(ref crypt) = self.client.crypt {
                let mut inner_req = req;
                let body = if need_body {
                    if self.client.config.zstd {
                        zstd::encode_all(self.body.as_ref(), 0)?
                    } else {
                        self.body.as_ref().to_vec()
                    }
                } else {
                    Vec::new()
                };
                let encrypted = crypt.encrypt(
                    url.path(),
                    body.as_slice(),
                    inner_req.inspect().headers(),
                )?;
                req = self.client.inner.post(url).bytes(encrypted.body);
                req = req.header("Key", crypt.key_header(encrypted.peer_key.as_str()));
                maybe_sk = Some(encrypted.shared_key);
            }

            req = req.timeout(self.client.config.timeout);

            match req.send() {
                Ok(v) => break Ok(v),
                Err(e) => {
                    if (retry_cnt - 1) == 0 {
                        break Err(RspamdError::HttpError(e.to_string()));
                    }
                    retry_cnt -= 1;
                    std::thread::sleep(self.client.config.timeout);
                    continue;
                }
            }
        }?;

        if !response.is_success() {
            return Err(RspamdError::HttpError(format!(
                "Status: {}",
                response.status()
            )));
        }

        if let Some(sk) = maybe_sk {
            let mut body = response
                .bytes()
                .map_err(|e| RspamdError::HttpError(e.to_string()))?;
            let decrypted_offset = httpcrypt_decrypt(body.as_mut(), sk)?;
            let mut hdrs = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Response::new(&mut hdrs);

            let body_offset = parsed
                .parse(&body.as_slice()[decrypted_offset..])
                .map_err(|s| RspamdError::HttpError(s.to_string()))?;
            let mut output_hdrs = HeaderMap::with_capacity(parsed.headers.len());
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
            let headers = response.headers().clone();
            let data = if response
                .headers()
                .get("Compression")
                .is_some_and(|hv| hv == "zstd")
            {
                zstd::decode_all(response.bytes()?.as_slice())?
            } else {
                response.bytes()?
            };

            Ok((headers, data.into()))
        }
    }
}

impl<B: AsRef<[u8]>> AttoRequest<B> {
    pub fn new(
        client: RspamdSyncClient,
        body: B,
        command: RspamdCommand,
        envelope_data: EnvelopeData,
    ) -> Result<AttoRequest<B>, RspamdError> {
        Ok(Self {
            endpoint: RspamdEndpoint::from_command(command),
            client,
            body,
            envelope_data: Some(envelope_data),
        })
    }
}

/// Synchronously scan an email
///
/// This is a one-shot helper: it builds a new client on every call. Prefer
/// [`RspamdSyncClient`] to avoid re-doing configuration and key setup per scan.
///
/// Example:
/// ```rust,no_run
/// use rspamd_client::config::Config;
/// use rspamd_client::scan_sync;
/// use rspamd_client::error::RspamdError;
///
/// fn main() -> Result<(), RspamdError>{
///   let config = Config::builder()
///             .base_url("http://localhost:11333".to_string())
///              .build();
///    let email = "From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.";
///    let envelope = Default::default();
///    let response = scan_sync(&config, email, envelope)?;
///    Ok(())
/// }
/// ```
#[deprecated(since = "0.7.0", note = "use RspamdSyncClient for a persistent client")]
pub fn scan_sync<B: AsRef<[u8]>>(
    options: &Config,
    body: B,
    envelope_data: EnvelopeData,
) -> Result<RspamdScanReply, RspamdError> {
    let client = RspamdSyncClient::new(options.clone())?;
    client.scan(body, envelope_data)
}
