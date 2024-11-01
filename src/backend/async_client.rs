use std::str::FromStr;
use std::time::Duration;
use bytes::{Bytes, BytesMut};
use reqwest::Client;
use reqwest::header::{HeaderName, HeaderValue};
use url::Url;
use zstd::zstd_safe::WriteBuf;
use crate::backend::traits::*;
use crate::config::Config;
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};
use crate::protocol::RspamdScanReply;
use crate::protocol::encryption::{httpcrypt_encrypt, httpcrypt_decrypt, make_key_header};

pub struct AsyncClient<'a> {
	config: &'a Config,
	inner: Client,
}

#[cfg(feature = "async")]
pub fn async_client(options: &Config) -> Result<AsyncClient, RspamdError> {
	let client = Client::builder()
		.timeout(Duration::from_secs_f64(options.timeout));

	let client = if let Some(ref proxy) = options.proxy_config {
		let proxy = reqwest::Proxy::all(proxy.proxy_url.clone()).map_err(|e| RspamdError::HttpError(e.to_string()))?;
		client.proxy(proxy)
	} else {
		client
	};
	let client = if let Some(ref tls) = options.tls_settings {
		if let Some(ca_path) = tls.ca_path.as_ref() {
			client.add_root_certificate(reqwest::Certificate::from_pem(
				&std::fs::read(std::fs::canonicalize(ca_path.as_str()).unwrap())
				.map_err(|e| RspamdError::ConfigError(e.to_string()))?)
				.map_err(|e| RspamdError::HttpError(e.to_string()))?)
		}
		else {
			client
		}
	} else {
		client
	};


	Ok(AsyncClient{
		inner: client.build()
			.map_err(|e| RspamdError::HttpError(e.to_string()))?,
		config: options,
	})
}

// Temporary structure for making a request
pub struct ReqwestRequest<'a> {
	endpoint: RspamdEndpoint<'a>,
	client: AsyncClient<'a>,
	body: Bytes,
}

#[maybe_async::maybe_async]
impl<'a> Request for ReqwestRequest<'a> {
	type Body = Bytes;
	type HeaderMap = reqwest::header::HeaderMap;

	async fn response(&self) -> Result<(Self::HeaderMap, Self::Body), RspamdError> {
		let mut retry_cnt = self.client.config.retries;
		let mut maybe_sk = Default::default();

		let response = loop {
			let method = if self.endpoint.need_body {  reqwest::Method::POST } else { reqwest::Method::GET };

			let mut url = Url::from_str(self.client.config.base_url.as_str())
				.map_err(|e| RspamdError::HttpError(e.to_string()))?;
			url.set_path(self.endpoint.url);
			let mut req = self.client.inner.request(method, url.clone());

			if let Some(ref password) = self.client.config.password {
				req = req.header("Password", password);
			}

			if self.client.config.zstd {
				req = req.header("Content-Encoding", "zstd");
				req = req.header("Compression", "zstd");
			}

			if let Some(ref encryption_key) = self.client.config.encryption_key {
				let inner_req = req.build().map_err(|e| RspamdError::HttpError(e.to_string()))?;
				let body = if self.client.config.zstd {
					zstd::encode_all(self.body.as_ref(), 0)?
				}
				else {
					self.body.to_vec()
				};
				let encrypted = httpcrypt_encrypt(
					url.path(),
					body.as_slice(),
					inner_req.headers(),
					encryption_key.as_bytes(),
				)?;
				req = self.client.inner.request(reqwest::Method::POST, url);
				let key_header = make_key_header(encryption_key.as_str(), encrypted.peer_key.as_str())?;
				req = req.header("Key", key_header);
				req = req.body(encrypted.body);
				maybe_sk = Some(encrypted.shared_key);
			}
			else {
				if self.endpoint.need_body {
					req = if self.client.config.zstd {
						req.body(reqwest::Body::from(zstd::encode_all(self.body.as_ref(), 0)?))
					}
					else {
						req.body(self.body.clone())
					};
				}
			}

			let req = req.timeout(Duration::from_secs_f64(self.client.config.timeout));
			let req = req.build().map_err(|e| RspamdError::HttpError(e.to_string()))?;

			match self.client.inner.execute(req).await {
				Ok(v) => break Ok(v),
				Err(e) => {
					if (retry_cnt - 1) == 0 {
						break Err(e);
					}
					retry_cnt -= 1;
					let delay = Duration::from_secs_f64(self.client.config.timeout);
					tokio::time::sleep(delay).await;
					continue;
				}
			};
		}.map_err(|e| RspamdError::HttpError(e.to_string()))?;

		if !response.status().is_success() {
			return Err(RspamdError::HttpError(format!(
				"Status: {}",
				response.status()
			)));
		}

		if let Some(sk) = maybe_sk {
			let mut body = BytesMut::from(response.bytes().await.map_err(|e| RspamdError::HttpError(e.to_string()))?);
			let decrypted_offset = httpcrypt_decrypt(body.as_mut(), sk)?;
			let mut hdrs = [httparse::EMPTY_HEADER; 64];
			let mut parsed = httparse::Response::new(&mut hdrs);

			let body_offset = parsed.parse(&body.as_slice()[decrypted_offset..]).map_err(|s| RspamdError::HttpError(s.to_string()))?;
			let mut output_hdrs = reqwest::header::HeaderMap::with_capacity(hdrs.len());
			for hdr in hdrs.into_iter() {
				output_hdrs.insert(HeaderName::from_str(hdr.name)?, HeaderValue::from_str(std::str::from_utf8(hdr.value)?)?);
			}
			let body = body.as_slice()[body_offset.unwrap() + decrypted_offset..].to_vec();
			Ok((output_hdrs, body.into()))
		}
		else {
			Ok((response.headers().clone(), response.bytes().await?))
		}
	}
}

#[maybe_async::maybe_async]
impl<'a> ReqwestRequest<'a> {
	pub async fn new<T: Into<Bytes>>(
		client: AsyncClient<'a>,
		body: T,
		command: RspamdCommand,
	) -> Result<ReqwestRequest<'a>, RspamdError> {
		Ok(Self {
			endpoint: RspamdEndpoint::from_command(command),
			client,
			body: body.into(),
		})
	}
}

/// Scan an email asynchronously, returning the parsed reply or error.
/// Example:
/// ```rust
/// use rspamd_client::config::Config;
/// use rspamd_client::scan_async;
/// use rspamd_client::error::RspamdError;
/// use bytes::Bytes;
/// use std::str::FromStr;
///
///	#[tokio::main]
/// async fn main() -> Result<(), RspamdError> {
/// 	let config = Config::builder()
/// 		.base_url("http://localhost:11333".to_string())
/// 		.build();
/// 	let email = "...";
/// 	let response = scan_async(&config, email).await?;
/// 	Ok(())
/// }
/// ```
#[maybe_async::maybe_async]
pub async fn scan_async<T: Into<Bytes>>(options: &Config, body: T) -> Result<RspamdScanReply, RspamdError> {
	let client = async_client(options)?;
	let request = ReqwestRequest::new(client, body, RspamdCommand::Scan).await?;
	let (_, body) = request.response().await.map_err(|e| RspamdError::HttpError(e.to_string()))?;
	let response = serde_json::from_slice::<RspamdScanReply>(body.as_ref())?;
	Ok(response)
}
