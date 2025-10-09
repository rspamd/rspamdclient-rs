use attohttpc::{self, Session, ProxySettingsBuilder};
use attohttpc::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::time::Duration;
use bytes::Bytes;
use std::str::FromStr;
use std::fs;
use url::Url;
use crate::backend::traits::*;
use crate::config::{Config, EnvelopeData};
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};
use crate::protocol::encryption::{httpcrypt_decrypt, httpcrypt_encrypt, make_key_header};
use crate::protocol::RspamdScanReply;

pub struct SyncClient<'a> {
	config: &'a Config,
	inner: Session,
}

pub fn sync_client(options: &Config) -> Result<SyncClient, RspamdError> {
	let mut client = Session::new();
	client.timeout(Duration::from_secs_f64(options.timeout));

	if let Some(ref proxy) = options.proxy_config {
		let proxy = ProxySettingsBuilder::new().http_proxy(Url::from_str(&proxy.proxy_url)?).build();
		client.proxy_settings(proxy);
	}

	if let Some(ref tls) = options.tls_settings {
		if let Some(ca_path) = tls.ca_path.as_ref() {
			let ca_data = fs::read(fs::canonicalize(ca_path.as_str()).map_err(|e| RspamdError::ConfigError(e.to_string()))?)
				.map_err(|e| RspamdError::ConfigError(e.to_string()))?;
			let ca_cert = native_tls::Certificate::from_pem(&ca_data).map_err(|e| RspamdError::HttpError(e.to_string()))?;
			client.add_root_certificate(ca_cert);
		}
	}

	Ok(SyncClient {
		inner: client,
		config: options,
	})
}

pub struct AttoRequest<'a> {
	endpoint: RspamdEndpoint<'a>,
	client: SyncClient<'a>,
	body: Bytes,
	envelope_data: Option<EnvelopeData>,
}

impl<'a> Request for AttoRequest<'a> {
	type Body = Bytes;
	type HeaderMap = HeaderMap;

	fn response(mut self) -> Result<(Self::HeaderMap, Self::Body), RspamdError> {
		let mut retry_cnt = self.client.config.retries;
		let mut maybe_sk = Default::default();
		let extra_hdrs :  HashMap<String, String> = HashMap::from_iter(self.envelope_data.take().unwrap().into_iter());

		let response = loop {
			// Check if File header is present - if so, we don't need to send the body
			let has_file_header = extra_hdrs.contains_key("File");
			let need_body = self.endpoint.need_body && !has_file_header;

			let mut url = Url::from_str(self.client.config.base_url.as_str())
				.map_err(|e| RspamdError::HttpError(e.to_string()))?;
			url.set_path(self.endpoint.url);

			let body = if need_body {
				if self.client.config.zstd {
					zstd::encode_all(self.body.as_ref(), 0)
						.map_err(|e| RspamdError::HttpError(e.to_string()))?
				} else {
					self.body.to_vec()
				}
			}
			else {
				Vec::new()
			};


			let mut req  = if need_body {
				self.client.inner.post(url.clone())
			}
			else {
				self.client.inner.get(url.clone())
			}.bytes(body);

			for (k, v) in extra_hdrs.iter() {
				req = req.header(HeaderName::from_str(k.as_str()).unwrap(), v.clone());
			}

			if let Some(ref password) = self.client.config.password {
				req = req.header("Password", password);
			}

			if self.client.config.zstd && need_body {
				req = req.header("Content-Encoding", "zstd");
				req = req.header("Compression", "zstd");
			}

			if let Some(ref encryption_key) = self.client.config.encryption_key {
				let mut inner_req = req;
				let body = if need_body {
					if self.client.config.zstd {
						zstd::encode_all(self.body.as_ref(), 0)?
					}
					else {
						self.body.to_vec()
					}
				} else {
					Vec::new()
				};
				let encrypted = httpcrypt_encrypt(
					url.path(),
					body.as_slice(),
					inner_req.inspect().headers(),
					encryption_key.as_bytes(),
				)?;
				req = self.client.inner.post(url).bytes(encrypted.body);
				let key_header = make_key_header(encryption_key.as_str(), encrypted.peer_key.as_str())?;
				req = req.header("Key", key_header);
				maybe_sk = Some(encrypted.shared_key);
			}

			req = req.timeout(Duration::from_secs_f64(self.client.config.timeout));

			match req.send() {
				Ok(v) => break Ok(v),
				Err(e) => {
					if (retry_cnt - 1) == 0 {
						break Err(RspamdError::HttpError(e.to_string()));
					}
					retry_cnt -= 1;
					std::thread::sleep(Duration::from_secs_f64(self.client.config.timeout));
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
			let mut body = response.bytes().map_err(|e| RspamdError::HttpError(e.to_string()))?;
			let decrypted_offset = httpcrypt_decrypt(body.as_mut(), sk)?;
			let mut hdrs = [httparse::EMPTY_HEADER; 64];
			let mut parsed = httparse::Response::new(&mut hdrs);

			let body_offset = parsed.parse(&body.as_slice()[decrypted_offset..]).map_err(|s| RspamdError::HttpError(s.to_string()))?;
			let mut output_hdrs = HeaderMap::with_capacity(parsed.headers.len());
			for hdr in parsed.headers.into_iter() {
				output_hdrs.insert(HeaderName::from_str(hdr.name)?, HeaderValue::from_str(std::str::from_utf8(hdr.value)?)?);
			}
			let body = if output_hdrs.get("Compression").map_or(false,
																|hv| hv == "zstd") {
				zstd::decode_all(&body.as_slice()[body_offset.unwrap() + decrypted_offset..])?
			} else {
				body.as_slice()[body_offset.unwrap() + decrypted_offset..].to_vec()
			};
			Ok((output_hdrs, body.into()))
		}
		else {
			let headers = response.headers().clone();
			let data = if response.headers().get("Compression").map_or(false, |hv| hv == "zstd") {
				zstd::decode_all(response.bytes()?.as_slice())?
			}
			else {
				response.bytes()?
			};

			Ok((headers, data.into()))
		}
	}
}

impl<'a> AttoRequest<'a> {
	pub fn new<T: Into<Bytes>>(
		client: SyncClient<'a>,
		body: T,
		command: RspamdCommand,
		envelope_data: EnvelopeData,
	) -> Result<AttoRequest<'a>, RspamdError> {
		Ok(Self {
			endpoint: RspamdEndpoint::from_command(command),
			client,
			body: body.into(),
			envelope_data: Some(envelope_data),
		})
	}
}

/// Synchronously scan an email
/// Example:
/// ```rust
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
///
pub fn scan_sync<T: Into<Bytes>>(options: &Config, body: T, envelope_data: EnvelopeData) -> Result<RspamdScanReply, RspamdError> {
	let client = sync_client(options)?;
	let request = AttoRequest::new(client, body, RspamdCommand::Scan, envelope_data)?;
	let (_, body) = request.response().map_err(|e| RspamdError::HttpError(e.to_string()))?;
	Ok(serde_json::from_slice::<RspamdScanReply>(body.as_ref())?)
}