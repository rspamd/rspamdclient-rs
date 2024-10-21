use attohttpc::{self, Response, Session, ProxySettingsBuilder};
use attohttpc::header::HeaderMap;
use std::collections::HashMap;
use std::time::Duration;
use bytes::Bytes;
use std::str::FromStr;
use std::fs;
use url::Url;
use crate::backend::traits::*;
use crate::config::Config;
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};
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
}

impl<'a> Request for AttoRequest<'a> {
	type Response = Response;
	type HeaderMap = HeaderMap;

	fn response(&self) -> Result<Self::Response, RspamdError> {
		let mut retry_cnt = self.client.config.retries;

		let response = loop {
			let mut url = Url::from_str(self.client.config.base_url.as_str())
				.map_err(|e| RspamdError::HttpError(e.to_string()))?;
			url.set_path(self.endpoint.url);

			let body = if self.endpoint.need_body {
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

			let mut req  = if self.endpoint.need_body {
				self.client.inner.post(url)
			}
			else {
				self.client.inner.get(url)
			}.bytes(body);

			if let Some(ref password) = self.client.config.password {
				req = req.header("Password", password);
			}

			if self.client.config.zstd {
				req = req.header("Content-Encoding", "zstd");
				req = req.header("Compression", "zstd");
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

		Ok(response)
	}

	fn response_data(&self) -> Result<ResponseData, RspamdError> {
		let response = self.response()?;
		let status_code = response.status().as_u16();
		let headers = response.headers().clone();
		let response_headers = headers
			.iter()
			.map(|(k, v)| {
				(
					k.to_string(),
					v.to_str()
						.unwrap_or("could-not-decode-header-value")
						.to_string(),
				)
			})
			.collect::<HashMap<String, String>>();
		let body_vec = response.bytes().map_err(|e| RspamdError::HttpError(e.to_string()))?;
		Ok(ResponseData::new(Bytes::from(body_vec), status_code, response_headers))
	}

	fn response_header(&self) -> Result<(Self::HeaderMap, u16), RspamdError> {
		let response = self.response()?;
		let status_code = response.status().as_u16();
		let headers = response.headers().clone();
		Ok((headers, status_code))
	}
}

impl<'a> AttoRequest<'a> {
	pub fn new<T: Into<Bytes>>(
		client: SyncClient<'a>,
		body: T,
		command: RspamdCommand,
	) -> Result<AttoRequest<'a>, RspamdError> {
		Ok(Self {
			endpoint: RspamdEndpoint::from_command(command),
			client,
			body: body.into(),
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
///    let response = scan_sync(&config, email)?;
///    Ok(())
/// }
///
pub fn scan_sync<T: Into<Bytes>>(options: &Config, body: T) -> Result<RspamdScanReply, RspamdError> {
	let client = sync_client(options)?;
	let request = AttoRequest::new(client, body, RspamdCommand::Scan)?;
	let response = request.response().map_err(|e| RspamdError::HttpError(e.to_string()))?;
	let is_compressed = response.headers().get("Compression").map(|hdr| return hdr == "zstd").unwrap_or_default();
	let response = if is_compressed {
		zstd::decode_all(response.bytes().map_err(|e| RspamdError::HttpError(e.to_string()))?.as_slice())?
	}
	else {
		response.bytes().map_err(|e| RspamdError::HttpError(e.to_string()))?
	};
	let response = serde_json::from_slice::<RspamdScanReply>(&response)?;
	Ok(response)
}