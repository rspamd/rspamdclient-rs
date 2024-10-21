use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use bytes::Bytes;
use reqwest::Client;
use url::Url;

use crate::backend::traits::*;
use crate::config::Config;
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};
use crate::protocol::RspamdScanReply;

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
	type Response = reqwest::Response;
	type HeaderMap = reqwest::header::HeaderMap;

	async fn response(&self) -> Result<Self::Response, RspamdError> {
		let mut retry_cnt = self.client.config.retries;

		let response = loop {
			let method = if self.endpoint.need_body {  reqwest::Method::POST } else { reqwest::Method::GET };

			let mut url = Url::from_str(self.client.config.base_url.as_str())
				.map_err(|e| RspamdError::HttpError(e.to_string()))?;
			url.set_path(self.endpoint.url);
			let mut req = self.client.inner.request(method, url);

			if let Some(ref password) = self.client.config.password {
				req = req.header("Password", password);
			}

			if self.client.config.zstd {
				req = req.header("Content-Encoding", "zstd");
				req = req.header("Compression", "zstd");
			}

			if self.endpoint.need_body {
				req = if self.client.config.zstd {
					req.body(reqwest::Body::from(zstd::encode_all(self.body.as_ref(), 0)?))
				}
				else {
					req.body(self.body.clone())
				};
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
			}
		}.map_err(|e| RspamdError::HttpError(e.to_string()))?;

		if !response.status().is_success() {
			return Err(RspamdError::HttpError(format!(
				"Status: {}",
				response.status()
			)));
		}

		Ok(response)
	}

	async fn response_data(&self) -> Result<ResponseData, RspamdError> {
		let response = self.response().await?;
		let status_code = response.status().as_u16();
		let headers = response.headers().clone();
		let response_headers = headers
			.clone()
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
		let body_vec = response.bytes().await.map_err(|e| RspamdError::HttpError(e.to_string()))?;
		Ok(ResponseData::new(body_vec, status_code, response_headers))
	}

	async fn response_header(&self) -> Result<(Self::HeaderMap, u16), RspamdError> {
		let response = self.response().await?;
		let status_code = response.status().as_u16();
		let headers = response.headers().clone();
		Ok((headers, status_code))
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
	let response = request.response().await.map_err(|e| RspamdError::HttpError(e.to_string()))?;
	let response = response.text().await.map_err(|e| RspamdError::HttpError(e.to_string()))?;
	let response = serde_json::from_str::<RspamdScanReply>(&response)?;
	Ok(response)
}
