use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use reqwest::{Client, Url};

use crate::backend::traits::*;
use crate::config::Config;
use crate::error::RspamdError;
use crate::protocol::commands::{RspamdCommand, RspamdEndpoint};

pub struct AsyncClient<'a> {
	config: &'a Config,
	inner: Client,
}

#[cfg(feature = "async")]
pub fn client(options: &Config) -> Result<AsyncClient, RspamdError> {
	let client = Client::builder()
		.timeout(Duration::from_secs_f64(options.timeout));

	let client = if let Some(ref proxy) = options.proxy_config {
		let proxy = reqwest::Proxy::all(proxy.proxy_url.clone())?;
		client.proxy(proxy)
	} else {
		client
	};
	let client = if let Some(ref tls) = options.tls_settings {
		if let Some(ca_path) = tls.ca_path.as_ref() {
			client.add_root_certificate(reqwest::Certificate::from_pem(
				&std::fs::read(std::fs::canonicalize(ca_path.as_str()).unwrap())
				.map_err(|e| RspamdError::ConfigError(e.to_string()))?)?)
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
	body: &'a str,
}

#[maybe_async::maybe_async]
impl<'a> Request for ReqwestRequest<'a> {
	type Response = reqwest::Response;
	type HeaderMap = reqwest::header::HeaderMap;

	async fn response(&self) -> Result<Self::Response, RspamdError> {
		let method = if self.endpoint.need_body {  reqwest::Method::POST } else { reqwest::Method::GET };

		let mut url = Url::from_str(self.client.config.base_url.as_str())
			.map_err(|e| RspamdError::HttpError(e.to_string()))?;
		url.set_path(self.endpoint.url);
		let mut req = self.client.inner.request(method, url);

		if let Some(ref password) = self.client.config.password {
			req = req.header("Password", password);
		}

		if self.endpoint.need_body {
			req = req.body(self.body.to_owned());
		}
		let req = req.build()?;
		let response = self.client.inner.execute(req).await
			.map_err(|e| RspamdError::HttpError(e.to_string()))?;

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
		let body_vec = response.bytes().await?;
		Ok(ResponseData::new(body_vec, status_code, response_headers))
	}

	async fn response_header(&self) -> Result<(Self::HeaderMap, u16), RspamdError> {
		let response = self.response().await?;
		let status_code = response.status().as_u16();
		let headers = response.headers().clone();
		Ok((headers, status_code))
	}
}


impl<'a> ReqwestRequest<'a> {
	pub async fn new(
		client: AsyncClient<'a>,
		body: &'a str,
		command: RspamdCommand,
	) -> Result<ReqwestRequest<'a>, RspamdError> {
		Ok(Self {
			endpoint: RspamdEndpoint::from_command(command),
			client,
			body,
		})
	}
}