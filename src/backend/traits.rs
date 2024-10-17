
use std::collections::HashMap;
use bytes::Bytes;
use crate::error::RspamdError;
#[cfg(feature = "async")]
use std::pin::Pin;
#[cfg(feature = "async")]
use tokio_stream::Stream;

#[cfg(feature = "async")]
pub type StreamItem = Result<Bytes, RspamdError>;

#[cfg(feature = "async")]
pub type DataStream = Pin<Box<dyn Stream<Item = StreamItem> + Send>>;
#[cfg(feature = "async")]
pub struct ResponseDataStream {
	pub bytes: DataStream,
	pub status_code: u16,
}

/// Raw response data
#[derive(Debug)]
pub struct ResponseData {
	bytes: Bytes,
	status_code: u16,
	headers: HashMap<String, String>,
}

#[cfg(feature = "async")]
impl ResponseDataStream {
	pub fn bytes(&mut self) -> &mut DataStream {
		&mut self.bytes
	}
}

impl From<ResponseData> for Vec<u8> {
	fn from(data: ResponseData) -> Vec<u8> {
		data.to_vec()
	}
}

impl ResponseData {
	pub fn new(bytes: Bytes, status_code: u16, headers: HashMap<String, String>) -> ResponseData {
		ResponseData {
			bytes,
			status_code,
			headers,
		}
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.bytes
	}

	pub fn to_vec(self) -> Vec<u8> {
		self.bytes.to_vec()
	}

	pub fn bytes(&self) -> &Bytes {
		&self.bytes
	}

	pub fn bytes_mut(&mut self) -> &mut Bytes {
		&mut self.bytes
	}

	pub fn into_bytes(self) -> Bytes {
		self.bytes
	}

	pub fn status_code(&self) -> u16 {
		self.status_code
	}

	pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
		std::str::from_utf8(self.as_slice())
	}

	pub fn to_string(&self) -> Result<String, std::str::Utf8Error> {
		std::str::from_utf8(self.as_slice()).map(|s| s.to_string())
	}

	pub fn headers(&self) -> HashMap<String, String> {
		self.headers.clone()
	}
}

use std::fmt;

impl fmt::Display for ResponseData {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"Status code: {}\n Data: {}",
			self.status_code(),
			self.to_string()
				.unwrap_or_else(|_| "Data could not be cast to UTF string".to_string())
		)
	}
}

/// Represents a request to the Rspamd server
#[maybe_async::maybe_async]
pub trait Request {
	type Response;
	type HeaderMap;

	async fn response(&self) -> Result<Self::Response, RspamdError>;
	async fn response_data(&self) -> Result<ResponseData, RspamdError>;
	async fn response_header(&self) -> Result<(Self::HeaderMap, u16), RspamdError>;

}
