use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rspamd scan reply structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RspamdScanReply {
	/// If message has been skipped
	#[serde(default)]
	pub is_skipped: bool,
	/// Scan score
	#[serde(default)]
	pub score: f64,
	/// Required score (legacy)
	#[serde(default)]
	pub required_score: f64,
	/// Action to take
	#[serde(default)]
	pub action: String,
	/// Action thresholds
	#[serde(default)]
	pub thresholds: HashMap<String, f64>,
	/// Symbols detected
	#[serde(default)]
	pub symbols: HashMap<String, Symbol>,
	/// Messages
	#[serde(default)]
	pub messages: HashMap<String, String>,
	/// URLs
	#[serde(default)]
	pub urls: Vec<String>,
	/// Emails
	#[serde(default)]
	pub emails: Vec<String>,
	/// Message id
	#[serde(rename = "message-id", default)]
	pub message_id: String,
	/// Real time of scan
	#[serde(default)]
	pub time_real: f64,
	/// Milter actions block
	#[serde(default)]
	pub milter: Option<Milter>,
	#[serde(default)]
	/// Filename
	pub filename: String,
	#[serde(default)]
	pub scan_time: f64,
}

/// Symbol structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Symbol {
	#[serde(default)]
	pub name: String,
	#[serde(default)]
	pub score: f64,
	#[serde(default)]
	pub metric_score: f64,
	#[serde(default)]
	pub description: Option<String>,
	#[serde(default)]
	pub options: Option<Vec<String>>,
}

/// Milter actions block
#[derive(Debug, Serialize, Deserialize)]
pub struct Milter {
	#[serde(default)]
	pub add_headers: HashMap<String, MailHeader>,
	#[serde(default)]
	pub remove_headers: HashMap<String, i32>,
}

/// Milter header action
#[derive(Debug, Serialize, Deserialize)]
pub struct MailHeader {
	#[serde(default)]
	pub value: String,
	#[serde(default)]
	pub order: i32,
}
