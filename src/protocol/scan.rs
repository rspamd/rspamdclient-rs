use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct RspamdScanReply {
	#[serde(default)]
	pub is_skipped: bool,
	#[serde(default)]
	pub score: f64,
	#[serde(default)]
	pub required_score: f64,
	#[serde(default)]
	pub action: String,
	#[serde(default)]
	pub thresholds: HashMap<String, f64>,
	#[serde(default)]
	pub symbols: HashMap<String, Symbol>,
	#[serde(default)]
	pub messages: HashMap<String, String>,
	#[serde(default)]
	pub urls: Vec<String>,
	#[serde(default)]
	pub emails: Vec<String>,
	#[serde(rename = "message-id", default)]
	pub message_id: String,
	#[serde(default)]
	pub time_real: f64,
	#[serde(default)]
	pub milter: Option<Milter>,
	#[serde(default)]
	pub filename: String,
	#[serde(default)]
	pub scan_time: f64,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Milter {
	#[serde(default)]
	pub add_headers: HashMap<String, MailHeader>,
	#[serde(default)]
	pub remove_headers: HashMap<String, i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailHeader {
	#[serde(default)]
	pub value: String,
	#[serde(default)]
	pub order: i32,
}
