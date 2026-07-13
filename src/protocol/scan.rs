use crate::error::RspamdError;
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
    /// Rewritten message body (only present when body_block flag is set and message was rewritten)
    /// This field is not part of the JSON response but is extracted from the response body
    #[serde(skip)]
    pub rewritten_body: Option<Vec<u8>>,
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

/// Reply for controller commands (learn spam/ham, fuzzy add/del)
#[derive(Debug, Serialize, Deserialize)]
pub struct RspamdLearnReply {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// Parse a scan reply body, honouring the `Message-Offset` header used by the
/// `body_block` feature: when present and in bounds, the body carries JSON up
/// to the offset followed by the rewritten message.
pub fn parse_scan_reply(
    message_offset: Option<&str>,
    body: &[u8],
) -> Result<RspamdScanReply, RspamdError> {
    if let Some(offset_str) = message_offset {
        let offset = offset_str
            .parse::<usize>()
            .map_err(|e| RspamdError::HttpError(format!("Invalid Message-Offset value: {}", e)))?;

        if offset < body.len() {
            // Split body into JSON part and rewritten body part
            let mut response = serde_json::from_slice::<RspamdScanReply>(&body[..offset])?;
            response.rewritten_body = Some(body[offset..].to_vec());
            return Ok(response);
        }
        // Offset is out of bounds, parse entire body as JSON
    }
    Ok(serde_json::from_slice::<RspamdScanReply>(body)?)
}
