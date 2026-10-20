//! Turn an HTTP response body into MCP tool content.
//!
//! A generic HTTP tool (`whatsapp__api-call` calling WAHA
//! `GET /api/files/<session>/<id>.jpeg`, and the same shape anywhere else)
//! used to run every body through a UTF-8 decode. JPEG bytes are not UTF-8,
//! so the string came back full of U+FFFD and the image was gone.
//!
//! Text and JSON stay a decoded string. The caller parses that string the
//! way it always has (JSON-RPC, SSE). `image/*` becomes an image block
//! (`mimeType` + base64 `data`). Every other non-text type becomes an
//! embedded resource whose `blob` is the same base64. Both shapes are the
//! ones the tool-result spec defines for inline bytes:
//! <https://modelcontextprotocol.io/specification/2025-06-18/server/tools>

use base64::Engine as _;
use serde_json::{json, Value};

/// Media type with parameters stripped and lowercased.
/// `image/jpeg; charset=binary` and `Image/JPEG` are both `image/jpeg`.
pub(super) fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Text, JSON, and a missing type stay on the string path.
///
/// Missing is included on purpose: every MCP peer that answers JSON-RPC
/// without a `Content-Type` has always been parsed as text, and a binary
/// response from a real server names its type.
pub(super) fn is_textual_content_type(content_type: &str) -> bool {
    let mt = media_type(content_type);
    mt.is_empty() || mt.starts_with("text/") || mt == "application/json" || mt.ends_with("+json")
}

/// MCP `tools/call` result for a body that is not text.
///
/// `uri` is required on an embedded resource. It is the URL the bytes came
/// from, which is the only identifier this layer has.
pub(super) fn binary_tool_result(content_type: &str, body: &[u8], uri: &str) -> Value {
    let mime = media_type(content_type);
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    if mime.starts_with("image/") {
        json!({
            "content": [{
                "type": "image",
                "mimeType": mime,
                "data": encoded,
            }]
        })
    } else {
        json!({
            "content": [{
                "type": "resource",
                "resource": {
                    "uri": uri,
                    "mimeType": mime,
                    "blob": encoded,
                }
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const JPEG: &[u8] = include_bytes!("fixtures/waha-8x8.jpeg");

    fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn decode_data(result: &Value, field: &str) -> Vec<u8> {
        let b64 = result["content"][0][field].as_str().unwrap();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

    #[test]
    fn text_and_json_stay_textual() {
        for ct in [
            "",
            "text/plain",
            "text/plain; charset=utf-8",
            "text/html",
            "text/event-stream",
            "application/json",
            "application/json; charset=utf-8",
            "application/problem+json",
            "application/vnd.api+json",
        ] {
            assert!(
                is_textual_content_type(ct),
                "{ct} must stay on the string path"
            );
        }
    }

    #[test]
    fn images_and_other_binary_are_not_textual() {
        for ct in [
            "image/jpeg",
            "image/jpeg; charset=binary",
            "Image/PNG",
            "image/svg+xml",
            "application/pdf",
            "application/octet-stream",
            "application/zip",
            "audio/wav",
        ] {
            assert!(
                !is_textual_content_type(ct),
                "{ct} must not be decoded as text"
            );
        }
    }

    /// The bytes WAHA returns for `GET /api/files/avelino/<id>.jpeg`.
    /// The fixture is a real JPEG and is not valid UTF-8, which is the
    /// input that used to become U+FFFD.
    #[test]
    fn jpeg_round_trips_as_image_content() {
        assert!(
            String::from_utf8(JPEG.to_vec()).is_err(),
            "the fixture has to be the case the old decode corrupted"
        );
        assert!(String::from_utf8_lossy(JPEG).contains('\u{FFFD}'));

        let result = binary_tool_result("image/jpeg", JPEG, "http://waha/api/files/avelino/x.jpeg");
        let block = &result["content"][0];
        assert_eq!(block["type"], "image");
        assert_eq!(block["mimeType"], "image/jpeg");
        assert!(block.get("text").is_none());
        assert!(block.get("resource").is_none());

        let decoded = decode_data(&result, "data");
        assert_eq!(decoded, JPEG);
        assert_eq!(sha256(&decoded), sha256(JPEG));
        assert!(!serde_json::to_string(&result).unwrap().contains('\u{FFFD}'));
    }

    #[test]
    fn image_parameters_do_not_change_the_mime_type() {
        let result = binary_tool_result("image/jpeg; charset=binary", JPEG, "urn:test");
        assert_eq!(result["content"][0]["mimeType"], "image/jpeg");
        assert_eq!(decode_data(&result, "data"), JPEG);
    }

    /// SVG is `image/*` even though the payload is XML. It follows the
    /// image rule, not the `+json` / `text/` rule.
    #[test]
    fn svg_is_image_content() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"/>"#;
        let result = binary_tool_result("image/svg+xml", svg, "urn:test");
        assert_eq!(result["content"][0]["type"], "image");
        assert_eq!(result["content"][0]["mimeType"], "image/svg+xml");
        assert_eq!(decode_data(&result, "data"), svg);
    }

    #[test]
    fn other_binary_is_an_embedded_resource_blob() {
        // Invalid UTF-8 on purpose: a PDF or a zip has the same property.
        let bytes = [0x25, 0x50, 0x44, 0x46, 0xff, 0xfe, 0x00, 0x01];
        let uri = "https://waha.example/api/files/avelino/note.pdf";
        let result = binary_tool_result("application/pdf", &bytes, uri);
        let block = &result["content"][0];
        assert_eq!(block["type"], "resource");
        assert!(block.get("data").is_none());
        assert_eq!(block["resource"]["uri"], uri);
        assert_eq!(block["resource"]["mimeType"], "application/pdf");

        let b64 = block["resource"]["blob"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert_eq!(decoded, bytes);
        assert_eq!(sha256(&decoded), sha256(&bytes));
        assert!(!serde_json::to_string(&result).unwrap().contains('\u{FFFD}'));
    }

    /// Audio is not an image. The mapping asked for is image content for
    /// `image/*` and an embedded resource for every other binary type.
    #[test]
    fn audio_is_an_embedded_resource_not_an_audio_block() {
        let bytes = [0x52, 0x49, 0x46, 0x46, 0xff, 0x00];
        let result = binary_tool_result("audio/wav", &bytes, "urn:wav");
        let block = &result["content"][0];
        assert_eq!(block["type"], "resource");
        assert_ne!(block["type"], "audio");
        assert_eq!(block["resource"]["mimeType"], "audio/wav");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(block["resource"]["blob"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, bytes);
    }
}
