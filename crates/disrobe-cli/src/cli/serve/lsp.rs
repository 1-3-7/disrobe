use super::SERVE_VERSION;
use super::util::{decode_base64, hex32, normalize_dr_code};

pub(super) fn run_stdio_lsp() -> miette::Result<()> {
    use lsp_server::{Connection, Message as LspMessage, Response};
    use lsp_types::{ServerCapabilities, ServerInfo};

    let (connection, io_threads): (Connection, lsp_server::IoThreads) = Connection::stdio();
    let server_caps: ServerCapabilities = ServerCapabilities {
        experimental: Some(serde_json::json!({
            "disrobe": {
                "methods": ["disrobe/analyze", "disrobe/explain"],
                "transport": "lsp-framed stdio json-rpc",
                "note": "custom request methods; this server does not implement the standard textDocument LSP surface"
            }
        })),
        ..ServerCapabilities::default()
    };
    let init_value: serde_json::Value = serde_json::json!({
        "capabilities": server_caps,
        "serverInfo": ServerInfo {
            name: "disrobe-serve".to_owned(),
            version: Some(SERVE_VERSION.to_owned()),
        },
    });
    let _init_params: serde_json::Value = connection
        .initialize(init_value)
        .map_err(|e| miette::miette!("DR-CLI-0201: initialize failed: {e}"))?;

    while let Ok(msg) = connection.receiver.recv() {
        match msg {
            LspMessage::Request(req) => {
                if connection.handle_shutdown(&req).unwrap_or(false) {
                    break;
                }
                let response: Response = build_lsp_response(req);
                let _ = connection.sender.send(LspMessage::Response(response));
            }
            LspMessage::Notification(_) | LspMessage::Response(_) => {}
        }
    }
    io_threads
        .join()
        .map_err(|e| miette::miette!("DR-CLI-0203: io thread join: {e}"))?;
    Ok(())
}

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct LspAnalyzeParams {
    pub(super) bytes_b64: String,
    #[serde(default)]
    pub(super) label: Option<String>,
}

pub(super) fn build_lsp_response(req: lsp_server::Request) -> lsp_server::Response {
    use lsp_server::{ErrorCode, Response, ResponseError};
    match req.method.as_str() {
        "disrobe/analyze" => {
            let parsed: Result<LspAnalyzeParams, serde_json::Error> =
                serde_json::from_value::<LspAnalyzeParams>(req.params.clone());
            let parsed: LspAnalyzeParams = match parsed {
                Ok(p) => p,
                Err(e) => {
                    return Response {
                        id: req.id,
                        result: None,
                        error: Some(ResponseError {
                            code: ErrorCode::InvalidParams as i32,
                            message: format!(
                                "DR-CLI-0210: disrobe/analyze requires `bytes_b64` (string); \
                                 path-based reads are not supported over LSP-stdio: {e}"
                            ),
                            data: None,
                        }),
                    };
                }
            };
            let bytes: Vec<u8> = match decode_base64(&parsed.bytes_b64) {
                Ok(b) if !b.is_empty() => b,
                Ok(_) => {
                    return Response {
                        id: req.id,
                        result: None,
                        error: Some(ResponseError {
                            code: ErrorCode::InvalidParams as i32,
                            message: "DR-CLI-0211: `bytes_b64` decoded to empty payload".to_owned(),
                            data: None,
                        }),
                    };
                }
                Err(e) => {
                    return Response {
                        id: req.id,
                        result: None,
                        error: Some(ResponseError {
                            code: ErrorCode::InvalidParams as i32,
                            message: format!("DR-CLI-0212: `bytes_b64` decode failed: {e}"),
                            data: None,
                        }),
                    };
                }
            };
            let label: String = parsed.label.unwrap_or_else(|| "<inline>".to_owned());
            let cl: disrobe_binfmt::InputClassification =
                disrobe_binfmt::classify_input(std::path::Path::new(&label), &bytes);
            let response: serde_json::Value = serde_json::json!({
                "label": label,
                "bytes": bytes.len(),
                "action": format!("{:?}", cl.primary_action),
                "reason": cl.reason,
                "blake3": hex32(blake3::hash(&bytes).as_bytes()),
            });
            Response {
                id: req.id,
                result: Some(response),
                error: None,
            }
        }
        "disrobe/explain" => {
            let code: String = req
                .params
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let normalized: String = normalize_dr_code(&code);
            let response: serde_json::Value = crate::cli::explain::lookup_for_serve(&normalized)
                .map_or_else(
                    || serde_json::json!({ "code": normalized.clone(), "known": false }),
                    |entry| {
                        serde_json::json!({
                            "code": normalized.clone(),
                            "known": true,
                            "title": entry.title,
                            "description": entry.description,
                            "crate_path": entry.crate_path,
                        })
                    },
                );
            Response {
                id: req.id,
                result: Some(response),
                error: None,
            }
        }
        other => Response {
            id: req.id,
            result: None,
            error: Some(ResponseError {
                code: ErrorCode::MethodNotFound as i32,
                message: format!("disrobe LSP: unsupported method `{other}`"),
                data: None,
            }),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use lsp_server::{Request, RequestId};

    use super::*;

    fn request(method: &str, params: serde_json::Value) -> Request {
        Request {
            id: RequestId::from(1),
            method: method.to_owned(),
            params,
        }
    }

    #[test]
    fn lsp_advertises_custom_disrobe_methods_in_experimental_capabilities() {
        let caps: lsp_types::ServerCapabilities = lsp_types::ServerCapabilities {
            experimental: Some(serde_json::json!({
                "disrobe": {
                    "methods": ["disrobe/analyze", "disrobe/explain"],
                    "transport": "lsp-framed stdio json-rpc",
                    "note": "custom request methods; this server does not implement the standard textDocument LSP surface"
                }
            })),
            ..lsp_types::ServerCapabilities::default()
        };
        let methods: &Vec<serde_json::Value> = caps
            .experimental
            .as_ref()
            .and_then(|v: &serde_json::Value| v.pointer("/disrobe/methods"))
            .and_then(serde_json::Value::as_array)
            .expect("experimental.disrobe.methods must be advertised");
        assert!(
            methods
                .iter()
                .any(|m: &serde_json::Value| m == "disrobe/analyze")
        );
    }

    #[test]
    fn analyze_method_returns_correct_classification() {
        let mut payload: Vec<u8> = vec![0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0u8; 12]);
        let b64: String = BASE64_STANDARD.encode(&payload);

        let expected: disrobe_binfmt::InputClassification =
            disrobe_binfmt::classify_input(std::path::Path::new("module.wasm"), &payload);
        let expected_action: String = format!("{:?}", expected.primary_action);
        let expected_hash: String = hex32(blake3::hash(&payload).as_bytes());

        let resp: lsp_server::Response = build_lsp_response(request(
            "disrobe/analyze",
            serde_json::json!({ "bytes_b64": b64, "label": "module.wasm" }),
        ));
        assert!(
            resp.error.is_none(),
            "analyze must succeed: {:?}",
            resp.error
        );
        let result: serde_json::Value = resp.result.expect("analyze result");
        assert_eq!(result["bytes"].as_u64(), Some(payload.len() as u64));
        assert_eq!(result["blake3"].as_str(), Some(expected_hash.as_str()));
        assert_eq!(result["action"].as_str(), Some(expected_action.as_str()));
        assert_ne!(result["action"].as_str(), Some("Unknown"));
    }

    #[test]
    fn analyze_method_rejects_empty_and_bad_base64() {
        let empty: lsp_server::Response = build_lsp_response(request(
            "disrobe/analyze",
            serde_json::json!({ "bytes_b64": "" }),
        ));
        assert!(
            empty
                .error
                .is_some_and(|e: lsp_server::ResponseError| e.message.contains("DR-CLI-0211"))
        );

        let bad: lsp_server::Response = build_lsp_response(request(
            "disrobe/analyze",
            serde_json::json!({ "bytes_b64": "@@@@" }),
        ));
        assert!(
            bad.error
                .is_some_and(|e: lsp_server::ResponseError| e.message.contains("DR-CLI-0212"))
        );
    }

    #[test]
    fn explain_method_looks_up_a_real_error_code() {
        let resp: lsp_server::Response = build_lsp_response(request(
            "disrobe/explain",
            serde_json::json!({ "code": "DR-CLI-0001" }),
        ));
        assert!(resp.error.is_none());
        let result: serde_json::Value = resp.result.expect("explain result");
        assert_eq!(result["code"].as_str(), Some("DR-CLI-0001"));
        assert_eq!(
            result["known"].as_bool(),
            Some(true),
            "DR-CLI-0001 is a registered code and must resolve to known=true"
        );
        assert!(
            result["title"]
                .as_str()
                .is_some_and(|t: &str| !t.is_empty()),
            "a known code must carry a non-empty title"
        );
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let resp: lsp_server::Response =
            build_lsp_response(request("textDocument/hover", serde_json::json!({})));
        let err: lsp_server::ResponseError = resp.error.expect("unknown method must error");
        assert_eq!(err.code, lsp_server::ErrorCode::MethodNotFound as i32);
    }
}
