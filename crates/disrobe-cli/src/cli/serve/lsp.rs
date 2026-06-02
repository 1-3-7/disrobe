use super::SERVE_VERSION;
use super::util::{decode_base64, hex32, normalize_dr_code};

pub(super) fn run_stdio_lsp() -> miette::Result<()> {
    use lsp_server::{Connection, Message as LspMessage, Response};
    use lsp_types::{ServerCapabilities, ServerInfo};

    let (connection, io_threads): (Connection, lsp_server::IoThreads) = Connection::stdio();
    let server_caps: ServerCapabilities = ServerCapabilities::default();
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
