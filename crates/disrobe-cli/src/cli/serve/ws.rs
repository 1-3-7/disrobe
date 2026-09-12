use std::sync::Arc;

use axum::extract::{
    State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::response::Response;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use super::handlers::ServerState;
use super::util::{decode_inline_bytes, hex32};

pub(super) async fn stream_ws(
    State(state): State<Arc<ServerState>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<ServerState>) {
    let cancel: CancellationToken = state.cancel.clone();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            recv = socket.recv() => match recv {
                Some(Ok(Message::Text(text))) => {
                    let parsed: Result<StreamRequest, _> = serde_json::from_str(text.as_str());
                    match parsed {
                        Ok(req) => stream_dispatch(&mut socket, req).await,
                        Err(e) => {
                            let err: serde_json::Value = serde_json::json!({
                                "stage": "error",
                                "error_code": "DR-CLI-0189",
                                "message": format!("malformed StreamRequest: {e}"),
                            });
                            let _ = socket.send(Message::Text(err.to_string().into())).await;
                        }
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamRequest {
    op: String,
    bytes_b64: String,
}

async fn stream_dispatch(socket: &mut WebSocket, req: StreamRequest) {
    let bytes: Vec<u8> = match decode_inline_bytes(&req.bytes_b64) {
        Ok(b) => b,
        Err(api) => {
            let line: serde_json::Value = serde_json::json!({
                "stage": "error",
                "error_code": api.error_code,
                "message": api.message,
            });
            let _ = socket.send(Message::Text(line.to_string().into())).await;
            return;
        }
    };
    let line0: serde_json::Value = serde_json::json!({
        "stage": "received",
        "op": req.op,
        "bytes": bytes.len(),
        "blake3": hex32(blake3::hash(&bytes).as_bytes()),
    });
    if socket
        .send(Message::Text(line0.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    let classification: disrobe_binfmt::InputClassification =
        disrobe_binfmt::classify_input(std::path::Path::new("inline"), &bytes);
    let line1: serde_json::Value = serde_json::json!({
        "stage": "classified",
        "action": format!("{:?}", classification.primary_action),
        "reason": classification.reason,
    });
    if socket
        .send(Message::Text(line1.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    let line2: serde_json::Value = serde_json::json!({
        "stage": "completed",
        "op": req.op,
    });
    let _ = socket.send(Message::Text(line2.to_string().into())).await;
}
