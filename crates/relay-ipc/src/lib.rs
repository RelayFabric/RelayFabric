//! RelayFabric Plugin Protocol v1: 4-byte big-endian length prefix + CBOR body
//! over a Unix domain socket (spec §9). Language-neutral by construction.

use chrono::{DateTime, Utc};
use relay_core::Capabilities;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcAttachment {
    pub filename: String,
    pub mime: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PluginToDaemon {
    Hello {
        plugin: String,
        version: String,
        protocol_version: u32,
        capabilities: Capabilities,
    },
    Inbound {
        endpoint: String,
        sender: String,
        kind: String,
        body: String,
        created_at: Option<DateTime<Utc>>,
        #[serde(default)]
        attachments: Vec<IpcAttachment>,
        // additive (spec §39): kept last so the canonical CBOR encoding of
        // every pre-existing Inbound field is unchanged; only appends one
        // trailing map entry. A plugin that doesn't send it (older plugin,
        // or a class the daemon doesn't recognize) normalizes to "normal"
        // via relay_core::priority_rank, same as any other unknown value.
        #[serde(default)]
        priority: Option<String>,
    },
    DeliveryResult {
        corr: i64,
        delivered: bool,
        detail: Option<String>,
    },
    // additive (design §3, cycle D): kept LAST so the canonical CBOR
    // encoding of every pre-existing PluginToDaemon variant is unchanged —
    // both golden-byte tests below stay byte-identical. Best-effort,
    // rate-limited (plugin-side) gauge snapshot (e.g. RSSI/SNR, queue
    // depth); a plugin that never sends it changes nothing for the daemon
    // (unknown-t tolerance already covers older plugins on the daemon side,
    // and older daemons ignore this the same way).
    Gauges {
        gauges: BTreeMap<String, f64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DaemonToPlugin {
    HelloAck {
        protocol_version: u32,
        error: Option<String>,
    },
    Send {
        corr: i64,
        endpoint: String,
        kind: String,
        body: String,
        #[serde(default)]
        attachments: Vec<IpcAttachment>,
    },
    Shutdown,
    // additive (design §IPC, cycle C): kept last so the canonical CBOR
    // encoding of every pre-existing DaemonToPlugin variant is unchanged.
    // Sent to direct-capable plugins (capabilities.direct_messages) to
    // deliver a single message to a native destination ref, outside any
    // channel/endpoint mapping (used by identity-link challenge delivery).
    SendDirect {
        corr: i64,
        native_ref: String,
        body: String,
    },
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> io::Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body).map_err(io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame exceeds MAX_FRAME"));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr);
    if len > MAX_FRAME {
        return Err(io::Error::other("frame exceeds MAX_FRAME"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    ciborium::from_reader(body.as_slice()).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_core::Capabilities;

    #[tokio::test]
    async fn roundtrips_a_frame() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = PluginToDaemon::Hello {
            plugin: "mqtt".into(),
            version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities::default(),
        };
        write_frame(&mut a, &msg).await.unwrap();
        let got: PluginToDaemon = read_frame(&mut b).await.unwrap();
        match got {
            PluginToDaemon::Hello {
                plugin,
                protocol_version,
                ..
            } => {
                assert_eq!(plugin, "mqtt");
                assert_eq!(protocol_version, 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_oversize_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // hand-write a header claiming a frame larger than MAX_FRAME
        use tokio::io::AsyncWriteExt;
        a.write_all(&(MAX_FRAME + 1).to_be_bytes()).await.unwrap();
        let got: std::io::Result<PluginToDaemon> = read_frame(&mut b).await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn write_frame_rejects_oversize_message() {
        // Symmetric guard: write_frame must refuse to emit a frame whose
        // encoded body exceeds MAX_FRAME, the same way read_frame refuses to
        // accept one (rejects_oversize_frame above).
        let mut buf = Vec::new();
        let msg = PluginToDaemon::Inbound {
            endpoint: "chan".into(),
            sender: "s".into(),
            kind: "text".into(),
            body: String::new(),
            created_at: None,
            attachments: vec![IpcAttachment {
                filename: "big.bin".into(),
                mime: "application/octet-stream".into(),
                data: vec![0u8; MAX_FRAME as usize + 1],
            }],
            priority: None,
        };
        let got = write_frame(&mut buf, &msg).await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn corr_survives_send_result_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(
            &mut a,
            &DaemonToPlugin::Send {
                corr: 42,
                endpoint: "chan".into(),
                kind: "text".into(),
                body: "hi".into(),
                attachments: vec![],
            },
        )
        .await
        .unwrap();
        let DaemonToPlugin::Send { corr, .. } = read_frame(&mut b).await.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(corr, 42);
    }

    #[tokio::test]
    async fn canonical_hello_frame_bytes_are_stable() {
        let mut buf = Vec::new();
        let msg = PluginToDaemon::Hello {
            plugin: "lxmf".into(),
            version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities {
                direct_messages: true,
                groups: true,
                ..Capabilities::default()
            },
        };
        write_frame(&mut buf, &msg).await.unwrap();
        // Wire-format lock: Python plugins reproduce these exact bytes
        // (test_relay_ipc.py). If this assertion ever fails, the plugin
        // protocol changed — that is a breaking protocol event, not a test fix.
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "000000a5a561746568656c6c6f66706c7567696e646c786d666776657273696f6e65302e312e307070726f746f636f6c5f76657273696f6e016c6361706162696c6974696573a96474657874f56f6469726563745f6d65737361676573f56667726f757073f56b6174746163686d656e7473f4686c6f636174696f6ef4697265616374696f6e73f4687265636569707473f46870726573656e6365f46b6d61785f7061796c6f6164f6");
    }

    #[tokio::test]
    async fn canonical_inbound_attachment_frame_bytes_are_stable() {
        let mut buf = Vec::new();
        let msg = PluginToDaemon::Inbound {
            endpoint: "chan".into(),
            sender: "s".into(),
            kind: "text".into(),
            body: "hi".into(),
            created_at: None,
            attachments: vec![IpcAttachment {
                filename: "a.bin".into(),
                mime: "application/octet-stream".into(),
                data: vec![1, 2, 3],
            }],
            priority: None,
        };
        write_frame(&mut buf, &msg).await.unwrap();
        // Wire-format lock: Python plugins reproduce these exact bytes
        // (test_relay_ipc.py). If this assertion ever fails, the plugin
        // protocol changed — that is a breaking protocol event, not a test fix.
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0000008fa8617467696e626f756e6468656e64706f696e74646368616e6673656e6465726173646b696e64647465787464626f64796268696a637265617465645f6174f66b6174746163686d656e747381a36866696c656e616d6565612e62696e646d696d6578186170706c69636174696f6e2f6f637465742d73747265616d646461746143010203687072696f72697479f6");
    }

    #[tokio::test]
    async fn send_direct_frame_roundtrips() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(
            &mut a,
            &DaemonToPlugin::SendDirect {
                corr: 99,
                native_ref: "a91d00aa".into(),
                body: "verification code".into(),
            },
        )
        .await
        .unwrap();
        let DaemonToPlugin::SendDirect {
            corr,
            native_ref,
            body,
        } = read_frame(&mut b).await.unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(corr, 99);
        assert_eq!(native_ref, "a91d00aa");
        assert_eq!(body, "verification code");
    }

    #[tokio::test]
    async fn priority_field_roundtrips_and_defaults_to_none() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = PluginToDaemon::Inbound {
            endpoint: "chan".into(),
            sender: "s".into(),
            kind: "text".into(),
            body: "hi".into(),
            created_at: None,
            attachments: vec![],
            priority: Some("emergency".into()),
        };
        write_frame(&mut a, &msg).await.unwrap();
        let PluginToDaemon::Inbound { priority, .. } = read_frame(&mut b).await.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(priority.as_deref(), Some("emergency"));
    }

    #[tokio::test]
    async fn gauges_frame_roundtrips() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let mut gauges = BTreeMap::new();
        gauges.insert("rssi".to_string(), -71.5);
        gauges.insert("queue_depth".to_string(), 3.0);
        write_frame(
            &mut a,
            &PluginToDaemon::Gauges {
                gauges: gauges.clone(),
            },
        )
        .await
        .unwrap();
        let PluginToDaemon::Gauges { gauges: got } = read_frame(&mut b).await.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(got, gauges);
    }
}
