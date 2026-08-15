//! RelayFabric Plugin Protocol v1: 4-byte big-endian length prefix + CBOR body
//! over a Unix domain socket (spec §9). Language-neutral by construction.

use chrono::{DateTime, Utc};
use relay_core::Capabilities;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

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
    },
    DeliveryResult {
        corr: i64,
        delivered: bool,
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DaemonToPlugin {
    HelloAck { protocol_version: u32, error: Option<String> },
    Send { corr: i64, endpoint: String, kind: String, body: String },
    Shutdown,
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

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
) -> io::Result<T> {
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
            PluginToDaemon::Hello { plugin, protocol_version, .. } => {
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
    async fn corr_survives_send_result_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, &DaemonToPlugin::Send {
            corr: 42, endpoint: "chan".into(), kind: "text".into(), body: "hi".into(),
        }).await.unwrap();
        let DaemonToPlugin::Send { corr, .. } = read_frame(&mut b).await.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(corr, 42);
    }
}
