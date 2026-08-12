//! Length-prefixed protocol shared by the runtime, SSH transport, and Python agent.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAGIC: &[u8; 4] = b"SCX1";
pub const MAX_HEADER: usize = 8 * 1024 * 1024;
pub const MAX_PAYLOAD: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Request {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Response {
    pub id: String,
    pub ok: bool,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Frame<T> {
    pub header: T,
    pub payload: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid frame magic")]
    Magic,
    #[error("frame header exceeds {MAX_HEADER} bytes")]
    HeaderTooLarge,
    #[error("frame payload exceeds {MAX_PAYLOAD} bytes")]
    PayloadTooLarge,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON header: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn write_frame<W, T>(writer: &mut W, frame: &Frame<T>) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let header = serde_json::to_vec(&frame.header)?;
    if header.len() > MAX_HEADER {
        return Err(ProtocolError::HeaderTooLarge);
    }
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge);
    }
    writer.write_all(MAGIC).await?;
    writer.write_u32(header.len() as u32).await?;
    writer.write_u64(frame.payload.len() as u64).await?;
    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<Frame<T>, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        return Err(ProtocolError::Magic);
    }
    let header_len = reader.read_u32().await? as usize;
    let payload_len = reader.read_u64().await? as usize;
    if header_len > MAX_HEADER {
        return Err(ProtocolError::HeaderTooLarge);
    }
    if payload_len > MAX_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let mut header = vec![0; header_len];
    reader.read_exact(&mut header).await?;
    let mut payload = vec![0; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok(Frame {
        header: serde_json::from_slice(&header)?,
        payload: Bytes::from(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn round_trips_binary_payload() {
        let request = Request {
            id: "7".into(),
            method: "write".into(),
            params: serde_json::json!({"path":"/tmp/x"}),
            readonly: false,
        };
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let expected = Frame {
            header: request.clone(),
            payload: Bytes::from_static(&[0, 255, 10, 13]),
        };
        write_frame(&mut tx, &expected).await.unwrap();
        let actual: Frame<Request> = read_frame(&mut rx).await.unwrap();
        assert_eq!(actual, expected);
    }
}
