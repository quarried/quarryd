use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HEADER_BYTES: usize = 4;

/// Largest frame body accepted from the guest.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Largest frame body accepted from the host; larger because [`crate::Configure`] carries secrets.
pub const MAX_HOST_FRAME_BYTES: usize = 1024 * 1024;

/// Error reading or writing a length-prefixed frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError
{
    /// The frame length exceeds the limit; the body was not read.
    #[error("frame of {len} bytes exceeds the limit of {max} bytes")]
    TooLarge
    {
        /// Length announced in the header.
        len: usize,
        /// Limit in effect.
        max: usize,
    },
    /// The stream ended inside a frame.
    #[error("stream ended inside a frame")]
    Truncated,
    /// The underlying transport failed.
    #[error("transport error: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one frame: a 4-byte big-endian length followed by that many bytes.
///
/// Returns `Ok(None)` on end of stream at a frame boundary. A length above
/// `max` fails with [`FrameError::TooLarge`] before the body is read or allocated.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<Bytes>, FrameError>
{
    let mut header = [0u8; HEADER_BYTES];
    let mut filled = 0;
    while filled < HEADER_BYTES
    {
        let read = r.read(&mut header[filled..]).await?;
        if read == 0
        {
            if filled == 0
            {
                return Ok(None);
            }
            return Err(FrameError::Truncated);
        }
        filled += read;
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > max
    {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut body = BytesMut::zeroed(len);
    r.read_exact(&mut body)
        .await
        .map_err(|error| match error.kind()
        {
            std::io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            _ => FrameError::Io(error),
        })?;
    Ok(Some(body.freeze()))
}

/// Encodes `message` as one frame, writes it, and flushes the writer.
pub async fn write_message<W: AsyncWrite + Unpin, M: prost::Message>(
    w: &mut W,
    message: &M,
) -> Result<(), FrameError>
{
    let len = message.encoded_len();
    let header = u32::try_from(len).map_err(|_| FrameError::TooLarge {
        len,
        max: u32::MAX as usize,
    })?;
    let mut buffer = BytesMut::with_capacity(HEADER_BYTES + len);
    buffer.put_u32(header);
    message.encode_raw(&mut buffer);
    w.write_all(&buffer).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::{GuestBody, GuestMessage, Log};
    use prost::Message;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    struct HeaderOnly
    {
        header: [u8; 4],
        position: usize,
    }

    impl AsyncRead for HeaderOnly
    {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>>
        {
            assert!(self.position < 4, "body must not be read");
            let byte = self.header[self.position];
            self.position += 1;
            buf.put_slice(&[byte]);
            Poll::Ready(Ok(()))
        }
    }

    fn log_message(line: &str) -> GuestMessage
    {
        GuestMessage {
            body: Some(GuestBody::Log(Log {
                line: line.to_owned(),
            })),
        }
    }

    #[tokio::test]
    async fn frames_round_trip()
    {
        let mut wire = Vec::new();
        write_message(&mut wire, &log_message("one")).await.unwrap();
        write_message(&mut wire, &log_message("two")).await.unwrap();
        let mut reader = wire.as_slice();
        let first = read_frame(&mut reader, MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        let second = read_frame(&mut reader, MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(GuestMessage::decode(first).unwrap(), log_message("one"));
        assert_eq!(GuestMessage::decode(second).unwrap(), log_message("two"));
        assert!(
            read_frame(&mut reader, MAX_FRAME_BYTES)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn header_is_big_endian_length()
    {
        let mut wire = Vec::new();
        let message = log_message("abc");
        write_message(&mut wire, &message).await.unwrap();
        let len = message.encoded_len() as u32;
        assert_eq!(&wire[..4], &len.to_be_bytes());
        assert_eq!(wire.len(), 4 + len as usize);
    }

    #[tokio::test]
    async fn empty_frame_is_valid()
    {
        let mut reader: &[u8] = &[0, 0, 0, 0];
        let frame = read_frame(&mut reader, MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert!(frame.is_empty());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_reading_body()
    {
        let mut reader = HeaderOnly {
            header: u32::MAX.to_be_bytes(),
            position: 0,
        };
        let error = read_frame(&mut reader, MAX_FRAME_BYTES).await.unwrap_err();
        assert!(
            matches!(error, FrameError::TooLarge { len, max } if len == u32::MAX as usize && max == MAX_FRAME_BYTES)
        );
        assert_eq!(reader.position, 4);
    }

    #[tokio::test]
    async fn frame_at_limit_is_accepted_and_one_over_is_not()
    {
        let mut at_limit = (16u32).to_be_bytes().to_vec();
        at_limit.extend_from_slice(&[7u8; 16]);
        let mut reader = at_limit.as_slice();
        assert_eq!(
            read_frame(&mut reader, 16).await.unwrap().unwrap().len(),
            16
        );

        let mut reader = HeaderOnly {
            header: 17u32.to_be_bytes(),
            position: 0,
        };
        assert!(matches!(
            read_frame(&mut reader, 16).await,
            Err(FrameError::TooLarge { len: 17, max: 16 })
        ));
    }

    #[tokio::test]
    async fn truncated_header_is_an_error()
    {
        let mut reader: &[u8] = &[0, 0];
        assert!(matches!(
            read_frame(&mut reader, MAX_FRAME_BYTES).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn truncated_body_is_an_error()
    {
        let mut reader: &[u8] = &[0, 0, 0, 10, 1, 2, 3];
        assert!(matches!(
            read_frame(&mut reader, MAX_FRAME_BYTES).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn frames_survive_a_byte_at_a_time_transport()
    {
        let (mut client, mut server) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            write_message(&mut client, &log_message("slow"))
                .await
                .unwrap();
        });
        let frame = read_frame(&mut server, MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();
        assert_eq!(GuestMessage::decode(frame).unwrap(), log_message("slow"));
    }
}
