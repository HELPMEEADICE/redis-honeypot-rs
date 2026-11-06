//! Minimal RESP2 codec with the RESP3 bits real clients actually need.
//!
//! The decoder is hand written on purpose: a full Redis client/server crate is
//! an enormous amount of code that runs *in front of* attacker input, and every
//! line of it is attack surface. This module is small enough to audit.

pub mod encode;
pub mod parser;

pub use encode::{encode_frame, encode_frame_vec};
pub use parser::{ParseOutcome, ProtocolError, RespDecoder};

/// A decoded RESP value, or a value to be encoded.
///
/// `Map` is RESP3 only; [`encode_frame`] flattens it into a RESP2 array when the
/// peer negotiated protocol 2, which is what `HELLO 3` handling needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespFrame {
    /// `+...`
    Simple(Vec<u8>),
    /// `-...`
    Error(Vec<u8>),
    /// `:...`
    Integer(i64),
    /// `$...`
    Bulk(Vec<u8>),
    /// `$-1` in RESP2, `_` in RESP3.
    Null,
    /// `*...`
    Array(Vec<RespFrame>),
    /// `%...` in RESP3, flattened to an array in RESP2.
    Map(Vec<(RespFrame, RespFrame)>),
}

impl RespFrame {
    pub fn simple(s: &str) -> Self {
        Self::Simple(s.as_bytes().to_vec())
    }

    pub fn error(s: &str) -> Self {
        Self::Error(s.as_bytes().to_vec())
    }

    pub fn bulk(bytes: impl AsRef<[u8]>) -> Self {
        Self::Bulk(bytes.as_ref().to_vec())
    }

    pub fn bulk_str(s: &str) -> Self {
        Self::Bulk(s.as_bytes().to_vec())
    }

    pub fn int(v: i64) -> Self {
        Self::Integer(v)
    }

    pub fn array(items: Vec<RespFrame>) -> Self {
        Self::Array(items)
    }

    pub fn null() -> Self {
        Self::Null
    }

    /// The canonical `+OK`.
    pub fn ok() -> Self {
        Self::Simple(b"OK".to_vec())
    }

    /// Cheap tag used to label the RESP type in `commands.resp_type`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Simple(_) => "simple_string",
            Self::Error(_) => "error",
            Self::Integer(_) => "integer",
            Self::Bulk(_) => "bulk_string",
            Self::Null => "null",
            Self::Array(_) => "array",
            Self::Map(_) => "map",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_then_encode_round_trips_a_pipeline() {
        let wire: &[u8] = b"*2\r\n$3\r\nGET\r\n$4\r\nkey\x00\r\n+OK\r\n:12\r\n$-1\r\n";
        let mut decoder = RespDecoder::from_limits(&crate::config::Limits::default());
        decoder
            .extend(wire)
            .expect("message fits the default limits");

        let mut out = Vec::new();
        let mut frames = 0;
        while let Some(frame) = decoder.try_decode().expect("well formed stream") {
            frames += 1;
            encode_frame(&frame, false, &mut out);
        }
        assert_eq!(frames, 4);
        assert!(decoder.is_empty());
        assert_eq!(
            out, wire,
            "every decodable frame re-encodes to the bytes it came from"
        );
    }

    #[test]
    fn constructors_build_expected_frames() {
        assert_eq!(RespFrame::ok(), RespFrame::Simple(b"OK".to_vec()));
        assert_eq!(
            RespFrame::simple("PONG"),
            RespFrame::Simple(b"PONG".to_vec())
        );
        assert_eq!(RespFrame::int(-1), RespFrame::Integer(-1));
        assert_eq!(RespFrame::bulk(b"\x00\xff").type_name(), "bulk_string");
        assert_eq!(RespFrame::null().type_name(), "null");
        assert_eq!(
            RespFrame::array(vec![RespFrame::int(1)]).type_name(),
            "array"
        );
    }
}
