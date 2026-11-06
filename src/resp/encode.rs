//! RESP encoder.
//!
//! Every reply the honeypot emits is built here, so this is the one place that
//! must never let attacker influenced bytes break the framing: simple strings
//! and errors are CR/LF scrubbed, and bulk payloads are length prefixed.

use super::RespFrame;

/// Append `frame` to `out`.
///
/// `resp3` selects RESP3 spellings for `Null` (`_`) and `Map` (`%`); with
/// `resp3 == false` a map degrades to a flat array, which is what a RESP2
/// client that sent a stray `HELLO` expects.
pub fn encode_frame(frame: &RespFrame, resp3: bool, out: &mut Vec<u8>) {
    match frame {
        RespFrame::Simple(bytes) => {
            out.push(b'+');
            push_line_safe(out, bytes);
            out.extend_from_slice(b"\r\n");
        }
        RespFrame::Error(bytes) => {
            out.push(b'-');
            push_line_safe(out, bytes);
            out.extend_from_slice(b"\r\n");
        }
        RespFrame::Integer(value) => {
            out.push(b':');
            out.extend_from_slice(value.to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        RespFrame::Bulk(bytes) => {
            out.push(b'$');
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(bytes);
            out.extend_from_slice(b"\r\n");
        }
        RespFrame::Null => {
            if resp3 {
                out.extend_from_slice(b"_\r\n");
            } else {
                out.extend_from_slice(b"$-1\r\n");
            }
        }
        RespFrame::Array(items) => {
            out.push(b'*');
            out.extend_from_slice(items.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            for item in items {
                encode_frame(item, resp3, out);
            }
        }
        RespFrame::Map(pairs) => {
            if resp3 {
                out.push(b'%');
                out.extend_from_slice(pairs.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                for (key, value) in pairs {
                    encode_frame(key, resp3, out);
                    encode_frame(value, resp3, out);
                }
            } else {
                out.push(b'*');
                out.extend_from_slice((pairs.len() * 2).to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                for (key, value) in pairs {
                    encode_frame(key, resp3, out);
                    encode_frame(value, resp3, out);
                }
            }
        }
    }
}

/// Same as [`encode_frame`] but returns a fresh buffer.
pub fn encode_frame_vec(frame: &RespFrame, resp3: bool) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(frame, resp3, &mut out);
    out
}

/// Copy `bytes` into `out`, replacing CR, LF and NUL with a space.
///
/// Simple strings and errors are line terminated, so an embedded CR/LF coming
/// from a simulated command would let an attacker splice their own reply. It
/// cannot come from our side, but scrubbing is one `match` and removes the
/// whole class.
fn push_line_safe(out: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'\r' | b'\n' | 0x00 => out.push(b' '),
            _ => out.push(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(frame: &RespFrame, resp3: bool) -> &'static [u8] {
        // Leak in a test only; keeps assertions readable.
        Box::leak(encode_frame_vec(frame, resp3).into_boxed_slice())
    }

    #[test]
    fn encodes_each_type_in_resp2() {
        assert_eq!(enc(&RespFrame::ok(), false), b"+OK\r\n");
        assert_eq!(enc(&RespFrame::error("ERR bad"), false), b"-ERR bad\r\n");
        assert_eq!(enc(&RespFrame::int(42), false), b":42\r\n");
        assert_eq!(enc(&RespFrame::int(-7), false), b":-7\r\n");
        assert_eq!(enc(&RespFrame::bulk(b"x"), false), b"$1\r\nx\r\n");
        assert_eq!(enc(&RespFrame::bulk(Vec::new()), false), b"$0\r\n\r\n");
        assert_eq!(enc(&RespFrame::null(), false), b"$-1\r\n");
        assert_eq!(
            enc(
                &RespFrame::array(vec![RespFrame::bulk(b"a"), RespFrame::int(1)]),
                false
            ),
            b"*2\r\n$1\r\na\r\n:1\r\n"
        );
    }

    #[test]
    fn encodes_resp3_variants() {
        assert_eq!(enc(&RespFrame::null(), true), b"_\r\n");
        let map = RespFrame::Map(vec![(
            RespFrame::bulk(b"server"),
            RespFrame::bulk(b"redis"),
        )]);
        assert_eq!(enc(&map, true), b"%1\r\n$6\r\nserver\r\n$5\r\nredis\r\n");
        // RESP2 flattening of the same map
        assert_eq!(enc(&map, false), b"*2\r\n$6\r\nserver\r\n$5\r\nredis\r\n");
    }

    #[test]
    fn bulk_strings_are_binary_safe() {
        let payload = vec![0u8, 1, 2, 255, b'\r', b'\n'];
        let encoded = encode_frame_vec(&RespFrame::bulk(payload), false);
        assert_eq!(encoded, b"$6\r\n\x00\x01\x02\xff\r\n\r\n");
    }

    #[test]
    fn line_types_scrub_crlf_injection() {
        let injected = RespFrame::Simple(b"OK\r\n+INJECTED".to_vec());
        assert_eq!(encode_frame_vec(&injected, false), b"+OK  +INJECTED\r\n");
        let injected_err = RespFrame::Error(b"ERR X\nY".to_vec());
        assert_eq!(encode_frame_vec(&injected_err, false), b"-ERR X Y\r\n");
    }

    #[test]
    fn nested_arrays_encode_recursively() {
        let nested = RespFrame::Array(vec![RespFrame::Array(vec![RespFrame::bulk(b"x")])]);
        assert_eq!(encode_frame_vec(&nested, false), b"*1\r\n*1\r\n$1\r\nx\r\n");
    }
}
