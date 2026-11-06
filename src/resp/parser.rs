//! Streaming, non-allocating-on-trust RESP decoder.
//!
//! ## Contract (implemented by the parser task, must not change)
//!
//! * [`RespDecoder::extend`] appends attacker bytes. It fails with
//!   [`ProtocolError::MessageTooLarge`] *before* the internal buffer can exceed
//!   `max_message_bytes`, so no untrusted length is ever used to reserve memory.
//! * [`RespDecoder::try_decode`] either returns `Ok(Some(frame))` and consumes
//!   exactly that frame from the buffer, `Ok(None)` and consumes nothing (an
//!   incomplete frame), or an error describing a malformed/oversized message.
//! * Arrays nested deeper than `max_depth`, arrays longer than `max_array_len`
//!   and bulk strings longer than `max_bulk_len` are rejected, not truncated.
//! * Inline commands (a line without a leading type byte, as typed by humans
//!   and by `nc`-style scanners) decode to an array of bulk strings.
//!
//! ## Implementation notes
//!
//! * Arrays are assembled with an explicit stack instead of recursion. Depth is
//!   bounded by `max_depth` so recursion would normally be safe, but a decoder
//!   built directly with a large depth would then let attacker input drive the
//!   thread stack; the explicit stack makes the deepest message cost heap only.
//! * [`ProtocolError::UnsupportedType`] is never returned. Every byte that is
//!   not one of `+ - : $ * _` starts an inline command, control bytes included;
//!   that fallback is total on its own, so a second "unsupported" path would
//!   only describe the same input twice. The variant is kept because callers
//!   map it to a client message.
//! * An error leaves the decoder unusable on purpose: the caller closes the
//!   connection rather than trying to resynchronise a stream whose framing is
//!   already known to be broken.

use crate::config::Limits;

use super::RespFrame;

/// Result of a decode attempt that is allowed to run out of data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseOutcome {
    /// A complete frame was appended to the decoder's output queue.
    Complete,
    /// More bytes are needed; nothing was consumed.
    Incomplete,
}

/// A malformed, oversized or unsupported message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// The buffered message exceeded `max_message_bytes`.
    MessageTooLarge,
    /// A bulk string declared more than `max_bulk_len` bytes.
    BulkTooLarge,
    /// An array declared more than `max_array_len` elements.
    ArrayTooLong,
    /// Nesting exceeded `max_depth`.
    DepthExceeded,
    /// Non-numeric, empty or negative length/integer where one is required.
    InvalidLength,
    /// A length prefix that does not fit in `i64` / an element count overflow.
    IntegerOverflow,
    /// Missing `\r\n` where the protocol requires it.
    InvalidTerminator,
    /// Unknown type byte.
    UnsupportedType(u8),
    /// A payload that decodes to zero arguments (e.g. an empty inline line).
    EmptyCommand,
}

impl ProtocolError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MessageTooLarge => "message_too_large",
            Self::BulkTooLarge => "bulk_too_large",
            Self::ArrayTooLong => "array_too_long",
            Self::DepthExceeded => "depth_exceeded",
            Self::InvalidLength => "invalid_length",
            Self::IntegerOverflow => "integer_overflow",
            Self::InvalidTerminator => "invalid_terminator",
            Self::UnsupportedType(_) => "unsupported_type",
            Self::EmptyCommand => "empty_command",
        }
    }

    /// True for resource-limit violations, which are reported differently from
    /// simple malformed junk.
    pub fn is_oversized(self) -> bool {
        matches!(
            self,
            Self::MessageTooLarge | Self::BulkTooLarge | Self::ArrayTooLong | Self::DepthExceeded
        )
    }

    /// The `-ERR ...` text handed back to the peer.
    pub fn client_message(self) -> &'static str {
        match self {
            Self::MessageTooLarge | Self::BulkTooLarge => "ERR Protocol error: invalid bulk length",
            Self::ArrayTooLong => "ERR Protocol error: invalid multibulk length",
            Self::DepthExceeded => "ERR Protocol error: nesting too deep",
            Self::IntegerOverflow | Self::InvalidLength => "ERR Protocol error: invalid length",
            Self::InvalidTerminator => "ERR Protocol error: expected CRLF",
            Self::UnsupportedType(_) => "ERR Protocol error: unsupported type byte",
            Self::EmptyCommand => "ERR Protocol error: empty command",
        }
    }
}

/// Incremental RESP decoder. Holds only the unparsed tail of the stream.
#[derive(Debug)]
pub struct RespDecoder {
    /// Bytes received but not yet decoded.
    buffer: Vec<u8>,
    /// Read cursor inside `buffer`; compacted on the next `extend`.
    consumed: usize,
    /// `buffer[consumed..consumed + line_scanned]` is known to contain neither
    /// `\r` nor `\n`. It lets an unterminated line be rescanned from where the
    /// previous attempt stopped, so a client dribbling a long line one byte at
    /// a time costs linear instead of quadratic time.
    line_scanned: usize,
    max_message_bytes: usize,
    max_bulk_len: usize,
    max_array_len: usize,
    max_depth: usize,
}

impl RespDecoder {
    pub fn new(
        max_message_bytes: usize,
        max_bulk_len: usize,
        max_array_len: usize,
        max_depth: usize,
    ) -> Self {
        Self {
            buffer: Vec::new(),
            consumed: 0,
            line_scanned: 0,
            max_message_bytes,
            max_bulk_len,
            max_array_len,
            max_depth,
        }
    }

    /// Build a decoder from the honeypot's configured limits.
    pub fn from_limits(limits: &Limits) -> Self {
        Self::new(
            limits.max_message_bytes,
            limits.max_bulk_len,
            limits.max_array_len,
            limits.max_depth,
        )
    }

    /// Append bytes read from the socket.
    pub fn extend(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        // Compact first so the cap is measured over live bytes only.
        if self.consumed > 0 {
            let len = self.buffer.len();
            if self.consumed >= len {
                self.buffer.clear();
            } else {
                self.buffer.copy_within(self.consumed.., 0);
                self.buffer.truncate(len - self.consumed);
            }
            self.consumed = 0;
            // `line_scanned` counts bytes after the cursor, so compaction leaves
            // it meaningful; clamp it so it can never point past the buffer.
            self.line_scanned = self.line_scanned.min(self.buffer.len());
        }
        // Checked before any growth: the buffer never exceeds `max_message_bytes`
        // and no length that came off the wire is used to reserve memory.
        let total = self
            .buffer
            .len()
            .checked_add(data.len())
            .ok_or(ProtocolError::MessageTooLarge)?;
        if total > self.max_message_bytes {
            return Err(ProtocolError::MessageTooLarge);
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Try to decode one frame.
    pub fn try_decode(&mut self) -> Result<Option<RespFrame>, ProtocolError> {
        if self.buffered() == 0 {
            return Ok(None);
        }
        let Some(tail) = self.buffer.get(self.consumed..) else {
            // Unreachable: the cursor never runs past the end of the buffer.
            return Ok(None);
        };
        let mut decode = Decode {
            buf: tail,
            pos: 0,
            line_scanned: self.line_scanned,
            max_message_bytes: self.max_message_bytes,
            max_bulk_len: self.max_bulk_len,
            max_array_len: self.max_array_len,
            max_depth: self.max_depth,
        };
        let outcome = decode.next_frame();
        self.line_scanned = decode.line_scanned;
        match outcome {
            Ok((frame, used)) => {
                // Every byte of `frame` is provably inside the buffer, so the
                // cursor can only move forward by at most `used`.
                self.consumed = self.consumed.saturating_add(used);
                self.line_scanned = 0;
                Ok(Some(frame))
            }
            Err(Fail::Incomplete) => Ok(None),
            Err(Fail::Protocol(error)) => Err(error),
        }
    }

    /// Bytes currently buffered and not yet decoded.
    pub fn buffered(&self) -> usize {
        self.buffer.len().saturating_sub(self.consumed)
    }

    /// True when there is nothing left to decode.
    pub fn is_empty(&self) -> bool {
        self.buffered() == 0
    }

    /// Drop everything buffered.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.consumed = 0;
        self.line_scanned = 0;
    }

    /// Configured caps, exposed for tests and diagnostics.
    pub fn caps(&self) -> (usize, usize, usize, usize) {
        (
            self.max_message_bytes,
            self.max_bulk_len,
            self.max_array_len,
            self.max_depth,
        )
    }
}

/// Internal control flow for a single decode attempt.
#[derive(Debug, Clone, Copy)]
enum Fail {
    /// The buffer ends inside a valid frame: consume nothing, wait for bytes.
    Incomplete,
    /// The stream is malformed or over a cap; the connection must be closed.
    Protocol(ProtocolError),
}

/// One step of the outer loop: a finished value, or an array that just opened.
enum Element {
    Frame(RespFrame),
    Container(Builder),
}

/// One array that is still collecting elements.
///
/// `remaining` is the declared element count minus what has been decoded so far.
/// The item vector grows only as real elements arrive, so a declared count of a
/// million never reserves memory up front, and the memory actually used is
/// bounded by the bytes that were really buffered.
struct Builder {
    items: Vec<RespFrame>,
    remaining: usize,
}

/// A single decode attempt over the not-yet-consumed tail of the buffer.
struct Decode<'a> {
    buf: &'a [u8],
    /// Cursor into `buf`.
    pos: usize,
    /// See [`RespDecoder::line_scanned`]; maintained here and written back.
    line_scanned: usize,
    max_message_bytes: usize,
    max_bulk_len: usize,
    max_array_len: usize,
    max_depth: usize,
}

impl Decode<'_> {
    /// Decode exactly one frame, or fail with `Incomplete` / a protocol error.
    fn next_frame(&mut self) -> Result<(RespFrame, usize), Fail> {
        let mut stack: Vec<Builder> = Vec::new();
        loop {
            // Retire every array that has all of its declared elements. Popping
            // one array can complete its parent, hence the inner loop.
            loop {
                let finished = matches!(stack.last(), Some(builder) if builder.remaining == 0);
                if !finished {
                    break;
                }
                let Some(builder) = stack.pop() else {
                    break;
                };
                let frame = RespFrame::Array(builder.items);
                match stack.last_mut() {
                    Some(parent) => parent.items.push(frame),
                    None => return Ok((frame, self.pos)),
                }
            }

            let Some(&type_byte) = self.buf.get(self.pos) else {
                return Err(Fail::Incomplete);
            };

            match self.element(type_byte, stack.len() + 1)? {
                Element::Frame(frame) => match stack.last_mut() {
                    Some(parent) => {
                        parent.remaining = parent.remaining.saturating_sub(1);
                        parent.items.push(frame);
                    }
                    None => return Ok((frame, self.pos)),
                },
                Element::Container(builder) => {
                    // A nested array occupies one slot of the array that holds
                    // it, so its element is accounted for the moment it opens.
                    if let Some(parent) = stack.last_mut() {
                        parent.remaining = parent.remaining.saturating_sub(1);
                    }
                    stack.push(builder);
                }
            }
        }
    }

    /// Decode one value starting at `self.pos`, whose first byte is `type_byte`.
    ///
    /// `depth` is the nesting depth this value would have if it is an array: the
    /// outermost array of a message is depth 1.
    fn element(&mut self, type_byte: u8, depth: usize) -> Result<Element, Fail> {
        Ok(match type_byte {
            b'+' | b'-' => {
                let start = self.pos + 1;
                let end = self.find_line_end(start)?;
                let payload = self.buf.get(start..end).ok_or(Fail::Incomplete)?.to_vec();
                self.pos = end + 2;
                if type_byte == b'+' {
                    Element::Frame(RespFrame::Simple(payload))
                } else {
                    Element::Frame(RespFrame::Error(payload))
                }
            }
            b':' => {
                let (value, next, _negative) = self.parse_number(self.pos + 1)?;
                self.pos = next;
                Element::Frame(RespFrame::Integer(value))
            }
            b'$' => Element::Frame(self.bulk()?),
            b'*' => {
                let (count, next, negative) = self.parse_number(self.pos + 1)?;
                if negative {
                    // `-1` is the only legal negative form: the null array.
                    if count != -1 {
                        return Err(Fail::Protocol(ProtocolError::InvalidLength));
                    }
                    self.pos = next;
                    Element::Frame(RespFrame::Null)
                } else {
                    let declared = usize::try_from(count)
                        .map_err(|_| Fail::Protocol(ProtocolError::ArrayTooLong))?;
                    if declared > self.max_array_len {
                        return Err(Fail::Protocol(ProtocolError::ArrayTooLong));
                    }
                    if depth > self.max_depth {
                        return Err(Fail::Protocol(ProtocolError::DepthExceeded));
                    }
                    self.pos = next;
                    Element::Container(Builder {
                        items: Vec::new(),
                        remaining: declared,
                    })
                }
            }
            b'_' => {
                // RESP3 null: `_\r\n`. Trailing bytes are part of the frame, so a
                // missing terminator is a fault, not a different value.
                match (self.buf.get(self.pos + 1), self.buf.get(self.pos + 2)) {
                    (Some(b'\r'), Some(b'\n')) => {
                        self.pos += 3;
                        Element::Frame(RespFrame::Null)
                    }
                    (Some(b'\r'), None) | (None, _) => return Err(Fail::Incomplete),
                    _ => return Err(Fail::Protocol(ProtocolError::InvalidTerminator)),
                }
            }
            _ => Element::Frame(self.inline()?),
        })
    }

    /// `$<len>\r\n<payload>\r\n` or `$-1\r\n`.
    fn bulk(&mut self) -> Result<RespFrame, Fail> {
        let (len, next, negative) = self.parse_number(self.pos + 1)?;
        if negative {
            if len != -1 {
                return Err(Fail::Protocol(ProtocolError::InvalidLength));
            }
            self.pos = next;
            return Ok(RespFrame::Null);
        }
        let declared =
            usize::try_from(len).map_err(|_| Fail::Protocol(ProtocolError::BulkTooLarge))?;
        if declared > self.max_bulk_len {
            return Err(Fail::Protocol(ProtocolError::BulkTooLarge));
        }
        // Reject a frame that could never fit *before* waiting for its payload, so
        // a declared-but-absent length cannot pin memory or time.
        let end = next
            .checked_add(declared)
            .ok_or(Fail::Protocol(ProtocolError::MessageTooLarge))?;
        let after = end
            .checked_add(2)
            .ok_or(Fail::Protocol(ProtocolError::MessageTooLarge))?;
        if after > self.max_message_bytes {
            return Err(Fail::Protocol(ProtocolError::MessageTooLarge));
        }
        if self.buf.len() < end {
            return Err(Fail::Incomplete);
        }
        match (self.buf.get(end), self.buf.get(end + 1)) {
            (Some(b'\r'), Some(b'\n')) => {}
            // The payload is here but its CRLF has not arrived yet.
            (Some(b'\r'), None) | (None, _) => return Err(Fail::Incomplete),
            _ => return Err(Fail::Protocol(ProtocolError::InvalidTerminator)),
        }
        // Length checked against `max_bulk_len` and the buffer above, so this
        // copy is bounded by bytes that are already buffered.
        let payload = self.buf.get(next..end).ok_or(Fail::Incomplete)?.to_vec();
        self.pos = after;
        Ok(RespFrame::Bulk(payload))
    }

    /// An inline command: one line, split into arguments on whitespace.
    fn inline(&mut self) -> Result<RespFrame, Fail> {
        let start = self.pos;
        let end = self.find_line_end(start)?;
        let line = self.buf.get(start..end).ok_or(Fail::Incomplete)?;
        let args = split_inline_args(line, self.max_array_len)?;
        if args.is_empty() {
            return Err(Fail::Protocol(ProtocolError::EmptyCommand));
        }
        self.pos = end + 2;
        Ok(RespFrame::Array(
            args.into_iter().map(RespFrame::Bulk).collect(),
        ))
    }

    /// Index of the `\r` that terminates the line starting at `from`.
    ///
    /// A bare `\n` and a `\r` followed by anything but `\n` are protocol errors;
    /// a buffer that merely ends too early is `Incomplete`.
    fn find_line_end(&mut self, from: usize) -> Result<usize, Fail> {
        // Bytes before `line_scanned` are known not to hold a terminator.
        let mut index = from.max(self.line_scanned);
        while let Some(&byte) = self.buf.get(index) {
            match byte {
                b'\r' => {
                    return match self.buf.get(index + 1) {
                        Some(b'\n') => Ok(index),
                        Some(_) => Err(Fail::Protocol(ProtocolError::InvalidTerminator)),
                        None => {
                            // Everything before this pending `\r` is clean; the
                            // `\r` itself must be looked at again next time.
                            self.line_scanned = index;
                            Err(Fail::Incomplete)
                        }
                    };
                }
                b'\n' => return Err(Fail::Protocol(ProtocolError::InvalidTerminator)),
                _ => index += 1,
            }
        }
        self.line_scanned = self.buf.len();
        Err(Fail::Incomplete)
    }

    /// Parse `<digits>\r\n`, optionally preceded by `-`.
    ///
    /// Returns the signed value, the offset just past the terminator, and whether
    /// a minus sign was present (the only place `-1` and `-2` differ in meaning).
    /// Digits are accumulated with checked arithmetic, so an oversized prefix is
    /// reported as [`ProtocolError::IntegerOverflow`] instead of wrapping, and no
    /// intermediate string is built.
    fn parse_number(&self, from: usize) -> Result<(i64, usize, bool), Fail> {
        let mut index = from;
        let negative = self.buf.get(index) == Some(&b'-');
        if negative {
            index += 1;
        }
        let mut magnitude: u64 = 0;
        let mut digits = 0usize;
        while let Some(&byte) = self.buf.get(index) {
            if !byte.is_ascii_digit() {
                break;
            }
            let digit = u64::from(byte - b'0');
            magnitude = magnitude
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or(Fail::Protocol(ProtocolError::IntegerOverflow))?;
            digits += 1;
            index += 1;
        }
        if digits == 0 {
            // Nothing that could still become a number, or nothing yet arrived.
            return if index >= self.buf.len() {
                Err(Fail::Incomplete)
            } else {
                Err(Fail::Protocol(ProtocolError::InvalidLength))
            };
        }
        match self.buf.get(index) {
            None => return Err(Fail::Incomplete),
            Some(b'\r') => match self.buf.get(index + 1) {
                Some(b'\n') => {}
                Some(_) => return Err(Fail::Protocol(ProtocolError::InvalidTerminator)),
                None => return Err(Fail::Incomplete),
            },
            Some(b'\n') => return Err(Fail::Protocol(ProtocolError::InvalidTerminator)),
            Some(_) => return Err(Fail::Protocol(ProtocolError::InvalidLength)),
        }
        let min_magnitude = i64::MIN.unsigned_abs();
        let value = if negative {
            if magnitude == min_magnitude {
                i64::MIN
            } else {
                let magnitude = i64::try_from(magnitude)
                    .map_err(|_| Fail::Protocol(ProtocolError::IntegerOverflow))?;
                magnitude
                    .checked_neg()
                    .ok_or(Fail::Protocol(ProtocolError::IntegerOverflow))?
            }
        } else {
            i64::try_from(magnitude).map_err(|_| Fail::Protocol(ProtocolError::IntegerOverflow))?
        };
        Ok((value, index + 2, negative))
    }
}

/// Split one inline command line into raw argument bytes.
///
/// Whitespace separates arguments; `"..."` and `'...'` group a value that may
/// contain whitespace; a backslash introduces `\n`, `\r`, `\t`, `\\`, `\"`,
/// `\xHH` and otherwise yields the escaped character itself. A trailing
/// backslash is kept verbatim instead of being treated as a fault.
///
/// The argument count is capped by `max_args` so one long line cannot turn into
/// an unbounded number of heap allocations.
fn split_inline_args(line: &[u8], max_args: usize) -> Result<Vec<Vec<u8>>, Fail> {
    let mut args: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut in_argument = false;
    let mut index = 0usize;
    while let Some(&byte) = line.get(index) {
        match byte {
            // `\r` and `\n` cannot appear here: the terminator scan rejected them.
            b' ' | b'\t' | 0x0b | 0x0c => {
                if in_argument {
                    push_arg(&mut args, std::mem::take(&mut current), max_args)?;
                    in_argument = false;
                }
                index += 1;
            }
            b'"' | b'\'' => {
                let quote = byte;
                in_argument = true;
                index += 1;
                loop {
                    let Some(&inner) = line.get(index) else {
                        return Err(Fail::Protocol(ProtocolError::InvalidTerminator));
                    };
                    index += 1;
                    if inner == quote {
                        break;
                    }
                    if inner == b'\\' {
                        index = push_escape(line, index, &mut current);
                    } else {
                        current.push(inner);
                    }
                }
            }
            b'\\' => {
                in_argument = true;
                index = push_escape(line, index + 1, &mut current);
            }
            _ => {
                in_argument = true;
                current.push(byte);
                index += 1;
            }
        }
    }
    if in_argument {
        push_arg(&mut args, current, max_args)?;
    }
    Ok(args)
}

/// Append one decoded argument, refusing to grow past the array cap.
fn push_arg(args: &mut Vec<Vec<u8>>, argument: Vec<u8>, max_args: usize) -> Result<(), Fail> {
    if args.len() >= max_args {
        return Err(Fail::Protocol(ProtocolError::ArrayTooLong));
    }
    args.push(argument);
    Ok(())
}

/// Decode one backslash escape. `after` points at the byte after the backslash.
/// Returns the index to continue scanning from.
fn push_escape(line: &[u8], after: usize, out: &mut Vec<u8>) -> usize {
    let Some(&escape) = line.get(after) else {
        out.push(b'\\');
        return after;
    };
    match escape {
        b'n' => out.push(b'\n'),
        b'r' => out.push(b'\r'),
        b't' => out.push(b'\t'),
        b'x' => {
            let high = line.get(after + 1).copied().and_then(hex_value);
            let low = line.get(after + 2).copied().and_then(hex_value);
            match (high, low) {
                (Some(high), Some(low)) => {
                    out.push((high << 4) | low);
                    return after + 3;
                }
                // Not `\xHH`: keep the `x` literally, as Redis does.
                _ => out.push(b'x'),
            }
        }
        other => out.push(other),
    }
    after + 1
}

/// Value of one hex digit, or `None` for anything else.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::resp::encode_frame_vec;

    /// A decoder with limits that exercise every cap without large buffers.
    fn dec() -> RespDecoder {
        RespDecoder::new(64 * 1024, 4096, 64, 4)
    }

    /// Feed `input` and decode until the decoder reports that it needs more data.
    fn decode_all(mut decoder: RespDecoder, input: &[u8]) -> Vec<RespFrame> {
        decoder.extend(input).unwrap();
        let mut frames = Vec::new();
        while let Some(frame) = decoder.try_decode().unwrap() {
            frames.push(frame);
        }
        assert!(
            decoder.is_empty(),
            "decoder kept {} bytes",
            decoder.buffered()
        );
        frames
    }

    /// Decode the single frame in `input`.
    fn decode_one(input: &[u8]) -> RespFrame {
        let mut frames = decode_all(dec(), input);
        assert_eq!(frames.len(), 1, "expected exactly one frame");
        frames.remove(0)
    }

    fn bulk_args(args: &[&[u8]]) -> RespFrame {
        RespFrame::Array(args.iter().map(RespFrame::bulk).collect())
    }

    #[test]
    fn scalars_decode_to_expected_frames() {
        let frames = decode_all(
            dec(),
            b"+OK\r\n-ERR bad\r\n:42\r\n:-7\r\n$3\r\nfoo\r\n$0\r\n\r\n",
        );
        assert_eq!(
            frames,
            vec![
                RespFrame::Simple(b"OK".to_vec()),
                RespFrame::Error(b"ERR bad".to_vec()),
                RespFrame::Integer(42),
                RespFrame::Integer(-7),
                RespFrame::Bulk(b"foo".to_vec()),
                RespFrame::Bulk(Vec::new()),
            ]
        );
        assert_eq!(decode_one(b":0\r\n"), RespFrame::Integer(0));
        assert_eq!(
            decode_one(b":-9223372036854775808\r\n"),
            RespFrame::Integer(i64::MIN)
        );
        assert_eq!(
            decode_one(b":9223372036854775807\r\n"),
            RespFrame::Integer(i64::MAX)
        );
        assert_eq!(
            decode_one(b"+a b c\r\n"),
            RespFrame::Simple(b"a b c".to_vec())
        );
        assert_eq!(
            decode_one(b"-WRONGTYPE nope\r\n"),
            RespFrame::error("WRONGTYPE nope")
        );
    }

    #[test]
    fn binary_bulk_round_trips_through_the_encoder() {
        let payload = vec![0x00u8, b'\r', b'\n', 0xff, 0x00];
        let mut wire = b"$5\r\n".to_vec();
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n");

        let frame = decode_one(&wire);
        assert_eq!(frame, RespFrame::Bulk(payload));
        assert_eq!(encode_frame_vec(&frame, false), wire);
        // And the re-encoded form decodes back to itself.
        assert_eq!(decode_one(&encode_frame_vec(&frame, false)), frame);
    }

    #[test]
    fn split_delivery_one_byte_at_a_time() {
        let first = b"*1\r\n$4\r\nPING\r\n";
        let second = b"*1\r\n$4\r\nPONG\r\n";
        let mut wire = first.to_vec();
        wire.extend_from_slice(second);
        let first_len = first.len();

        let mut decoder = dec();
        let mut frames = Vec::new();
        for (index, byte) in wire.iter().enumerate() {
            decoder.extend(&[*byte]).unwrap();
            while let Some(frame) = decoder.try_decode().unwrap() {
                assert!(
                    index + 1 >= first_len,
                    "frame {frame:?} completed after only {} bytes",
                    index + 1
                );
                frames.push(frame);
            }
        }
        assert_eq!(
            frames,
            vec![bulk_args(&[b"PING"]), bulk_args(&[b"PONG"])],
            "two commands in order"
        );
        assert_eq!(decoder.buffered(), 0);
        assert!(decoder.try_decode().unwrap().is_none());
    }

    #[test]
    fn pipelined_commands_decode_one_per_call() {
        let mut decoder = dec();
        decoder.extend(b"+OK\r\n:1\r\n$2\r\nhi\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::ok()));
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Integer(1)));
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Bulk(b"hi".to_vec()))
        );
        assert_eq!(decoder.try_decode().unwrap(), None);
        assert_eq!(decoder.buffered(), 0);

        // The same bytes split across three `extend` calls after consumption.
        let mut decoder = dec();
        decoder.extend(b"+OK\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::ok()));
        assert!(decoder.is_empty());
        decoder.extend(b":1\r\n$2\r\nhi\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Integer(1)));
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Bulk(b"hi".to_vec()))
        );
        assert_eq!(decoder.try_decode().unwrap(), None);
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn bulk_over_the_cap_is_rejected() {
        let mut decoder = RespDecoder::new(4096, 8, 8, 4);
        decoder.extend(b"$9\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::BulkTooLarge));
        // The cap is checked before any payload has to arrive.
        let mut decoder = RespDecoder::new(4096, 8, 8, 4);
        decoder.extend(b"$9\r\n123456789\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::BulkTooLarge));
        // A bulk at exactly the cap is fine.
        let mut decoder = RespDecoder::new(4096, 8, 8, 4);
        decoder.extend(b"$8\r\n12345678\r\n").unwrap();
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Bulk(b"12345678".to_vec()))
        );
    }

    #[test]
    fn malformed_lengths_are_rejected() {
        for wire in [
            &b"$-2\r\n"[..],
            &b"$-0\r\n"[..],
            &b"$-9999\r\n"[..],
            &b"$abc\r\n"[..],
            &b"$ 5\r\n"[..],
            &b"$+5\r\n"[..],
            &b"$\r\n"[..],
            &b"*abc\r\n"[..],
            &b"*-2\r\n"[..],
            &b"*-0\r\n"[..],
            &b":abc\r\n"[..],
            &b":-x\r\n"[..],
            &b":+1\r\n"[..],
        ] {
            let mut decoder = dec();
            decoder.extend(wire).unwrap();
            assert_eq!(
                decoder.try_decode(),
                Err(ProtocolError::InvalidLength),
                "input {:?}",
                String::from_utf8_lossy(wire)
            );
        }

        for wire in [
            &b"$99999999999999999999999\r\n"[..],
            &b"*99999999999999999999999\r\n"[..],
            &b":99999999999999999999\r\n"[..],
            &b":18446744073709551615\r\n"[..],
        ] {
            let mut decoder = dec();
            decoder.extend(wire).unwrap();
            assert_eq!(
                decoder.try_decode(),
                Err(ProtocolError::IntegerOverflow),
                "input {:?}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    #[test]
    fn array_cap_and_depth_cap_are_enforced() {
        let mut decoder = RespDecoder::new(4096, 4096, 4, 8);
        decoder.extend(b"*5\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::ArrayTooLong));

        // Four elements are fine, five are not.
        let mut decoder = RespDecoder::new(4096, 4096, 4, 8);
        decoder.extend(b"*4\r\n:1\r\n:2\r\n:3\r\n:4\r\n").unwrap();
        assert!(
            matches!(decoder.try_decode(), Ok(Some(RespFrame::Array(items))) if items.len() == 4)
        );

        // Exactly at `max_depth` succeeds...
        let at_cap = b"*1\r\n*1\r\n*1\r\n$1\r\nx\r\n";
        let mut decoder = RespDecoder::new(4096, 4096, 8, 3);
        decoder.extend(at_cap).unwrap();
        let frame = decoder.try_decode().unwrap().unwrap();
        assert_eq!(
            frame,
            RespFrame::Array(vec![RespFrame::Array(vec![RespFrame::Array(vec![
                RespFrame::Bulk(b"x".to_vec())
            ])])])
        );

        // ...one level deeper does not.
        let mut decoder = RespDecoder::new(4096, 4096, 8, 3);
        decoder
            .extend(b"*1\r\n*1\r\n*1\r\n*1\r\n$1\r\nx\r\n")
            .unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::DepthExceeded));

        // A leaf value never counts as a level.
        let mut decoder = RespDecoder::new(4096, 4096, 8, 1);
        decoder.extend(b"$1\r\nx\r\n").unwrap();
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Bulk(b"x".to_vec()))
        );
        // A null array is a leaf too.
        let mut decoder = RespDecoder::new(4096, 4096, 8, 1);
        decoder.extend(b"*-1\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Null));
    }

    #[test]
    fn oversized_stream_is_rejected_before_the_buffer_grows() {
        let mut decoder = RespDecoder::new(256, 256, 8, 4);
        let mut error = None;
        let mut accepted = 0usize;
        for _ in 0..200 {
            match decoder.extend(&[b'A'; 8]) {
                Ok(()) => {
                    accepted += 1;
                    assert!(
                        decoder.buffered() <= 256,
                        "buffer grew past max_message_bytes: {}",
                        decoder.buffered()
                    );
                }
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
        assert_eq!(error, Some(ProtocolError::MessageTooLarge));
        assert_eq!(accepted, 32, "256 / 8 chunks fit, the 33rd does not");
        assert!(decoder.buffered() <= 256);

        // One slice that is itself larger than the cap, on a fresh decoder.
        let mut decoder = RespDecoder::new(16, 16, 8, 4);
        assert_eq!(
            decoder.extend(&[b'A'; 64]),
            Err(ProtocolError::MessageTooLarge)
        );
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn incomplete_bulk_consumes_nothing_and_completes_later() {
        let mut decoder = dec();
        decoder.extend(b"$5\r\nab").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        assert_eq!(decoder.buffered(), 6, "nothing was consumed");
        decoder.extend(b"cde\r\n").unwrap();
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Bulk(b"abcde".to_vec()))
        );
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn inline_commands_split_into_bulk_arguments() {
        assert_eq!(decode_one(b"PING\r\n"), bulk_args(&[b"PING"]));
        assert_eq!(
            decode_one(b"SET key \"a value with spaces\"\r\n"),
            bulk_args(&[b"SET", b"key", b"a value with spaces"])
        );
        assert_eq!(
            decode_one(b"SET k 'single quoted'\r\n"),
            bulk_args(&[b"SET", b"k", b"single quoted"])
        );
        // Backslash escapes work outside quotes too.
        assert_eq!(
            decode_one(b"SET k a\\nb\r\n"),
            bulk_args(&[b"SET", b"k", b"a\nb"])
        );
        assert_eq!(
            decode_one(b"SET k \"a\\tb\\\\c\\\"d\"\r\n"),
            bulk_args(&[b"SET", b"k", b"a\tb\\c\"d"])
        );
        assert_eq!(
            decode_one(b"SET k \"\\x41\\x00z\"\r\n"),
            bulk_args(&[b"SET", b"k", b"A\x00z"])
        );
        // `\` before an unknown character yields that character.
        assert_eq!(
            decode_one(b"SET k q\\z\r\n"),
            bulk_args(&[b"SET", b"k", b"qz"])
        );
        // An empty quoted group is still an argument; runs of spaces collapse.
        assert_eq!(
            decode_one(b"SET   k   \"\"\r\n"),
            bulk_args(&[b"SET", b"k", b""])
        );
        // A line that is not a known type byte is an inline command, not an error.
        assert_eq!(
            decode_one(b"hello world\r\n"),
            bulk_args(&[b"hello", b"world"])
        );

        for wire in [&b"\r\n"[..], &b"   \r\n"[..], &b"\t \t\r\n"[..]] {
            let mut decoder = dec();
            decoder.extend(wire).unwrap();
            assert_eq!(
                decoder.try_decode(),
                Err(ProtocolError::EmptyCommand),
                "input {:?}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    #[test]
    fn invalid_terminators_are_reported() {
        for wire in [&b"+abc\rX"[..], &b"+abc\n"[..], &b"PING\n"[..]] {
            let mut decoder = dec();
            decoder.extend(wire).unwrap();
            assert_eq!(
                decoder.try_decode(),
                Err(ProtocolError::InvalidTerminator),
                "input {:?}",
                String::from_utf8_lossy(wire)
            );
        }
        // A buffer that merely stops before the `\n` is incomplete, not invalid.
        let mut decoder = dec();
        decoder.extend(b"+abc\r").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        assert_eq!(decoder.buffered(), 5);
        decoder.extend(b"\n").unwrap();
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Simple(b"abc".to_vec()))
        );

        // Same distinction for a bulk payload's terminator.
        let mut decoder = dec();
        decoder.extend(b"$1\r\na\r").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        decoder.extend(b"\n").unwrap();
        assert_eq!(
            decoder.try_decode().unwrap(),
            Some(RespFrame::Bulk(b"a".to_vec()))
        );
        let mut decoder = dec();
        decoder.extend(b"$1\r\naX\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::InvalidTerminator));
    }

    #[test]
    fn terminator_that_has_not_arrived_is_incomplete() {
        // Bulk payload fully buffered, its CRLF still in flight: the frame is
        // incomplete, not malformed. This is the split-packet case the server
        // sees whenever a payload and its terminator land in different segments.
        let mut decoder = dec();
        decoder.extend(b"*1\r\n$4\r\nPING").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        assert_eq!(decoder.buffered(), 12, "nothing was consumed");
        decoder.extend(b"\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(bulk_args(&[b"PING"])));
        assert_eq!(decoder.buffered(), 0);

        // Simple string: the `\r` arrived, the `\n` did not.
        let mut decoder = dec();
        decoder.extend(b"+OK\r").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        decoder.extend(b"\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::ok()));

        // Integer, with and without the terminator's `\r`.
        let mut decoder = dec();
        decoder.extend(b":123").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        decoder.extend(b"\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Integer(123)));

        let mut decoder = dec();
        decoder.extend(b":123\r").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        decoder.extend(b"\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Integer(123)));

        // RESP3 null, same split.
        let mut decoder = dec();
        decoder.extend(b"_\r").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        decoder.extend(b"\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Null));

        // A terminator that *did* arrive and is wrong stays an error.
        for wire in [&b"+OK\rX"[..], &b"$1\r\na\rX\r\n"[..], &b":1\rX"[..]] {
            let mut decoder = dec();
            decoder.extend(wire).unwrap();
            assert_eq!(
                decoder.try_decode(),
                Err(ProtocolError::InvalidTerminator),
                "input {:?}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    #[test]
    fn every_prefix_of_a_single_frame_waits_instead_of_failing() {
        let wires: [&[u8]; 7] = [
            b"$12\r\nhello world!\r\n",
            b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n",
            b":123456\r\n",
            b"+OK\r\n",
            b"-ERR nope\r\n",
            b"_\r\n",
            b"PING\r\n",
        ];
        for wire in wires {
            let expected = decode_one(wire);
            // Every proper prefix is a valid frame start that simply needs more
            // bytes: it must never be reported as malformed.
            for split in 0..wire.len() {
                let mut decoder = dec();
                decoder.extend(&wire[..split]).unwrap();
                assert_eq!(
                    decoder.try_decode(),
                    Ok(None),
                    "prefix of {split} bytes was not treated as incomplete: {:?}",
                    String::from_utf8_lossy(&wire[..split])
                );
                decoder.extend(&wire[split..]).unwrap();
                assert_eq!(
                    decoder.try_decode().unwrap(),
                    Some(expected.clone()),
                    "split at {split} of {:?}",
                    String::from_utf8_lossy(wire)
                );
                assert!(decoder.is_empty(), "leftover bytes after split {split}");
            }
        }
    }

    #[test]
    fn any_two_way_split_of_a_pipeline_decodes_identically() {
        let wire: &[u8] = b"*1\r\n$4\r\nPING\r\n+OK\r\n:42\r\n$3\r\nfoo\r\n";
        let expected = decode_all(dec(), wire);
        assert_eq!(expected.len(), 4);
        for split in 0..=wire.len() {
            let mut decoder = dec();
            decoder.extend(&wire[..split]).unwrap();
            // A prefix may already contain complete commands; it may never fail.
            let mut frames = Vec::new();
            while let Some(frame) = decoder.try_decode().unwrap() {
                frames.push(frame);
            }
            decoder.extend(&wire[split..]).unwrap();
            while let Some(frame) = decoder.try_decode().unwrap() {
                frames.push(frame);
            }
            assert_eq!(&frames, &expected, "split at {split}");
            assert!(decoder.is_empty(), "leftover bytes at split {split}");
        }
    }

    #[test]
    fn null_spellings_all_decode_to_null() {
        let frames = decode_all(dec(), b"$-1\r\n*-1\r\n_\r\n");
        assert_eq!(
            frames,
            vec![RespFrame::Null, RespFrame::Null, RespFrame::Null]
        );
        // RESP3 null needs its terminator.
        let mut decoder = dec();
        decoder.extend(b"_").unwrap();
        assert_eq!(decoder.try_decode(), Ok(None));
        decoder.extend(b"\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Null));
        let mut decoder = dec();
        decoder.extend(b"_x\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::InvalidTerminator));
    }

    #[test]
    fn zero_caps_do_not_panic() {
        let mut decoder = RespDecoder::new(64, 0, 0, 0);
        assert_eq!(decoder.caps(), (64, 0, 0, 0));
        decoder.extend(b"$1\r\na\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::BulkTooLarge));

        let mut decoder = RespDecoder::new(64, 0, 0, 0);
        decoder.extend(b"*1\r\n$1\r\na\r\n").unwrap();
        assert_eq!(decoder.try_decode(), Err(ProtocolError::ArrayTooLong));

        // The inline path also refuses to build more arguments than allowed.
        let mut decoder = RespDecoder::new(64, 0, 0, 0);
        decoder.extend(b"PING\r\n").unwrap();
        assert!(decoder.try_decode().is_err());

        // Values that never touch the caps still decode.
        let mut decoder = RespDecoder::new(64, 0, 0, 0);
        decoder.extend(b":1\r\n").unwrap();
        assert_eq!(decoder.try_decode().unwrap(), Some(RespFrame::Integer(1)));

        // A zero-byte message cap refuses everything without growing.
        let mut decoder = RespDecoder::new(0, 0, 0, 0);
        assert_eq!(decoder.extend(b"x"), Err(ProtocolError::MessageTooLarge));
        assert_eq!(decoder.extend(b""), Ok(()));
        assert_eq!(decoder.try_decode().unwrap(), None);
    }

    #[test]
    fn garbage_input_terminates_without_panicking() {
        let mut state = 0x5eed_1234u32;
        let mut garbage = Vec::new();
        for _ in 0..10_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            garbage.push(((state >> 16) & 0xff) as u8);
        }
        let mut decoder = RespDecoder::new(100_000, 4096, 32, 6);
        decoder.extend(&garbage).unwrap();
        let mut steps = 0usize;
        loop {
            steps += 1;
            assert!(steps <= 50_000, "decoder made no progress");
            match decoder.try_decode() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break,
            }
        }
        assert!(decoder.buffered() <= garbage.len());

        // Same bytes, one at a time, to exercise every partial-prefix path.
        let mut decoder = RespDecoder::new(100_000, 4096, 32, 6);
        for byte in garbage.iter().take(2_000) {
            if decoder.extend(&[*byte]).is_err() {
                break;
            }
            let mut budget = 4;
            while budget > 0 {
                budget -= 1;
                match decoder.try_decode() {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}
