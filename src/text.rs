//! Bounded, binary-safe rendering of attacker controlled bytes.
//!
//! Nothing that came off the wire may reach a log line, a terminal or a SQLite
//! column without passing through one of these helpers first: they cap the
//! length *and* make control bytes and invalid UTF-8 visible and inert.

use std::fmt::Write as _;

/// Render up to `max_len` bytes as a printable ASCII escape sequence.
///
/// Non printable bytes become `\xNN`, so binary payloads (Lua, RDB headers,
/// CRLF injection attempts) are safe to store and safe to print.
pub fn escape_bytes(bytes: &[u8], max_len: usize) -> String {
    let take = bytes.len().min(max_len);
    let mut out = String::new();
    for &b in &bytes[..take] {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                // `write!` into a String cannot fail.
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    if bytes.len() > take {
        let _ = write!(out, "...(+{}B)", bytes.len() - take);
    }
    out
}

/// Escape and cap a `&str`. Invalid UTF-8 cannot occur here, but control bytes can.
pub fn escape_str(s: &str, max_len: usize) -> String {
    escape_bytes(s.as_bytes(), max_len)
}

/// Truncate on a UTF-8 character boundary, appending `...` when shortened.
pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_owned();
    }
    let mut cut = max_len;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + 3);
    out.push_str(&s[..cut]);
    out.push_str("...");
    out
}

/// Render a RESP argument vector as one bounded, escaped, space separated line.
///
/// Quoting is added only when an argument contains a space or is empty, so the
/// common case (`CONFIG GET *`) stays readable.
pub fn join_args(args: &[Vec<u8>], max_total: usize) -> String {
    let mut out = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if out.len() >= max_total {
            let _ = write!(out, "...(+{} args)", args.len() - i);
            break;
        }
        let remaining = max_total - out.len();
        let needs_quote = arg.is_empty() || arg.iter().any(|b| matches!(b, b' ' | b'"'));
        if needs_quote {
            out.push('"');
        }
        out.push_str(&escape_bytes(arg, remaining));
        if needs_quote {
            out.push('"');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passes_through() {
        assert_eq!(escape_bytes(b"CONFIG GET *", 64), "CONFIG GET *");
    }

    #[test]
    fn control_and_binary_bytes_are_escaped() {
        assert_eq!(escape_bytes(b"a\r\nb\tc\\d", 64), "a\\r\\nb\\tc\\\\d");
        assert_eq!(
            escape_bytes(&[0xff, 0xfe, 0x00, b'A'], 64),
            "\\xff\\xfe\\x00A"
        );
    }

    #[test]
    fn escaping_is_length_capped() {
        let long = vec![b'A'; 10_000];
        let rendered = escape_bytes(&long, 16);
        assert!(rendered.starts_with(&"A".repeat(16)));
        assert!(rendered.ends_with("...(+9984B)"));
    }

    #[test]
    fn worst_case_expansion_stays_bounded() {
        // 4 bytes of output per input byte, still capped by max_len input.
        let rendered = escape_bytes(&[0x01; 100], 100);
        assert_eq!(rendered.len(), 400);
    }

    #[test]
    fn join_args_quotes_when_needed() {
        let args = vec![
            b"SET".to_vec(),
            b"key with space".to_vec(),
            b"".to_vec(),
            b"value".to_vec(),
        ];
        assert_eq!(join_args(&args, 256), "SET \"key with space\" \"\" value");
    }

    #[test]
    fn join_args_is_bounded() {
        let args: Vec<Vec<u8>> = (0..64).map(|_| vec![b'x'; 100]).collect();
        let rendered = join_args(&args, 128);
        assert!(rendered.len() < 128 + 32, "len={}", rendered.len());
        assert!(rendered.contains("args)"));
    }

    #[test]
    fn truncate_respects_char_boundary() {
        let s = "咸鱼罐头超长命令";
        let cut = truncate_str(s, 7);
        assert!(cut.ends_with("..."));
        assert!(cut.len() <= 10);
        assert_eq!(truncate_str("short", 32), "short");
    }
}
