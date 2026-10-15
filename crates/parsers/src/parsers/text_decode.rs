//! Encoding-tolerant text reading for artefacts that are frequently NOT UTF-8.
//!
//! Windows writes many text artefacts as UTF-16. Scheduled Task XML under
//! `\Windows\System32\Tasks\` is commonly UTF-16 LE with a BOM, and PowerShell
//! `ConsoleHost_history.txt` can be UTF-16 too. `std::fs::read_to_string` only
//! accepts UTF-8 and errors on anything else, which would fail every such file.
//! This reads the bytes and decodes by BOM, falling back to lossy UTF-8.

use std::path::Path;

/// Read a file as text, detecting the encoding from its byte-order mark:
/// UTF-8 BOM, UTF-16 LE BOM, or UTF-16 BE BOM. With no BOM, if the bytes look
/// like UTF-16 LE (ASCII text has a NUL in every other byte) it is decoded as
/// such; otherwise it is treated as UTF-8 (lossy, so stray bytes never fail the
/// parse). The returned string never contains a leading BOM.
pub fn read_text_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(decode_text(&bytes))
}

/// Decode a byte buffer to text using the same BOM/heuristic rules as
/// [`read_text_file`]. Exposed for testing.
pub fn decode_text(bytes: &[u8]) -> String {
    // UTF-8 BOM
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    // UTF-16 LE BOM
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        return decode_utf16le(&bytes[2..]);
    }
    // UTF-16 BE BOM
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        return decode_utf16be(&bytes[2..]);
    }
    // No BOM: sniff for UTF-16 LE (common for Windows exports). Plain ASCII text
    // in UTF-16 LE has a 0x00 as the high byte of most code units. If a large
    // share of even-indexed... (we check odd bytes) are NUL, treat as UTF-16 LE.
    if looks_like_utf16le(bytes) {
        return decode_utf16le(bytes);
    }
    // Default: UTF-8, lossy so a stray byte never aborts the parse.
    String::from_utf8_lossy(bytes).into_owned()
}

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return false;
    }
    // Sample up to 256 code units; if most high bytes (odd indices) are 0x00,
    // this is almost certainly UTF-16 LE ASCII-range text.
    let sample = bytes.len().min(512);
    let mut nul_high = 0usize;
    let mut total = 0usize;
    let mut i = 1;
    while i < sample {
        total += 1;
        if bytes[i] == 0x00 {
            nul_high += 1;
        }
        i += 2;
    }
    total > 0 && nul_high * 10 >= total * 7 // ≥70% high-byte NULs
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_utf16be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_plain() {
        assert_eq!(decode_text(b"<Task>hi</Task>"), "<Task>hi</Task>");
    }

    #[test]
    fn utf8_bom() {
        let mut b = vec![0xEF, 0xBB, 0xBF];
        b.extend_from_slice(b"<Task/>");
        assert_eq!(decode_text(&b), "<Task/>");
    }

    #[test]
    fn utf16le_bom() {
        // "<Task/>" as UTF-16 LE with BOM
        let mut b = vec![0xFF, 0xFE];
        for ch in "<Task/>".chars() {
            let u = ch as u16;
            b.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_text(&b), "<Task/>");
    }

    #[test]
    fn utf16be_bom() {
        let mut b = vec![0xFE, 0xFF];
        for ch in "<Task/>".chars() {
            let u = ch as u16;
            b.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(decode_text(&b), "<Task/>");
    }

    #[test]
    fn utf16le_no_bom_sniffed() {
        // UTF-16 LE without a BOM (some exports omit it) — should still decode.
        let mut b = Vec::new();
        for ch in "<Task><Command>cmd.exe</Command></Task>".chars() {
            b.extend_from_slice(&(ch as u16).to_le_bytes());
        }
        assert_eq!(decode_text(&b), "<Task><Command>cmd.exe</Command></Task>");
    }
}
