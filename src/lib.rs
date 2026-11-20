pub mod auto;
pub mod batch;
pub mod cryptnek;
pub mod native;
pub mod outer_legacy;
pub mod outer_nyx;
pub mod outer_v8;
pub mod source;
pub mod vm;

#[derive(Debug, Clone)]
pub struct Token {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
}

pub fn lex(source: &str) -> Result<Vec<Token>, String> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let comment = b[i..].starts_with(b"--");
        if comment {
            i += 2;
        }
        let long = if b.get(i) == Some(&b'[') {
            let mut j = i + 1;
            while b.get(j) == Some(&b'=') {
                j += 1;
            }
            (b.get(j) == Some(&b'[')).then_some(j - i - 1)
        } else {
            None
        };
        let kind;
        if let Some(level) = long {
            let close = format!("]{}]", "=".repeat(level));
            let content = i + level + 2;
            i = content
                + source[content..]
                    .find(&close)
                    .ok_or_else(|| format!("Unterminated long string at {start}"))?
                + close.len();
            kind = "string";
        } else if comment {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if b[i] == b'\'' || b[i] == b'"' {
            let quote = b[i];
            i += 1;
            loop {
                if i >= b.len() {
                    return Err(format!("Unterminated quoted string at {start}"));
                }
                if b[i] == quote {
                    i += 1;
                    break;
                }
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            kind = "string";
        } else if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            kind = "ident";
        } else if b[i].is_ascii_digit() {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            kind = "number";
        } else {
            if b[i] == b'`' {
                return Err(format!(
                    "Interpolated Luau strings are not supported at {start}"
                ));
            }
            if b[i] >= 128 {
                return Err(format!("Unsupported non-ASCII token at {start}"));
            }
            i += 1;
            kind = "punct";
        }
        if !comment {
            out.push(Token {
                start,
                end: i,
                kind,
            });
        }
    }
    Ok(out)
}

pub fn number(source: &str) -> Result<u64, String> {
    let clean = source.replace('_', "");
    let (radix, digits) = if clean.starts_with("0x") || clean.starts_with("0X") {
        (16, &clean[2..])
    } else if clean.starts_with("0b") || clean.starts_with("0B") {
        (2, &clean[2..])
    } else {
        (10, clean.as_str())
    };
    u64::from_str_radix(digits, radix).map_err(|e| format!("Invalid integer {source}: {e}"))
}

pub fn ascii85(source: &[u8]) -> Result<Vec<u8>, String> {
    if !source.len().is_multiple_of(5) {
        return Err("ASCII85 length is not divisible by five".into());
    }
    let mut out = Vec::new();
    for group in source.chunks_exact(5) {
        let mut n = 0u64;
        for &b in group {
            if !(33..=117).contains(&b) {
                return Err("Invalid ASCII85 digit".into());
            }
            n = n * 85 + (b - 33) as u64;
        }
        out.extend_from_slice(
            &u32::try_from(n)
                .map_err(|_| "ASCII85 word overflow")?
                .to_be_bytes(),
        );
    }
    Ok(out)
}

pub fn long_value(source: &str) -> Result<&str, String> {
    let open = source.find('[').ok_or("Not a long string")?;
    let level = source[open + 1..]
        .bytes()
        .take_while(|&b| b == b'=')
        .count();
    let start = open + level + 2;
    source
        .get(start..source.len() - level - 2)
        .ok_or("Invalid long string".into())
}

pub fn field_string<'a>(source: &'a str, tokens: &[Token], field: &str) -> Result<&'a str, String> {
    for t in tokens.windows(3) {
        if &source[t[0].start..t[0].end] == field
            && &source[t[1].start..t[1].end] == "="
            && t[2].kind == "string"
        {
            return long_value(&source[t[2].start..t[2].end]);
        }
    }
    Err(format!("Missing long string field {field}"))
}

pub fn pool_index(encoded: &str) -> Result<Vec<(u64, usize, usize)>, String> {
    let (mut value, mut place, mut offset) = (0u64, 1u64, 0usize);
    let mut pending = None;
    let mut out = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for b in encoded.bytes() {
        let digit = ((b as i64 - 33 - 74) * 17).rem_euclid(84) as u64;
        value = value
            .checked_add((digit % 42).checked_mul(place).ok_or("Index overflow")?)
            .ok_or("Index overflow")?;
        if digit >= 42 {
            place = place.checked_mul(42).ok_or("Index overflow")?;
        } else {
            if value == 0 || value > 2147483646 {
                return Err("Invalid index value".into());
            }
            if let Some(id) = pending.take() {
                let len = value as usize;
                if len < 10 || len >= 3776 || !len.is_multiple_of(5) {
                    return Err("Invalid pool record length".into());
                }
                if !ids.insert(id) {
                    return Err("Duplicate pool identifier".into());
                }
                out.push((id, offset, len));
                offset += len;
            } else {
                pending = Some(value);
            }
            value = 0;
            place = 1;
        }
    }
    if pending.is_some() || place != 1 || value != 0 {
        return Err("Truncated pool index".into());
    }
    Ok(out)
}

pub fn decrypt_record(id: u64, seed: u64, encoded: &str) -> Result<Vec<u8>, String> {
    let cipher = ascii85(encoded.as_bytes())?;
    let mut state = (id + 34707 + seed) % 65521;
    let mut checksum = (id + 34707 + seed) % 2147483647;
    let mut plain = Vec::new();
    for (i, b) in cipher.iter().enumerate() {
        state = (state * 197 + 432 + i as u64) % 65521;
        let v = (*b as i64 - (state % 256) as i64).rem_euclid(256) as u8;
        state = (state + *b as u64) % 65521;
        if i < 4 || i >= 8 {
            checksum = (checksum * 33 + v as u64) % 2147483647;
        }
        plain.push(v);
    }
    if plain.len() < 8 {
        return Err("Truncated encrypted record".into());
    }
    let len = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
    let expected = u32::from_le_bytes(plain[4..8].try_into().unwrap()) as u64;
    if len > plain.len() - 8 || plain.len() - 8 - len > 3 || checksum != expected {
        return Err(format!(
            "Record {id} failed length/checksum validation with seed {seed}"
        ));
    }
    Ok(plain[8..8 + len].to_vec())
}

pub fn lua_string(bytes: &[u8]) -> String {
    let mut s = String::from("\"");
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            32..=126 => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03}")),
        }
    }
    s.push('"');
    s
}
