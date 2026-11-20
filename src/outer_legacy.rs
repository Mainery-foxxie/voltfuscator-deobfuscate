//! Partial recovery for the inspected legacy v7.5/v7.6 corpus.
use mlua::{Function, Value};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// Authenticate the entire pre-application prefix, including the noise and wrapper,
// so an inserted environment mutation cannot change the meaning of a known helper.
// Only its self-contained decoder slice is evaluated.
const VERIFIED_PREFIXES: &[&str] = &[
    "979edb5dadd9754126064855e77519f9108c7f4f68fee1248766aba1cb5313ce",
    "e991cc112de417bd55844c9296cd70f800d237de8c93e710ec398cc29455fd38",
    "f0c1c4107b624a91229d9a717e38bdc88eee35ab88263af42e0774d00936f4f1",
    "6da4aad90bda2b6fa1b32f9d6d78b20cbe0bb4813f8be5578006e1953ed5a467",
    "32360a7c2b4ba9d738663257d3a5db062f93ce19e1e260be55e1f5e3eb8e749d",
    "7bec17a58d7d544be72f1987259bf15ab013de4b72772c0d977e6c91890267e1",
    "80b2b91ab7790a79e7b232f5bc2b8cffcb418101556331f933cc638d17e27e70",
    "4df2fa051cbf7a58fbd8538086deee4cd28a22e7478fabbfd022825f196ce19a",
    "86e155c6f86fb695d36ac7523ad1a85caf69a5cc98e0f033918af090cccf3f00",
    "f03bf4fa374326497284d6254cf344fb56026db4a9e7ab558deffe1e91c1f5ca",
    "74486f8818715507c8875e78d1d68fb4f2f00b8d657b309edbbd35c339591c88",
];

#[derive(Clone)]
struct Alias {
    name: String,
    decoder: String,
    fields: HashMap<String, f64>,
    end: usize,
}

fn numeric(s: &str) -> Option<f64> {
    let s = s.replace('_', "");
    if s.starts_with("0x") || s.starts_with("0X") || s.starts_with("0b") || s.starts_with("0B") {
        crate::number(&s).ok().map(|n| n as f64)
    } else {
        s.parse::<f64>().ok().filter(|n| n.is_finite())
    }
}

// Match only the observed three-argument forwarding functions, never arbitrary helpers.
fn alias(t: &[&str], i: usize) -> Option<Alias> {
    if t.get(i)? != &"local" || t.get(i + 2)? != &"=" || t.get(i + 3)? != &"{" {
        return None;
    }
    let name = t[i + 1].to_string();
    let mut j = i + 4;
    let mut fields = HashMap::new();
    let mut decoder = None;
    loop {
        let field = *t.get(j)?;
        if t.get(j + 1..j + 4)? != ["=", "function", "("] {
            return None;
        }
        let (a, b, c) = (*t.get(j + 4)?, *t.get(j + 6)?, *t.get(j + 8)?);
        if t.get(j + 5)? != &","
            || t.get(j + 7)? != &","
            || t.get(j + 9..j + 11)? != [")", "return"]
        {
            return None;
        }
        let target = *t.get(j + 11)?;
        if decoder.as_deref().is_some_and(|d| d != target)
            || t.get(j + 12)? != &"("
            || t.get(j + 13)? != &a
        {
            return None;
        }
        decoder = Some(target.to_string());
        let sign = match *t.get(j + 14)? {
            "+" => 1.,
            "-" => -1.,
            _ => return None,
        };
        let n = j + 15;
        let comma = (n..n + 4).find(|&k| t.get(k) == Some(&","))?;
        let offset = sign * numeric(&t[n..comma].concat())?;
        if t.get(comma..comma + 6)? != [",", b, ",", c, ")", "end"] {
            return None;
        }
        if fields.insert(field.to_string(), offset).is_some() {
            return None;
        }
        j = comma + 6;
        match *t.get(j)? {
            "," | ";" => {
                j += 1;
            }
            "}" => {
                return Some(Alias {
                    name,
                    decoder: decoder?,
                    fields,
                    end: j + 1,
                });
            }
            _ => return None,
        }
        if fields.len() > 32 {
            return None;
        }
    }
}

#[derive(Clone)]
enum Binding {
    Unknown,
    Decoder,
    Alias(HashMap<String, f64>),
}
#[derive(Default)]
struct Scope {
    parent: Option<usize>,
    pending_do: bool,
    bindings: HashMap<String, Vec<(usize, Binding)>>,
}

fn bind(scopes: &mut [Scope], scope: usize, name: &str, at: usize, value: Binding) {
    scopes[scope]
        .bindings
        .entry(name.into())
        .or_default()
        .push((at, value));
}
fn resolve<'a>(
    scopes: &'a [Scope],
    mut scope: usize,
    name: &str,
    at: usize,
) -> Option<(usize, usize, &'a Binding)> {
    loop {
        if let Some(entries) = scopes[scope].bindings.get(name) {
            if let Some((decl, binding)) = entries
                .iter()
                .filter(|(pos, _)| *pos <= at)
                .max_by_key(|(pos, _)| pos)
            {
                return Some((scope, *decl, binding));
            }
        }
        scope = scopes[scope].parent?;
    }
}

// Block scopes and parameter/local bindings prevent replacing lookalike calls in
// comments, strings, or functions that shadow a decoder alias.
fn scopes(t: &[&str]) -> (Vec<Scope>, Vec<usize>) {
    let mut scopes = vec![Scope::default()];
    let mut positions = Vec::with_capacity(t.len());
    let mut current = 0;
    for (i, token) in t.iter().enumerate() {
        positions.push(current);
        match *token {
            "function" | "if" | "for" | "while" | "repeat" => {
                let id = scopes.len();
                scopes.push(Scope {
                    parent: Some(current),
                    pending_do: matches!(*token, "for" | "while"),
                    ..Scope::default()
                });
                current = id;
                if *token == "function" {
                    if let Some(open) = (i + 1..(i + 5).min(t.len())).find(|&j| t[j] == "(") {
                        for &param in &t[open + 1..] {
                            if param == ")" {
                                break;
                            }
                            if param != "," && param != "." {
                                bind(&mut scopes, current, param, i, Binding::Unknown);
                            }
                        }
                    }
                } else if *token == "for" {
                    for &name in &t[i + 1..] {
                        if matches!(name, "=" | "in") {
                            break;
                        }
                        if name != "," {
                            bind(&mut scopes, current, name, usize::MAX, Binding::Unknown);
                        }
                    }
                }
            }
            "do" if scopes[current].pending_do => {
                scopes[current].pending_do = false;
                for entries in scopes[current].bindings.values_mut() {
                    for (at, _) in entries {
                        if *at == usize::MAX {
                            *at = i;
                        }
                    }
                }
            }
            "do" => {
                let id = scopes.len();
                scopes.push(Scope {
                    parent: Some(current),
                    ..Scope::default()
                });
                current = id;
            }
            "else" | "elseif" => {
                let parent = scopes[current].parent;
                let id = scopes.len();
                scopes.push(Scope {
                    parent,
                    ..Scope::default()
                });
                current = id;
            }
            "end" | "until" => current = scopes[current].parent.unwrap_or(0),
            "local" => {
                let mut j = i + 1;
                if t.get(j) == Some(&"function") {
                    j += 1;
                }
                loop {
                    if let Some(name) = t.get(j) {
                        bind(&mut scopes, current, name, i, Binding::Unknown);
                    }
                    if t.get(j + 1) != Some(&",") {
                        break;
                    }
                    j += 2;
                }
            }
            _ => {}
        }
    }
    (scopes, positions)
}

fn member_call(t: &[&str], i: usize) -> Option<(usize, usize, usize)> {
    if i > 0 && t[i - 1] == "function" {
        return None;
    }
    let result = if t.get(i + 1) == Some(&".") && t.get(i + 3) == Some(&"(") {
        (i + 2, i + 3, i)
    } else if i > 0
        && t[i - 1] == "("
        && t.get(i + 1..i + 3) == Some(&[")", "."][..])
        && t.get(i + 4) == Some(&"(")
    {
        (i + 3, i + 4, i - 1)
    } else {
        return None;
    };
    let start = result.2;
    let property = start > 0
        && (t[start - 1] == ":" || (t[start - 1] == "." && (start < 2 || t[start - 2] != ".")));
    (!property).then_some(result)
}

fn normalized(source: &str) -> Result<String, String> {
    let tokens = crate::lex(source)?;
    let mut out = source.to_string();
    for t in tokens.iter().rev().filter(|t| t.kind == "number") {
        out.replace_range(t.start..t.end, &source[t.start..t.end].replace('_', ""));
    }
    Ok(out)
}

fn constant(lua: &mlua::Lua, source: &str, tokens: &[crate::Token]) -> Option<f64> {
    if tokens.is_empty()
        || tokens.len() > 256
        || tokens.iter().any(|t| {
            t.kind != "number"
                && !(t.kind == "punct"
                    && matches!(
                        &source[t.start..t.end],
                        "+" | "-" | "*" | "/" | "%" | "^" | "(" | ")" | "."
                    ))
        })
    {
        return None;
    }
    let expression = normalized(&source[tokens.first()?.start..tokens.last()?.end]).ok()?;
    let value = match lua
        .load(format!("return ({expression})"))
        .eval::<Value>()
        .ok()?
    {
        Value::Number(n) => n,
        Value::Integer(n) => n as f64,
        _ => return None,
    };
    (value.is_finite() && value.fract() == 0. && value.abs() <= 9_007_199_254_740_991.)
        .then_some(value)
}

pub fn recover(source: &str) -> Result<(String, serde_json::Value), String> {
    let head: String = source.chars().take(200).collect();
    let version = if head.contains("Voltfuscator v7.5 - https://dsc.gg/Obfuscating") {
        "7.5"
    } else if head.contains("Voltfuscator v7.6 - https://dsc.gg/Obfuscating") {
        "7.6"
    } else {
        return Err("Unsupported legacy Voltfuscator banner".into());
    };
    if source.len() > 16 * 1024 * 1024 {
        return Err("Unsupported legacy input over 16 MiB".into());
    }
    let tokens = crate::lex(source)?;
    let t: Vec<&str> = tokens.iter().map(|t| &source[t.start..t.end]).collect();
    let start = (0..t.len().saturating_sub(3))
        .find(|&i| {
            t[i] == "local"
                && t[i + 2] == "="
                && tokens[i + 3].kind == "string"
                && t[i + 3].starts_with('[')
        })
        .ok_or("Unsupported legacy decoder: missing packed string setup")?;
    let (alias_at, first) = (start..t.len())
        .find_map(|i| alias(&t, i).map(|a| (i, a)))
        .ok_or("Unsupported legacy decoder: missing verified forwarding table")?;
    let end = first.end;
    if t.get(end..end + 3) != Some(&["return", "(", "function"][..]) {
        return Err("Unsupported legacy decoder application boundary".into());
    }
    let slice_start = tokens[start].start;
    let slice_end = tokens[end - 1].end;
    let helper = &source[slice_start..slice_end];
    let hash = format!("{:x}", Sha256::digest(helper.as_bytes()));
    let prefix_hash = format!("{:x}", Sha256::digest(source[..slice_end].as_bytes()));
    // shortcut: only reviewed corpus slices are admitted; inspect and register new
    // decoder slices before extending this list, never execute an unknown prefix.
    if !VERIFIED_PREFIXES.contains(&prefix_hash.as_str()) {
        return Err(format!(
            "Unsupported legacy decoder: no verified pure slice/prefix for SHA-256 {prefix_hash}"
        ));
    }
    if t[end..].contains(&"repeat") {
        return Err(
            "Unsupported legacy application: repeat/until alias scopes need inspection".into(),
        );
    }
    let lua = crate::vm::restricted_lua().map_err(|e| e.to_string())?;
    let decoder: Function = lua
        .load(format!("{}\nreturn {}", normalized(helper)?, first.decoder))
        .eval()
        .map_err(|e| format!("Verified legacy decoder setup failed: {e}"))?;
    let (mut scopes, positions) = scopes(&t);
    let root = positions[start];
    let decoder_at = (start..alias_at)
        .rev()
        .find(|&i| {
            t[i] == "local"
                && t.get(i + 1) == Some(&"function")
                && t.get(i + 2) == Some(&first.decoder.as_str())
                && positions[i] == root
        })
        .ok_or("Missing verified legacy decoder binding")?;
    bind(
        &mut scopes,
        root,
        &first.decoder,
        decoder_at,
        Binding::Decoder,
    );
    let mut alias_count = 0;
    let mut forwarding_ranges = Vec::new();
    for i in alias_at..t.len() {
        if let Some(a) = alias(&t, i) {
            if a.decoder == first.decoder
                && matches!(
                    resolve(&scopes, positions[i], &a.decoder, i),
                    Some((_, _, Binding::Decoder))
                )
            {
                bind(
                    &mut scopes,
                    positions[i],
                    &a.name,
                    i,
                    Binding::Alias(a.fields),
                );
                forwarding_ranges.push(i..a.end);
                alias_count += 1;
            }
        }
    }
    // An alias must remain private and immutable. A table/closure that escapes,
    // is reassigned, or has a member replaced cannot safely be constant-folded.
    let mut invalid = HashSet::new();
    let mut unsafe_references = Vec::new();
    let mut braces = Vec::new();
    let mut field_keys = HashSet::new();
    for i in 0..t.len() {
        if t[i] == "for" {
            let mut j = i + 1;
            while j < t.len() && !matches!(t[j], "=" | "in") {
                if t[j] != "," {
                    field_keys.insert(j);
                }
                j += 1;
            }
        }
        match t[i] {
            "{" => braces.push(positions[i]),
            "}" => {
                braces.pop();
            }
            _ if t.get(i + 1) == Some(&"=")
                && braces.last() == Some(&positions[i])
                && i > 0
                && matches!(t[i - 1], "{" | "," | ";") =>
            {
                field_keys.insert(i);
            }
            _ => {}
        }
    }
    for i in end..t.len() {
        if t[i] != "local" || i == 0 {
            continue;
        }
        let mut j = i + 1;
        let mut names = Vec::new();
        while j < t.len() {
            names.push(t[j]);
            if t.get(j + 1) != Some(&",") {
                break;
            }
            j += 2;
        }
        if t.get(j + 1) != Some(&"=") || forwarding_ranges.iter().any(|r| r.start == i) {
            continue;
        }
        for name in names {
            match resolve(&scopes, positions[i], name, i - 1) {
                Some((scope, decl, Binding::Alias(_))) => {
                    if invalid.insert((scope, decl)) {
                        unsafe_references.push(json!({"alias": name, "offset": tokens[i].start}));
                    }
                }
                Some((_, _, Binding::Decoder)) => return Err(
                    "Unsupported legacy application: decoder shadow initializer needs inspection"
                        .into(),
                ),
                _ => {}
            }
        }
    }
    for i in end..t.len() {
        let property =
            i > 0 && (t[i - 1] == ":" || (t[i - 1] == "." && (i < 2 || t[i - 2] != ".")));
        if tokens[i].kind != "ident" || field_keys.contains(&i) || property {
            continue;
        }
        let Some((scope, decl, binding)) = resolve(&scopes, positions[i], t[i], i) else {
            continue;
        };
        match binding {
            Binding::Alias(_) if i != decl + 1 && member_call(&t, i).is_none() => {
                if invalid.insert((scope, decl)) {
                    unsafe_references.push(json!({"alias": t[i], "offset": tokens[i].start}));
                }
            }
            Binding::Decoder if !forwarding_ranges.iter().any(|r| r.contains(&i)) => {
                return Err(format!(
                    "Unsupported legacy application: decoder binding escapes or changes at byte {}",
                    tokens[i].start
                ));
            }
            _ => {}
        }
    }
    let mut replacements = Vec::new();
    let (mut dynamic, mut rejected, mut admissions) = (0usize, 0usize, 0usize);
    for i in end..t.len() {
        let Some((member, open, call_start)) = member_call(&t, i) else {
            continue;
        };
        let Some((scope, decl, Binding::Alias(fields))) = resolve(&scopes, positions[i], t[i], i)
        else {
            continue;
        };
        if invalid.contains(&(scope, decl)) {
            continue;
        }
        let Some(&offset) = fields.get(t[member]) else {
            continue;
        };
        let mut depth = 1;
        let mut args = Vec::new();
        let mut arg = open + 1;
        let mut close = None;
        for j in open + 1..t.len().min(open + 1024) {
            match t[j] {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    if depth == 0 {
                        args.push(arg..j);
                        close = Some(j);
                        break;
                    }
                }
                "," if depth == 1 => {
                    args.push(arg..j);
                    arg = j + 1;
                }
                _ => {}
            }
        }
        if args.len() != 3 || close.is_none() {
            dynamic += 1;
            continue;
        }
        let values: Option<Vec<f64>> = args
            .iter()
            .map(|r| constant(&lua, source, &tokens[r.clone()]))
            .collect();
        let Some(values) = values else {
            dynamic += 1;
            continue;
        };
        let value = decoder
            .call::<Value>((values[0] + offset, values[1], values[2]))
            .map_err(|e| format!("Legacy string decoder failed: {e}"))?;
        match value {
            Value::String(value) => replacements.push((
                tokens[call_start].start,
                tokens[close.unwrap()].end,
                crate::lua_string(&value.as_bytes()),
            )),
            Value::Boolean(_) => admissions += 1,
            _ => rejected += 1,
        }
    }
    if replacements.is_empty() {
        return Err(format!(
            "Unsupported legacy application: no verified constant string calls ({dynamic} dynamic, {rejected} rejected; unsafe aliases {unsafe_references:?})"
        ));
    }
    let mut output = source.to_string();
    for (start, end, value) in replacements.iter().rev() {
        output.replace_range(*start..*end, value);
    }
    Ok((
        output,
        json!({
            "status": "partial", "format": format!("legacy-{version}"), "version": version,
            "recovered_layers": ["authenticated legacy string decoder calls"],
            "replaced_calls": replacements.len(), "alias_tables": alias_count,
            "unsafe_alias_tables_preserved": invalid.len(),
            "unsafe_alias_references": unsafe_references,
            "dynamic_calls": dynamic, "rejected_constant_calls": rejected, "admission_calls_preserved": admissions,
            "decoder_slice_sha256": hash, "decoder_slice_start": slice_start, "decoder_slice_end": slice_end,
            "decoder_prefix_sha256": prefix_hash,
            "validation": "Exact reviewed decoder slice; original record admission/resolve checks; bounded no-host runtime",
            "unresolved": ["Application VM remains", "Dynamic decoder calls and all wrapper side effects are preserved"],
        }),
    ))
}
