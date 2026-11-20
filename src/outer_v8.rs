//! Checksum-validated outer strings for the inspected v8.0 decoder family.
//! This deliberately retains the admission wrapper and the application VM.
use crate::{Token, ascii85, lex, long_value, lua_string, number};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

// Match the entire helper, with bijective identifier renaming and numeric slots.
// A changed operation must fail recognition before any constants are replaced.
const HELPER: &str = r#"
factory=function(XX)local XB;local Xe;do
local Xo=("")["byte"];local Xz=("")["char"];local Xs=("")["sub"];local Xr=("")["gsub"];local XA=error;
local XE,Xd;local XY={};local Xu={};local XF=0;
XB=function(Xm)local XC=XY[Xm];if XC~=nil then return XC end;
local Xj=(Xm+p_salt+(Xe or 0))%65521;local XV=(Xm+p_salt+(Xe or 0))%2147483647;
local Xc=0;local function Xk(Xn)Xj=(Xj*p_mult+p_add+Xc)%65521;Xc+=1;
local Xf=(Xn-Xj%256)%256;Xj=(Xj+Xn)%65521;
if Xc<=4 or Xc>8 then XV=(XV*33+Xf)%2147483647 end;return Xf end;
local Xx=XE[Xm];local Xi=Xx%p_stride;local Xg=(Xx-Xi)/p_stride+1;
local XW=Xr(Xs(Xd,Xg,Xg+Xi-1),".....",function(Xt)
local XH,Xy,Xv,XN,Xa=Xo(Xt,1,5);
local Xb=((((XH-33)*85+Xy-33)*85+Xv-33)*85+XN-33)*85+Xa-33;
local XP=Xb%16777216;local Xp=Xb%65536;local XU=Xb%256;
local XI=Xk((Xb-XP)/16777216);local XS=Xk((XP-Xp)/65536);local XD=Xk((Xp-XU)/256);local XO=Xk(XU);
return Xz(XI,XS,XD,XO)end);
local XL,XR,XM,XT=Xo(XW,1,4);local Xl=XL+XR*256+XM*65536+XT*16777216;
local XZ,Xq,Xh,XQ=Xo(XW,5,8);
if not XQ or Xc~=#XW or Xl>#XW-8 or#XW-8-Xl>3 or XV~=XZ+Xq*256+Xh*65536+XQ*16777216 then XA("Voltfuscator: C052",0)end;
XW=Xs(XW,9,Xl+8);if Xl<=64 then XF=XF%256+1;local Xw=Xu[XF];if Xw then XY[Xw]=nil end;Xu[XF]=Xm;XY[Xm]=XW end;return XW end;
XE={};do local XK=XX.indexfield;if#XK~=p_indexlen then XA("Voltfuscator: C052",0)end;
local XG,BX,BB,Be,Bo=0,1,0,0,5381;local Bz;
for Bs=1,#XK do local Br=Xo(XK,Bs);Bo=(Bo*33+Br)%2147483647;
local BA=((Br-33-p_shift)*p_inverse)%84;XG=XG+(BA%42)*BX;
if XG>2147483646 or BX>2147483647 then XA("Voltfuscator: C052",0)end;
if BA>=42 then BX=BX*42 else if XG<1 then XA("Voltfuscator: C052",0)end;
if Bz then if XG<10 or XG%5~=0 or XG>=p_stride or BB+XG>p_poollen or XE[Bz]~=nil then XA("Voltfuscator: C052",0)end;
XE[Bz]=BB*p_stride+XG;BB=BB+XG;Be=Be+1;Bz=nil else Bz=XG end;XG,BX=0,1 end end;
if Bz~=nil or BX~=1 or XG~=0 or Be~=p_count or BB~=p_poollen or Bo~=p_indexhash then XA("Voltfuscator: C052",0)end end;
Xd=XX.poolfield;if#Xd~=p_poollen then XA("Voltfuscator: C052",0)end;
return XB,function(BE)Xe=BE end end end
"#;

struct Text<'a> {
    source: &'a str,
    tokens: Vec<Token>,
}

impl<'a> Text<'a> {
    fn new(source: &'a str) -> Result<Self, String> {
        Ok(Self {
            source,
            tokens: lex(source)?,
        })
    }
    fn at(&self, i: usize) -> &str {
        self.tokens
            .get(i)
            .map(|t| &self.source[t.start..t.end])
            .unwrap_or("")
    }
    fn num(&self, i: usize) -> Result<u64, String> {
        number(self.at(i))
    }
    fn ident(&self, i: usize) -> bool {
        self.tokens.get(i).is_some_and(|t| t.kind == "ident") && !keyword(self.at(i))
    }
}

fn keyword(s: &str) -> bool {
    matches!(
        s,
        "and"
            | "break"
            | "do"
            | "else"
            | "elseif"
            | "end"
            | "false"
            | "for"
            | "function"
            | "if"
            | "in"
            | "local"
            | "nil"
            | "not"
            | "or"
            | "repeat"
            | "return"
            | "then"
            | "true"
            | "until"
            | "while"
            | "continue"
            | "error"
    )
}

#[derive(Default)]
struct Match<'a> {
    names: HashMap<&'a str, &'a str>,
    numbers: HashMap<&'a str, u64>,
}

fn match_at<'a>(text: &'a Text<'a>, i: usize, pattern: &'a Text<'a>) -> Option<Match<'a>> {
    let mut found = Match::default();
    let mut used = HashSet::new();
    for j in 0..pattern.tokens.len() {
        let p = pattern.at(j);
        let s = text.at(i + j);
        if p.starts_with("p_") && pattern.tokens[j].kind == "ident" {
            let n = text.num(i + j).ok()?;
            if n > 2147483647 || found.numbers.insert(p, n).is_some_and(|old| old != n) {
                return None;
            }
        } else if pattern.tokens[j].kind == "number" {
            if pattern.num(j).ok()? != text.num(i + j).ok()? {
                return None;
            }
        } else if pattern.ident(j) {
            if !text.ident(i + j) {
                return None;
            }
            if let Some(old) = found.names.get(p) {
                if *old != s {
                    return None;
                }
            } else {
                if !used.insert(s) {
                    return None;
                }
                found.names.insert(p, s);
            }
        } else if p != s {
            return None;
        }
    }
    Some(found)
}

#[derive(Debug)]
struct Function {
    start: usize,
    body: usize,
    end: usize,
    params: Vec<String>,
}

fn functions(text: &Text<'_>) -> Result<Vec<Function>, String> {
    let mut result = Vec::new();
    // Function index, or None for other blocks; loop headers consume their own do.
    let mut stack: Vec<(&str, Option<usize>)> = Vec::new();
    for i in 0..text.tokens.len() {
        if text.tokens[i].kind != "ident" {
            continue;
        }
        match text.at(i) {
            "function" => {
                let open = (i + 1..text.tokens.len())
                    .find(|&j| text.at(j) == "(")
                    .ok_or("Missing function parameters")?;
                let close = (open + 1..text.tokens.len())
                    .find(|&j| text.at(j) == ")")
                    .ok_or("Unclosed function parameters")?;
                let params = (open + 1..close)
                    .filter(|&j| text.ident(j))
                    .map(|j| text.at(j).to_owned())
                    .collect();
                stack.push(("end", Some(result.len())));
                result.push(Function {
                    start: i,
                    body: close + 1,
                    end: 0,
                    params,
                });
            }
            "if" => stack.push(("end", None)),
            "for" | "while" => stack.push(("loop", None)),
            "do" => {
                if stack.last().is_some_and(|x| x.0 == "loop") {
                    stack.last_mut().unwrap().0 = "end";
                } else {
                    stack.push(("end", None));
                }
            }
            "repeat" => stack.push(("until", None)),
            "end" | "until" => {
                let (kind, function) = stack.pop().ok_or("Unbalanced source blocks")?;
                if kind != text.at(i) {
                    return Err("Unexpected source block terminator".into());
                }
                if let Some(n) = function {
                    result[n].end = i;
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err("Unclosed source block".into());
    }
    Ok(result)
}

fn field_value<'a>(text: &'a Text<'a>, field: &str) -> Result<&'a str, String> {
    let hits: Vec<_> = (0..text.tokens.len())
        .filter(|&i| {
            text.at(i) == field
                && text.at(i + 1) == "="
                && text.tokens.get(i + 2).is_some_and(|t| t.kind == "string")
        })
        .collect();
    if hits.len() != 1 {
        return Err(format!("Expected exactly one long-string field {field}"));
    }
    let literal = text.at(hits[0] + 2);
    if !literal.starts_with('[') {
        return Err(format!("Field {field} is not a long string"));
    }
    let value = long_value(literal)?;
    // Lua discards one initial newline in a long-bracket literal.
    Ok(value
        .strip_prefix("\r\n")
        .or_else(|| value.strip_prefix('\n'))
        .or_else(|| value.strip_prefix('\r'))
        .unwrap_or(value))
}

#[derive(Debug)]
struct Record {
    id: u64,
    offset: usize,
    len: usize,
    seed: u64,
    plain: Vec<u8>,
}

fn read_index(index: &str, p: &HashMap<&str, u64>) -> Result<Vec<Record>, String> {
    let hash = index
        .bytes()
        .fold(5381u64, |h, b| (h * 33 + u64::from(b)) % 2147483647);
    if index.len() as u64 != p["p_indexlen"] || hash != p["p_indexhash"] {
        return Err("Outer index length/checksum mismatch".into());
    }
    let (mut value, mut place, mut offset) = (0u64, 1u64, 0usize);
    let mut pending = None;
    let mut ids = HashSet::new();
    let mut records = Vec::new();
    for b in index.bytes() {
        if !(33..=116).contains(&b) {
            return Err("Invalid outer index digit".into());
        }
        let digit = ((i64::from(b) - 33 - p["p_shift"] as i64) * p["p_inverse"] as i64)
            .rem_euclid(84) as u64;
        value = value
            .checked_add(
                (digit % 42)
                    .checked_mul(place)
                    .ok_or("Outer index overflow")?,
            )
            .ok_or("Outer index overflow")?;
        if value > 2147483646 || place > 2147483647 {
            return Err("Outer index overflow".into());
        }
        if digit >= 42 {
            place = place.checked_mul(42).ok_or("Outer index overflow")?;
        } else {
            if value == 0 {
                return Err("Zero outer index value".into());
            }
            if let Some(id) = pending.take() {
                if value < 10
                    || value >= p["p_stride"]
                    || value % 5 != 0
                    || offset as u64 + value > p["p_poollen"]
                    || !ids.insert(id)
                {
                    return Err("Invalid outer pool record".into());
                }
                records.push(Record {
                    id,
                    offset,
                    len: value as usize,
                    seed: 0,
                    plain: Vec::new(),
                });
                offset += value as usize;
            } else {
                pending = Some(value);
            }
            value = 0;
            place = 1;
        }
    }
    if pending.is_some()
        || place != 1
        || value != 0
        || records.len() as u64 != p["p_count"]
        || offset as u64 != p["p_poollen"]
    {
        return Err("Truncated/inconsistent outer index".into());
    }
    Ok(records)
}

fn decrypt(id: u64, seed: u64, cipher: &[u8], p: &HashMap<&str, u64>) -> Result<Vec<u8>, String> {
    let mut state = (id + p["p_salt"] + seed) % 65521;
    let mut checksum = (id + p["p_salt"] + seed) % 2147483647;
    let mut plain = Vec::with_capacity(cipher.len());
    for (i, &b) in cipher.iter().enumerate() {
        state = (state * p["p_mult"] + p["p_add"] + i as u64) % 65521;
        let v = (i64::from(b) - (state % 256) as i64).rem_euclid(256) as u8;
        state = (state + u64::from(b)) % 65521;
        if i < 4 || i >= 8 {
            checksum = (checksum * 33 + u64::from(v)) % 2147483647;
        }
        plain.push(v);
    }
    if plain.len() < 8 {
        return Err("Truncated outer record".into());
    }
    let len = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
    let expected = u64::from(u32::from_le_bytes(plain[4..8].try_into().unwrap()));
    if len > plain.len() - 8 || plain.len() - 8 - len > 3 || checksum != expected {
        return Err(format!(
            "Outer record {id} failed length/checksum at seed {seed}"
        ));
    }
    Ok(plain[8..8 + len].to_vec())
}

fn admission_seed(text: &Text<'_>, f: &Function) -> Result<u64, String> {
    let mut first = Vec::new();
    let mut second = Vec::new();
    for i in f.body..f.end {
        if text.at(i) == "return" && text.ident(i + 1) && text.at(i + 2) == "," {
            if text.ident(i + 3)
                && text.at(i + 4) == "and"
                && text.at(i + 6) == "or"
                && text.num(i + 7) == Ok(0)
            {
                if let Ok(n) = text.num(i + 5) {
                    first.push(n);
                }
            }
            if text.at(i + 4) == "+" && text.ident(i + 5) && text.at(i + 6) == "end" {
                if let Ok(n) = text.num(i + 3) {
                    second.push(n);
                }
            }
        }
    }
    if first.len() != 1 || second != first || first[0] > 65535 {
        return Err("Unrecognized v8 admission seed derivation".into());
    }
    Ok(first[0] * first[0])
}

fn check_alias(
    text: &Text<'_>,
    functions: &[Function],
    f: &Function,
    alias: &str,
    allowed_binding: Option<usize>,
) -> Result<(), String> {
    // shortcut: reject shadowing/mutation instead of resolving arbitrary Lua dataflow; add lexical binding analysis for new builds that need it.
    for nested in functions
        .iter()
        .filter(|n| n.start >= f.body && n.end < f.end)
    {
        if nested.params.iter().any(|p| p == alias) {
            return Err(format!("Shadowed outer decoder {alias}"));
        }
    }
    for i in f.body..f.end {
        if matches!(text.at(i), "local" | "for") {
            let mut j = i + 1;
            if text.at(j) == "function" {
                j += 1;
            }
            loop {
                if text.at(j) == alias && Some(j) != allowed_binding {
                    return Err(format!("Shadowed outer decoder {alias}"));
                }
                if !text.ident(j) || text.at(j + 1) != "," {
                    break;
                }
                j += 2;
            }
        }
        if text.at(i) == alias
            && Some(i) != allowed_binding
            && !matches!(text.at(i.saturating_sub(1)), "." | ":")
        {
            let mut end = i;
            while text.at(end + 1) == "," && text.ident(end + 2) {
                end += 2;
            }
            if (text.at(end + 1) == "=" && text.at(end + 2) != "=")
                || (matches!(text.at(i + 1), "+" | "-" | "*" | "/" | "%" | "^")
                    && text.at(i + 2) == "=")
                || text.at(i.saturating_sub(1)) == "function"
            {
                return Err(format!("Mutated outer decoder {alias}"));
            }
        }
    }
    Ok(())
}

pub fn recover(source: &str) -> Result<(String, Value), String> {
    if source.len() > 64 * 1024 * 1024 {
        return Err("v8 source exceeds 64 MiB limit".into());
    }
    let bom = source.starts_with('\u{feff}');
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let text = Text::new(source)?;
    let pattern = Text::new(HELPER)?;
    let mut candidates = Vec::new();
    for i in 0..text.tokens.len() {
        if text.ident(i)
            && text.at(i + 1) == "="
            && text.at(i + 2) == "function"
            && text.at(i + 5) == ")"
            && text.at(i + 6) == "local"
        {
            if let Some(m) = match_at(&text, i, &pattern) {
                candidates.push((i, m));
            }
        }
    }
    if candidates.len() != 1 {
        return Err(format!(
            "Expected one validated v8 outer helper, found {}",
            candidates.len()
        ));
    }
    let (helper_start, matched) = candidates.pop().unwrap();
    let p = &matched.numbers;
    if p["p_poollen"] > 16 * 1024 * 1024 || p["p_stride"] < 11 || p["p_count"] == 0 {
        return Err("Invalid/bounded v8 parameters".into());
    }
    let indexfield = matched.names["indexfield"];
    let poolfield = matched.names["poolfield"];
    let index = field_value(&text, indexfield)?;
    let pool = field_value(&text, poolfield)?;
    if pool.len() as u64 != p["p_poollen"] {
        return Err("Outer pool length mismatch".into());
    }
    let mut records = read_index(index, p)?;
    let functions = functions(&text)?;
    let wiring = Text::new(
        "local boot,setter=receiver:factory();local app,update=receiver:application(boot,env);",
    )?;
    let mut wirings = Vec::new();
    for i in 0..text.tokens.len() {
        if text.at(i) == "local" && text.at(i + 2) == "," && text.at(i + 4) == "=" {
            if let Some(m) = match_at(&text, i, &wiring) {
                if m.names["factory"] == matched.names["factory"] {
                    wirings.push((i, m));
                }
            }
        }
    }
    if wirings.len() != 1 {
        return Err("Expected one v8 factory/application wiring".into());
    }
    let (wire_start, wire) = wirings.pop().unwrap();
    let bootstrap = functions
        .iter()
        .filter(|f| f.body <= wire_start && f.end > wire_start)
        .min_by_key(|f| f.end - f.start)
        .ok_or("Missing v8 bootstrap function")?;
    let apps: Vec<_> = functions
        .iter()
        .filter(|f| {
            f.start >= 2
                && text.at(f.start - 1) == "="
                && text.at(f.start - 2) == wire.names["application"]
        })
        .collect();
    if apps.len() != 1 || apps[0].params.len() != 3 {
        return Err("Unrecognized v8 application factory parameters".into());
    }
    let app = apps[0];
    let app_alias = &app.params[1];
    let boot_alias = wire.names["boot"];
    let seed = admission_seed(&text, bootstrap)?;
    let mut by_id = BTreeMap::new();
    let mut seed_counts = BTreeMap::new();
    for (n, record) in records.iter_mut().enumerate() {
        let encoded = pool
            .as_bytes()
            .get(record.offset..record.offset + record.len)
            .ok_or("Outer record beyond pool")?;
        let cipher = ascii85(encoded)?;
        let mut valid = Vec::new();
        for candidate in [0, seed] {
            if let Ok(plain) = decrypt(record.id, candidate, &cipher, p) {
                valid.push((candidate, plain));
            }
        }
        if valid.len() != 1 {
            return Err(format!(
                "Outer record {} has {} valid seed candidates",
                record.id,
                valid.len()
            ));
        }
        (record.seed, record.plain) = valid.pop().unwrap();
        *seed_counts.entry(record.seed).or_insert(0usize) += 1;
        by_id.insert(record.id, n);
    }
    check_alias(&text, &functions, app, app_alias, None)?;
    check_alias(
        &text,
        &functions,
        bootstrap,
        boot_alias,
        Some(wire_start + 1),
    )?;
    let admission =
        Text::new("if result==false then return end;setter(result);update(env);return")?;
    let transitions: Vec<_> = (bootstrap.body..bootstrap.end)
        .filter_map(|i| {
            let m = match_at(&text, i, &admission)?;
            (m.names["setter"] == wire.names["setter"]
                && m.names["update"] == wire.names["update"]
                && m.names["env"] == wire.names["env"])
                .then_some(i)
        })
        .collect();
    if transitions.len() != 1 {
        return Err("Unrecognized v8 seed transition".into());
    }
    if (bootstrap.body..bootstrap.end)
        .filter(|&i| {
            text.at(i) == wire.names["setter"] && !matches!(text.at(i.saturating_sub(1)), "." | ":")
        })
        .count()
        != 2
    {
        return Err("Unexpected v8 seed setter reference".into());
    }
    let transition = transitions[0] + admission.tokens.len();
    let mut replacements = Vec::new();
    let mut unresolved = 0usize;
    let mut bootstrap_calls = 0usize;
    let mut application_calls = 0usize;
    let helper_end = helper_start + pattern.tokens.len();
    for (f, alias, is_app) in [(bootstrap, boot_alias, false), (app, app_alias, true)] {
        for i in f.body..f.end {
            if text.at(i) != alias
                || text.at(i + 1) != "("
                || matches!(text.at(i.saturating_sub(1)), "." | ":")
                || (helper_start..helper_end).contains(&i)
            {
                continue;
            }
            if text.at(i + 3) != ")" || text.tokens.get(i + 2).is_none_or(|t| t.kind != "number") {
                unresolved += 1;
                continue;
            }
            let id = text.num(i + 2)?;
            let record = by_id
                .get(&id)
                .map(|&n| &records[n])
                .ok_or_else(|| format!("Unknown outer decoder identifier {id}"))?;
            let expected_seed = if is_app || i >= transition { seed } else { 0 };
            if record.seed != expected_seed {
                return Err(format!(
                    "Outer call {alias}({id}) uses the wrong seed phase"
                ));
            }
            replacements.push((
                text.tokens[i].start,
                text.tokens[i + 3].end,
                lua_string(&record.plain),
            ));
            if is_app {
                application_calls += 1;
            } else {
                bootstrap_calls += 1;
            }
        }
    }
    replacements.sort_by_key(|r| r.0);
    if replacements.windows(2).any(|r| r[0].1 > r[1].0) {
        return Err("Overlapping outer replacements".into());
    }
    let mut output = String::with_capacity(source.len());
    if bom {
        output.push('\u{feff}');
    }
    let mut cursor = 0;
    for (start, end, value) in &replacements {
        output.push_str(&source[cursor..*start]);
        output.push_str(value);
        cursor = *end;
    }
    output.push_str(&source[cursor..]);
    let stats = json!({
        "status":"partial", "stage":"v8_outer_strings", "index_field":indexfield,"pool_field":poolfield,
        "factory":matched.names["factory"],"decoder":matched.names["XB"],"bootstrap_decoder":boot_alias,"application_decoder":app_alias,
        "parameters":p,"application_seed":seed,"records_validated":records.len(),"records_by_seed":seed_counts,
        "calls_replaced":replacements.len(),"bootstrap_calls_replaced":bootstrap_calls,"application_calls_replaced":application_calls,
        "dynamic_calls_retained":unresolved,"helper_byte_start":text.tokens[helper_start].start+if bom {3}else{0},"helper_byte_end":text.tokens[helper_end-1].end+if bom {3}else{0},
        "records":records.iter().map(|r|json!({"id":r.id,"offset":r.offset,"encoded_length":r.len,"seed":r.seed,"decoded_bytes":r.plain})).collect::<Vec<_>>(),
        "unresolved":["Application VM, inner strings, admission checks, and wrapper remain; full devirtualization was not performed."]
    });
    Ok((output, stats))
}
