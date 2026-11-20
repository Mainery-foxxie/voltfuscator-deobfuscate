//! Conservative outer-string recovery; the VM and application wrapper remain intact.
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone)]
struct Atom {
    text: String,
    kind: &'static str,
    start: usize,
    end: usize,
}

fn atoms(source: &str) -> Result<Vec<Atom>, String> {
    let mut out = Vec::new();
    for token in crate::lex(source)? {
        let raw = &source[token.start..token.end];
        if raw == ";" {
            continue;
        }
        out.push(Atom {
            text: if token.kind == "number" {
                crate::number(raw)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| raw.into())
            } else {
                raw.into()
            },
            kind: token.kind,
            start: token.start,
            end: token.end,
        });
    }
    // Luau compound increments and ordinary assignments express the same inspected recurrence.
    let mut i = 0;
    while i + 3 < out.len() {
        if out[i].kind == "ident" && out[i + 1].text == "+" && out[i + 2].text == "=" {
            let mut name = out[i].clone();
            let mut plus = out[i + 1].clone();
            name.start = out[i + 1].start;
            name.end = out[i + 2].end;
            plus.start = name.start;
            plus.end = name.end;
            out[i + 1].text = "=".into();
            out.splice(i + 2..i + 3, [name, plus]);
        }
        i += 1;
    }
    Ok(out)
}

fn string_value(lua: &mlua::Lua, atom: &Atom) -> Result<Vec<u8>, String> {
    if atom.kind != "string" {
        return Err("Expected literal string".into());
    }
    // The lexer has established exactly one quoted/long literal: no sample statements run.
    let value: mlua::LuaString = lua
        .load(format!("return {}", atom.text))
        .eval()
        .map_err(|e| e.to_string())?;
    Ok(value.as_bytes().to_vec())
}

fn fixed(name: &str) -> bool {
    matches!(
        name,
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
            | "error"
            | "type"
            | "pcall"
            | "select"
            | "debug"
            | "string"
    )
}

#[derive(Default, Clone)]
struct Match {
    names: HashMap<String, String>,
    numbers: HashMap<String, u64>,
    pool: Option<Atom>,
    start: usize,
    end: usize,
}

fn match_at(
    lua: &mlua::Lua,
    template: &[Atom],
    input: &[Atom],
    start: usize,
    mut found: Match,
) -> Option<Match> {
    let slice = input.get(start..start + template.len())?;
    for (i, (want, got)) in template.iter().zip(slice).enumerate() {
        if matches!(
            want.text.as_str(),
            "SALT" | "MUL" | "ADD" | "KEY" | "HOSTKEY"
        ) {
            if got.kind != "number" {
                return None;
            }
            let n = crate::number(&got.text).ok()?;
            if found
                .numbers
                .insert(want.text.clone(), n)
                .is_some_and(|old| old != n)
            {
                return None;
            }
        } else if want.text == "POOL" {
            if got.kind != "string" {
                return None;
            }
            found.pool = Some(got.clone());
        } else if want.kind == "string" && got.kind == "string" {
            if string_value(lua, want).ok()? != string_value(lua, got).ok()? {
                return None;
            }
        } else if want.kind == "ident"
            && !fixed(&want.text)
            && (i == 0 || !matches!(template[i - 1].text.as_str(), "." | ":"))
        {
            if got.kind != "ident" || fixed(&got.text) {
                return None;
            }
            if let Some(old) = found.names.get(&want.text) {
                if old != &got.text {
                    return None;
                }
            } else {
                if found.names.values().any(|old| old == &got.text) {
                    return None;
                }
                found.names.insert(want.text.clone(), got.text.clone());
            }
        } else if want.text != got.text {
            return None;
        }
    }
    found.start = start;
    found.end = start + template.len();
    Some(found)
}

const ID_PREFIX: &str = r#"do local mu=("")["byte"];local my=("")["char"];local mn=("")["sub"];local mo=("")["gsub"];local mx=error;local mR;local mj={};"#;
const ID_BODY: &str = r#"mY=function(mq)local mS=mj[mq];if mS~=nil then return mS end;local mU=(mq+SALT SEED)%65521;local me=(mq+SALT SEED)%2147483647;local mC=0;local function mb(mc)mU=(mU*MUL+ADD+mC)%65521;mC+=1;local mJ=(mc-mU%256)%256;mU=(mU+mc)%65521;if mC<=4 or mC>8 then me=(me*33+mJ)%2147483647 end;return mJ end;local ms=mo(mR[mq],".....",function(mk)local mv,mP,mi,mN,mK=mu(mk,1,5);local mZ=((((mv-33)*85+mP-33)*85+mi-33)*85+mN-33)*85+mK-33;local mW=mZ%16777216;local mV=mZ%65536;local mr=mZ%256;local mE=mb((mZ-mW)/16777216);local mh=mb((mW-mV)/65536);local mA=mb((mV-mr)/256);local mf=mb(mr);return my(mE,mh,mA,mf)end);local mz,lm,ll,lL=mu(ms,1,4);local lH=mz+lm*256+ll*65536+lL*16777216;local lO,lD,lF,lw=mu(ms,5,8);if not lw or mC~=#ms or lH>#ms-8 or#ms-8-lH>3 or me~=lO+lD*256+lF*65536+lw*16777216 then mx("Voltfuscator: C052",0)end;ms=mn(ms,9,lH+8);if lH<=64 then RING mj[mq]=ms end;return ms end"#;
const RING: &str = "mF=mF%256+1;local mZz=mX[mF];if mZz then mj[mZz]=nil end;mX[mF]=mq;";
const POSITIONAL: &str = r#"do local Je=POOL;local Jk={};local JB=("")["byte"];local JO=("")["char"];local Jy=("")["sub"];local JX=("")["gsub"];JJ=function(Jx,Jt,JY)local JZ=Jk[Jx];if JZ~=nil then return JZ end;local Jf=0;local Jz=JX(Jy(Je,Jx,Jx+((Jt+3)-(Jt+3)%4)/4*5-1),".....",function(Jb)local JQ,JF,Jc,JW,JR=JB(Jb,1,5);local Ja=((((JQ-33)*85+JF-33)*85+Jc-33)*85+JW-33)*85+JR-33;local JN=Ja%16777216;local Jn=Ja%65536;local Jp=Ja%256;local JU=JO(((Ja-JN)/16777216-JY-Jf%251)%256,((JN-Jn)/65536-JY-(Jf+1)%251)%256,((Jn-Jp)/256-JY-(Jf+2)%251)%256,(Jp-JY-(Jf+3)%251)%256);Jf+=4;return JU end);Jz=Jy(Jz,1,Jt);if Jt<=64 then Jk[Jx]=Jz end;return Jz end"#;
const LENGTH_ONLY_SUFFIX: &str = r#"local mj={};local mu=("")["byte"];local my=("")["char"];local mn=("")["sub"];local mo=("")["gsub"];mY=function(mq)local mS=mj[mq];if mS~=nil then return mS end;local mU=(mq+SALT)%65521;local mC=0;local function mb(mc)mU=(mU*MUL+ADD+mC)%65521;mC+=1;local mJ=(mc-mU%256)%256;mU=(mU+mc)%65521;return mJ end;local ms=mo(mR[mq],".....",function(mk)local mv,mP,mi,mN,mK=mu(mk,1,5);local mZ=((((mv-33)*85+mP-33)*85+mi-33)*85+mN-33)*85+mK-33;local mW=mZ%16777216;local mV=mZ%65536;local mr=mZ%256;local mE=mb((mZ-mW)/16777216);local mh=mb((mW-mV)/65536);local mA=mb((mV-mr)/256);local mf=mb(mr);return my(mE,mh,mA,mf)end);local mz,lm,ll,lL=mu(ms,1,4);local lH=mz+lm*256+ll*65536+lL*16777216;ms=mn(ms,5,lH+4);if lH<=64 then mj[mq]=ms end;return ms end"#;

// On admitted executions this guard proves the line-delta is zero before adding KEY.
const DEBUG_BOOT: &str = r##"(function(Lv,...)local Lk=debug local function LO(LJ)return type(LJ)=="number"and LJ>0 and LJ%1==0 end local function LB(LP)if type(Lk)~="table"then return end if type(Lk.getinfo)=="function"then local Lp,La=pcall(Lk.getinfo,LP,"S")if Lp and type(La)=="table"and LO(La.linedefined)and LO(La.lastlinedefined)then return La.linedefined,La.lastlinedefined-La.linedefined end end if type(Lk.info)=="function"then local Le,LG=pcall(Lk.info,LP,"l")if Le and LO(LG)then return LG,0 end end end local Lb local LY=0 local Ld=false local function Li(Lc)local Lm,Ls=LB(Lc)if not Lm then Ld=true;return end if Ls<0 then Ls=-Ls end LY=LY+Ls if Lb then local Lq=Lm-Lb if Lq<0 then Lq=-Lq end LY=LY+Lq else Lb=Lm end end Li(LB)for Lj=1,select("#",...)do Li((select(Lj,...)))end if LY~=0 then error("Voltfuscator: C091",0)end if Ld then error("Voltfuscator: C090",0)end return Lv,KEY+LY end)"##;
const HOST_BOOT: &str = r#"(function(sL,...)local sa,si=(function(sB)local se,sV=pcall(function()local sh=sB.typeof;local sr,st=sB.game,sB.workspace;local sJ=sB.Instance if type(sh)~="function"or type(sJ)~="table"or type(sJ.new)~="function"or sh(sr)~="Instance"or sh(st)~="Instance"then return false end if sr.ClassName~="DataModel"or st.ClassName~="Workspace"or st.Parent~=sr or sr:GetService("Workspace")~=st then return false end local so=sr:GetService("RunService");if sh(so)~="Instance"or so.ClassName~="RunService"then return false end local sl,sw,sx=so:IsStudio(),so:IsClient(),so:IsServer()if type(sl)~="boolean"or type(sw)~="boolean"or type(sx)~="boolean"or sw and sx or not(sl or sw or sx)then return false end if not sw or type(sB.getgenv)~="function"or type(sB.getgenv())~="table"then return false end return true end);local sc=se and sV==true;if not sc then error("Voltfuscator: C094",0)end;return sB,sc and HOSTKEY or 0 end)(sL);local HQ,HM=DEBUG(sa,...);return HQ,si*HM end)"#;
const EXECUTOR_CHECK: &str = r#"local function excheck(exfn)if type(exfn)=="function"then local exok,exname=pcall(exfn);if exok and type(exname)=="string"and#exname<=128 and string.find(exname,"%S")and not string.find(exname,"%c")then return exname end end end local exvalue=excheck(sB.identifyexecutor)or excheck(sB.getexecutorname);if not exvalue then return false end"#;

fn scopes(tokens: &[Atom]) -> Result<(Vec<usize>, Vec<usize>), String> {
    let mut ids = Vec::with_capacity(tokens.len());
    let mut parents = vec![0];
    let mut stack = vec![0];
    for token in tokens {
        ids.push(*stack.last().unwrap());
        match token.text.as_str() {
            "function" | "if" | "do" | "repeat" if token.kind == "ident" => {
                parents.push(*stack.last().unwrap());
                stack.push(parents.len() - 1);
            }
            "end" | "until" if token.kind == "ident" => {
                if stack.len() == 1 {
                    return Err("Unbalanced lexical block".into());
                }
                stack.pop();
            }
            _ => (),
        }
    }
    if stack.len() != 1 {
        return Err("Unrecognized lexical block structure".into());
    }
    Ok((ids, parents))
}

fn ancestor(parents: &[usize], parent: usize, mut child: usize) -> bool {
    while child != parent && child != 0 {
        child = parents[child];
    }
    child == parent
}

fn table_records(
    lua: &mlua::Lua,
    tokens: &[Atom],
    name: &str,
) -> Result<(BTreeMap<u64, Vec<u8>>, usize, usize), String> {
    let positions: Vec<_> = (0..tokens.len().saturating_sub(2))
        .filter(|&i| {
            tokens[i].text == name && tokens[i + 1].text == "=" && tokens[i + 2].text == "{"
        })
        .collect();
    if positions.len() != 1 {
        return Err("Expected one numeric-ID cipher table assignment".into());
    }
    let start = positions[0];
    let mut i = start + 3;
    let mut records = BTreeMap::new();
    while tokens.get(i).is_some_and(|t| t.text != "}") {
        let row = tokens.get(i..i + 5).ok_or("Truncated cipher table")?;
        if row[0].text != "["
            || row[1].kind != "number"
            || row[2].text != "]"
            || row[3].text != "="
            || row[4].kind != "string"
        {
            return Err("Nonliteral entry in cipher table".into());
        }
        let id = crate::number(&row[1].text)?;
        if id == 0 || id >= 2147483647 || records.insert(id, string_value(lua, &row[4])?).is_some()
        {
            return Err("Invalid or duplicate outer string ID".into());
        }
        i += 5;
        if tokens.get(i).is_some_and(|t| t.text == ",") {
            i += 1;
        } else if tokens.get(i).is_none_or(|t| t.text != "}") {
            return Err("Invalid cipher table separator".into());
        }
    }
    if records.is_empty() || i >= tokens.len() {
        return Err("Empty or truncated outer cipher table".into());
    }
    Ok((records, start, i + 1))
}

fn decrypt(
    id: u64,
    seed: u64,
    salt: u64,
    mul: u64,
    add: u64,
    encoded: &[u8],
    checksummed: bool,
) -> Result<Vec<u8>, String> {
    let cipher = crate::ascii85(encoded)?;
    let mut state = (id + salt + seed) % 65521;
    let mut checksum = (id + salt + seed) % 2147483647;
    let mut plain = Vec::with_capacity(cipher.len());
    for (i, &byte) in cipher.iter().enumerate() {
        state = (state * mul + add + i as u64) % 65521;
        let value = byte.wrapping_sub((state % 256) as u8);
        state = (state + byte as u64) % 65521;
        if checksummed && (i < 4 || i >= 8) {
            checksum = (checksum * 33 + value as u64) % 2147483647;
        }
        plain.push(value);
    }
    let header = if checksummed { 8 } else { 4 };
    if plain.len() < header {
        return Err(format!("Record {id}: truncated record header"));
    }
    let length = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
    let checksum_valid =
        !checksummed || checksum == u32::from_le_bytes(plain[4..8].try_into().unwrap()) as u64;
    if length > plain.len() - header || plain.len() - header - length > 3 || !checksum_valid {
        return Err(format!(
            "Record {id}: {} validation failed",
            if checksummed {
                "length/checksum"
            } else {
                "length/padding"
            }
        ));
    }
    Ok(plain[header..header + length].to_vec())
}

fn seed_bootstrap(
    lua: &mlua::Lua,
    tokens: &[Atom],
    decoder: &Match,
) -> Result<(u64, Option<(usize, usize)>), String> {
    let Some(seed_name) = decoder.names.get("seed") else {
        return Ok((0, None));
    };
    let debug = atoms(DEBUG_BOOT)?;
    let host = atoms(&HOST_BOOT.replace("DEBUG", DEBUG_BOOT))?;
    let executor_host = atoms(
        &HOST_BOOT
            .replace(
                "then return false end return true end);",
                &format!("then return false end {EXECUTOR_CHECK} return true end);"),
            )
            .replace("DEBUG", DEBUG_BOOT),
    )?;
    let assignments: Vec<_> = (1..tokens.len().saturating_sub(2))
        .filter(|&i| {
            tokens[i].text == *seed_name && tokens[i - 1].text == "," && tokens[i + 1].text == "="
        })
        .collect();
    if assignments.len() != 1 {
        return Err("Unrecognized or reassigned outer string seed".into());
    }
    let start = assignments[0] + 2;
    let header_start = start
        .checked_sub(4)
        .ok_or("Truncated outer seed assignment")?;
    if tokens[header_start].kind != "ident" {
        return Err("Expected environment/seed multiple assignment".into());
    }
    for (template, multiply) in [(&debug, false), (&host, true), (&executor_host, true)] {
        if let Some(found) = match_at(lua, template, tokens, start, Match::default()) {
            let suffix = tokens
                .get(found.end..found.end + 7)
                .ok_or("Truncated seed bootstrap invocation")?;
            let dec = &decoder.names["mY"];
            if suffix[0].text != "("
                || suffix[1].kind != "ident"
                || suffix[2].text != ","
                || suffix[3].text != *dec
                || suffix[4].text != ","
                || suffix[5].kind != "ident"
                || suffix[6].text != ")"
            {
                return Err("Unexpected outer seed bootstrap arguments".into());
            }
            let key = found.numbers["KEY"];
            if key > 65520 || found.numbers.get("HOSTKEY").is_some_and(|n| *n > 65520) {
                return Err("Outer seed factors exceed verified exact arithmetic range".into());
            }
            let seed = if multiply {
                key.checked_mul(found.numbers["HOSTKEY"])
                    .ok_or("Outer seed overflow")?
            } else {
                key
            };
            return Ok((seed, Some((header_start, found.end + 7))));
        }
    }
    Err("Outer string seed bootstrap does not match inspected guards".into())
}

pub fn recover(source: &str) -> Result<(String, serde_json::Value), String> {
    if source.len() > 16 * 1024 * 1024 {
        return Err("Outer source size limit exceeded".into());
    }
    let lua = crate::vm::restricted_lua().map_err(|e| e.to_string())?;
    let tokens = atoms(source)?;
    let (scope_ids, parents) = scopes(&tokens)?;
    let mut templates = Vec::new();
    for seeded in [false, true] {
        for ring in [false, true] {
            templates.push((
                atoms(&format!(
                    "{ID_PREFIX}{}{}",
                    if ring { "local mX={};local mF=0;" } else { "" },
                    ID_BODY
                        .replace("SEED", if seeded { "+seed" } else { "" })
                        .replace("RING", if ring { RING } else { "" })
                ))?,
                false,
            ));
        }
    }
    templates.push((atoms(POSITIONAL)?, true));
    let length_only_suffix = atoms(LENGTH_ONLY_SUFFIX)?;
    let mut candidates = Vec::new();
    for i in 0..tokens.len() {
        if tokens[i].text != "do" || tokens.get(i + 1).is_none_or(|t| t.text != "local") {
            continue;
        }
        for (template, positional) in &templates {
            if let Some(found) = match_at(&lua, template, &tokens, i, Match::default()) {
                candidates.push((found, *positional, false));
            }
        }
        if tokens.get(i + 3).is_some_and(|t| t.text == "=")
            && tokens.get(i + 4).is_some_and(|t| t.text == "{")
        {
            let table_name = &tokens[i + 2].text;
            // Scan only literal-entry tokens; table_records rejects expressions, duplicates and malformed tables.
            let mut end = i + 5;
            while tokens.get(end).is_some_and(|t| t.text != "}") {
                if tokens.get(end..end + 5).is_none_or(|row| {
                    row[0].text != "["
                        || row[1].kind != "number"
                        || row[2].text != "]"
                        || row[3].text != "="
                        || row[4].kind != "string"
                }) {
                    break;
                }
                end += 5;
                if tokens.get(end).is_some_and(|t| t.text == ",") {
                    end += 1;
                }
            }
            if tokens.get(end).is_some_and(|t| t.text == "}") {
                let mut initial = Match::default();
                initial.names.insert("mR".into(), table_name.clone());
                if let Some(mut found) =
                    match_at(&lua, &length_only_suffix, &tokens, end + 1, initial)
                {
                    found.start = i;
                    candidates.push((found, false, true));
                }
            }
        }
    }
    if candidates.len() != 1 {
        return Err(format!(
            "Expected one inspected Nyx outer decoder; matched {} (unrecognized layouts and rewritten samples are unsupported)",
            candidates.len()
        ));
    }
    let (found, positional, length_only) = candidates.pop().unwrap();
    let name = &found.names[if positional { "JJ" } else { "mY" }];
    let (seed, boot) = if positional {
        (0, None)
    } else {
        seed_bootstrap(&lua, &tokens, &found)?
    };
    let mut decoded = BTreeMap::<u64, Vec<u8>>::new();
    let mut record_lengths = BTreeMap::new();
    let mut table_range = None;
    let mut parameters = serde_json::json!({"kind":"positional ASCII85 minus key and byte-index modulo 251","checksum":"not present in this layout"});
    let helper_end = tokens[found.end - 1].end;
    let helper_start = tokens[found.start].start;
    let helper;
    if positional {
        helper = format!(
            "local {name};{};return {name} end",
            &source[helper_start..helper_end]
        );
    } else {
        let salt = found.numbers["SALT"];
        let mul = found.numbers["MUL"];
        let add = found.numbers["ADD"];
        if salt > 65520 || mul > 65520 || add > 65520 {
            return Err("Outer cipher constants exceed inspected arithmetic range".into());
        }
        let table_name = &found.names["mR"];
        let (records, begin, end) = table_records(&lua, &tokens, table_name)?;
        if (length_only && begin != found.start + 2)
            || (!length_only && begin < found.end)
            || scope_ids[begin] != scope_ids[found.start + 1]
        {
            return Err("Cipher table assignment lies outside the decoder's lexical block".into());
        }
        for (&id, encoded) in &records {
            let plain = decrypt(id, seed, salt, mul, add, encoded, !length_only)?;
            record_lengths.insert(id, plain.len());
            decoded.insert(id, plain);
        }
        table_range = Some((begin, end));
        helper = if length_only {
            format!(
                "local {name};{};return {name} end",
                &source[helper_start..helper_end]
            )
        } else {
            format!(
                "local {name};{}{};{};return {name} end",
                found
                    .names
                    .get("seed")
                    .map(|s| format!("local {s}={seed};"))
                    .unwrap_or_default(),
                &source[helper_start..helper_end],
                &source[tokens[begin].start..tokens[end - 1].end]
            )
        };
        parameters = if length_only {
            serde_json::json!({"salt":salt,"multiplier":mul,"addend":add,"seed":seed,"state_modulus":65521,"header_bytes":4,"checksum":"not present in this layout","integrity_verified":false,"validation":"strict ASCII85 and length/padding framing; every record compared byte-for-byte with bounded isolated original helper","limit":"Decoder equivalence only; well-framed ciphertext corruption cannot be detected reliably without a checksum"})
        } else {
            serde_json::json!({"salt":salt,"multiplier":mul,"addend":add,"seed":seed,"state_modulus":65521,"checksum_modulus":2147483647,"checksum_multiplier":33,"checksum":"all records verified, including padding bytes; header checksum bytes excluded"})
        };
    }
    // Only the exact matched data/decoder statements are evaluated, never the wrapper/bootstrap/application.
    let reference: mlua::Function = lua
        .load(&helper)
        .set_name("inspected-outer-string-helper")
        .eval()
        .map_err(|e| format!("Isolated outer decoder: {e}"))?;
    for (&id, plain) in &decoded {
        let independent: mlua::LuaString = reference.call(id).map_err(|e| e.to_string())?;
        if independent.as_bytes().as_ref() != plain.as_slice() {
            return Err(format!("Record {id}: Rust/Luau decoder mismatch"));
        }
    }
    let pool = if positional {
        Some(string_value(
            &lua,
            found.pool.as_ref().ok_or("Missing positional pool")?,
        )?)
    } else {
        None
    };
    let mut edits = Vec::new();
    let mut declarations = 0;
    let mut unresolved = 0;
    let mut comment_calls = 0;
    let mut seen = HashMap::<u64, (u64, u64)>::new();
    let mut occupied = HashSet::new();
    let declaration_indices: Vec<_> = (1..tokens.len())
        .filter(|&i| tokens[i].text == *name && tokens[i - 1].text == "local")
        .collect();
    if declaration_indices.len() != 1 {
        return Err("Expected one unambiguous local outer decoder declaration".into());
    }
    let declaration = declaration_indices[0];
    let binding_scope = scope_ids[declaration];
    if declaration >= found.start || !ancestor(&parents, binding_scope, scope_ids[found.start]) {
        return Err("Decoder assignment cannot see the local decoder binding".into());
    }
    for (i, token) in tokens.iter().enumerate() {
        if token.text != *name || (found.start..found.end).contains(&i) {
            continue;
        }
        if i != declaration && (i < declaration || !ancestor(&parents, binding_scope, scope_ids[i]))
        {
            return Err("Outer decoder reference lies outside its local binding".into());
        }
        if i > 0 && tokens[i - 1].text == "local" {
            declarations += 1;
            if tokens
                .get(i + 1)
                .is_some_and(|t| t.text == "=" || t.text == ",")
            {
                return Err("Outer decoder is shadowed or initialized elsewhere".into());
            }
            continue;
        }
        if boot.is_some_and(|(a, b)| (a..b).contains(&i)) {
            continue;
        }
        if i > 0 && matches!(tokens[i - 1].text.as_str(), "." | ":" | "function") {
            return Err("Outer decoder has an ambiguous member or function binding".into());
        }
        if tokens.get(i + 1).is_none_or(|t| t.text != "(") {
            return Err(
                "Outer decoder is rebound, shadowed, or escapes the inspected scope".into(),
            );
        }
        let argc = if positional { 3 } else { 1 };
        let mut args = Vec::new();
        let mut cursor = i + 2;
        for a in 0..argc {
            if let Some(t) = tokens.get(cursor).filter(|t| t.kind == "number") {
                args.push(crate::number(&t.text)?);
                cursor += 1;
            } else {
                break;
            }
            if a + 1 < argc {
                if tokens.get(cursor).is_none_or(|t| t.text != ",") {
                    break;
                }
                cursor += 1;
            }
        }
        if args.len() != argc || tokens.get(cursor).is_none_or(|t| t.text != ")") {
            if positional {
                return Err("Dynamic positional calls could alter the shared offset cache".into());
            }
            unresolved += 1;
            continue;
        }
        let id = args[0];
        if positional {
            let (length, key) = (args[1], args[2]);
            if let Some(old) = seen.insert(id, (length, key)) {
                if old != (length, key) {
                    return Err(format!(
                        "Positional cache key {id} has conflicting arguments"
                    ));
                }
            }
            if id == 0 || length > 16 * 1024 * 1024 || key > 255 {
                return Err("Invalid positional string arguments".into());
            }
            let count = length
                .div_ceil(4)
                .checked_mul(5)
                .ok_or("Positional span overflow")?;
            let start = usize::try_from(id - 1).map_err(|_| "Positional offset overflow")?;
            let end = start
                .checked_add(count as usize)
                .ok_or("Positional offset overflow")?;
            let encoded = pool
                .as_ref()
                .unwrap()
                .get(start..end)
                .ok_or("Positional string exceeds pool")?;
            let bytes = crate::ascii85(encoded)?;
            let plain: Vec<_> = bytes
                .iter()
                .take(length as usize)
                .enumerate()
                .map(|(j, b)| b.wrapping_sub(key as u8).wrapping_sub((j % 251) as u8))
                .collect();
            let independent: mlua::LuaString = reference
                .call((id, length, key))
                .map_err(|e| e.to_string())?;
            if independent.as_bytes().as_ref() != plain.as_slice() {
                return Err(format!(
                    "Positional record {id}: Rust/Luau decoder mismatch"
                ));
            }
            record_lengths.insert(id, plain.len());
            decoded.insert(id, plain);
        }
        let plain = decoded
            .get(&id)
            .ok_or_else(|| format!("Outer call references absent ID {id}"))?;
        if tokens[i..=cursor].windows(2).any(|pair| {
            source[pair[0].end..pair[1].start]
                .bytes()
                .any(|byte| !byte.is_ascii_whitespace())
        }) {
            comment_calls += 1;
            continue;
        }
        if !occupied.insert(token.start) {
            return Err("Overlapping outer substitutions".into());
        }
        let mut replacement = crate::lua_string(plain);
        // Debug bootstrap guards observe physical line spans even after outer recovery.
        replacement.extend(
            source[token.start..tokens[cursor].end]
                .chars()
                .filter(|c| matches!(c, '\r' | '\n')),
        );
        edits.push((token.start, tokens[cursor].end, replacement));
    }
    if declarations != 1 {
        return Err("Expected one unambiguous local outer decoder declaration".into());
    }
    if edits.is_empty() {
        return Err("No validated literal outer calls to substitute".into());
    }
    // Refuse hidden reassignment of any decoder state captured by the isolated helper.
    let protected: HashSet<_> = found.names.values().collect();
    for i in 0..tokens.len().saturating_sub(1) {
        if !protected.contains(&tokens[i].text)
            || (found.start..found.end).contains(&i)
            || table_range.is_some_and(|(a, b)| (a..b).contains(&i))
            || boot.is_some_and(|(a, b)| (a..b).contains(&i))
        {
            continue;
        }
        if tokens[i].text == *name {
            continue;
        }
        if found.names.get("seed") != Some(&tokens[i].text)
            && !ancestor(&parents, scope_ids[found.start + 1], scope_ids[i])
        {
            continue;
        }
        if found.names.get("seed") == Some(&tokens[i].text)
            && tokens[i + 1].text == "do"
            && i > 0
            && tokens[i - 1].text == ","
        {
            continue;
        }
        return Err(format!(
            "Outer decoder state {} escapes inspected statements",
            tokens[i].text
        ));
    }
    let count = edits.len();
    let mut output = source.to_owned();
    for (start, end, text) in edits.into_iter().rev() {
        output.replace_range(start..end, &text);
    }
    mlua::chunk::Compiler::new()
        .compile(&output)
        .map_err(|e| format!("Partial source syntax validation: {e}"))?;
    let stats = serde_json::json!({"status":"partial","adapter":"nyx-outer-strings","layout":if positional{"positional-ascii85"}else if length_only{"length-only-id-ascii85"}else{"checksummed-id-ascii85"},"decoder":name,"strings_decoded":decoded.len(),"calls_replaced":count,"unresolved_dynamic_calls":unresolved,"calls_preserved_with_comments":comment_calls,"decoded_bytes":decoded.values().map(Vec::len).sum::<usize>(),"decoded_lengths":record_lengths,"cipher":parameters,"validation":"exact lexical decoder template; source-derived parameters; Rust versus isolated Luau helper; partial output compiles","application_executed":false,"wrapper_preserved":true,"vm_devirtualized":false,"limit":"Outer strings only; VM instructions, application behavior and wrapper admission effects remain unresolved"});
    Ok((output, stats))
}
