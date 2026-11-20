use crate::{lex, lua_string, number};
use std::collections::{BTreeMap, BTreeSet, HashMap};

fn unmix(state: u64, context: u64, zs: &BTreeMap<u64, u64>) -> (u64, u64) {
    let modulus = zs[&35];
    let (mut a, mut b) = (state / modulus, state % modulus);
    let rounds = if context % 2 == 0 {
        vec![
            (6279815, 256),
            (zs[&36], 1024),
            (zs[&37], 262144),
            (13703770, 131072),
            (zs[&38], 262144),
            (zs[&39], 512),
        ]
    } else {
        vec![
            (zs[&40], 32768),
            (zs[&41], 512),
            (zs[&42], 524288),
            (7151992, 16384),
            (zs[&43], 2048),
            (zs[&44], 4096),
        ]
    };
    for (salt, div) in rounds {
        let x = (a + context + salt) % modulus;
        let x = (x % div) * (modulus / div) + x / div;
        (a, b) = ((b + modulus - (x * x) % modulus) % modulus, a);
    }
    (a, b)
}

pub fn recover(
    source: &str,
    constants: &mlua::Table,
    decoders: &BTreeMap<String, mlua::Function>,
    output: &std::path::Path,
) -> Result<(), String> {
    let mut zs = BTreeMap::new();
    for pair in constants.clone().pairs::<u64, u64>() {
        let (k, v) = pair.map_err(|e| e.to_string())?;
        zs.insert(k, v);
    }
    let tokens = lex(source)?;
    let text = |i: usize| &source[tokens[i].start..tokens[i].end];
    let mut candidates: BTreeSet<u64> = zs
        .values()
        .copied()
        .filter(|n| *n >= zs[&35] && *n < zs[&35] * zs[&35])
        .collect();
    for (i, t) in tokens.iter().enumerate() {
        if t.kind == "number" {
            if let Ok(n) = number(text(i)) {
                if n >= zs[&35] && n < zs[&35] * zs[&35] {
                    candidates.insert(n);
                }
            }
        }
    }
    let mut contexts: HashMap<(String, u64), u64> = HashMap::new();
    let mut guard_sites = Vec::new();
    for (decoder, state_var, context_var, guard_offset) in
        [("gB", "Ag", "Ax", -58133i64), ("zzM", "zdS", "zdG", 36399)]
    {
        let Some(function) = decoders.get(decoder) else {
            return Err(format!("Missing decoder {decoder}"));
        };
        let mut blocks = BTreeMap::new();
        for i in 0..tokens.len().saturating_sub(13) {
            if text(i) == "if"
                && text(i + 1) == state_var
                && text(i + 2) == "~"
                && text(i + 3) == "="
                && tokens[i + 4].kind == "number"
                && text(i + 5) == "or"
                && text(i + 6) == "not"
                && text(i + 7) == "("
                && text(i + 9) == "["
                && tokens[i + 10].kind == "number"
            {
                let block = number(text(i + 4))?;
                let seal = number(text(i + 10))?;
                blocks.insert(block, seal);
                guard_sites.push((
                    tokens[i].start,
                    decoder.to_string(),
                    context_var.to_string(),
                    block,
                ));
            }
        }
        let mut pending = vec![0u64];
        let mut seen = BTreeSet::new();
        while let Some(context) = pending.pop() {
            if !seen.insert(context) {
                continue;
            }
            for &state in &candidates {
                let (block, next) = unmix(state, context, &zs);
                if contexts.contains_key(&(decoder.to_string(), block)) {
                    continue;
                }
                if let Some(&seal) = blocks.get(&block) {
                    let value: mlua::Value = function
                        .call((guard_offset, seal, next))
                        .map_err(|e| e.to_string())?;
                    if matches!(value, mlua::Value::Boolean(true)) {
                        contexts.insert((decoder.to_string(), block), next);
                        pending.push(next);
                    }
                }
            }
        }
        println!(
            "{decoder}: verified contexts for {} / {} native blocks",
            contexts.keys().filter(|(d, _)| d == decoder).count(),
            blocks.len()
        );
    }
    guard_sites.sort_by_key(|r| r.0);
    let mut replacements = Vec::new();
    let mut listing = BTreeMap::new();
    let mut unresolved = 0;
    for i in 0..tokens.len().saturating_sub(8) {
        let decoder = text(i);
        if !matches!(decoder, "gB" | "zzM") || text(i + 1) != "(" {
            continue;
        }
        let mut j = i + 2;
        let mut args = Vec::new();
        while j < tokens.len() {
            let start = j;
            while j < tokens.len() && !matches!(text(j), "," | ")") {
                j += 1;
            }
            args.push((start, j));
            if j >= tokens.len() || text(j) == ")" {
                break;
            }
            j += 1;
        }
        if args.len() != 3 || j >= tokens.len() {
            continue;
        }
        let int_arg = |(start, end): (usize, usize)| -> Option<i64> {
            if end == start + 1 {
                number(text(start)).ok().and_then(|v| v.try_into().ok())
            } else if end == start + 2 && text(start) == "-" {
                number(text(start + 1))
                    .ok()
                    .and_then(|v| i64::try_from(v).ok())
                    .map(|n| -n)
            } else {
                None
            }
        };
        let (Some(a), Some(b)) = (int_arg(args[0]), int_arg(args[1])) else {
            continue;
        };
        let context = if let Some(n) = int_arg(args[2]) {
            Some(n as u64)
        } else {
            guard_sites
                .iter()
                .rev()
                .find(|r| r.0 < tokens[i].start && r.1 == decoder)
                .and_then(|(_, d, _, block)| contexts.get(&(d.clone(), *block)).copied())
        };
        let Some(context) = context else {
            unresolved += 1;
            continue;
        };
        let value: mlua::Value = decoders[decoder]
            .call((a, b, context))
            .map_err(|e| e.to_string())?;
        let literal = match value {
            mlua::Value::String(s) => lua_string(&s.as_bytes()),
            mlua::Value::Boolean(b) => b.to_string(),
            mlua::Value::Integer(n) => n.to_string(),
            mlua::Value::Number(n) => n.to_string(),
            _ => {
                unresolved += 1;
                continue;
            }
        };
        listing.insert(format!("{decoder}({a},{b},{context})"), literal.clone());
        replacements.push((tokens[i].start, tokens[j].end, literal));
    }
    let mut decoded = String::new();
    let mut last = 0;
    for (start, end, literal) in &replacements {
        decoded.push_str(&source[last..*start]);
        decoded.push_str(literal);
        last = *end;
    }
    decoded.push_str(&source[last..]);
    std::fs::write(output.join("chess.native-decoded.luau"), decoded).map_err(|e| e.to_string())?;
    std::fs::write(
        output.join("native-strings.tsv"),
        listing
            .iter()
            .map(|(k, v)| format!("{k}\t{v}\n"))
            .collect::<String>(),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(output.join("native-stats.json"),serde_json::json!({"verified_contexts":contexts.len(),"decoder_calls_replaced":replacements.len(),"unresolved_calls":unresolved}).to_string()).map_err(|e|e.to_string())?;
    println!(
        "Replaced {} native decoder calls; {unresolved} calls remain unresolved.",
        replacements.len()
    );
    Ok(())
}
