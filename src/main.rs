use chess_deobf::*;
use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() == 4 && args[1] == "--batch" {
        return batch::run(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]));
    }
    if args.len() == 4 && args[1] == "--auto" {
        return auto::run(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]));
    }
    if args.len() == 4 && args[1] == "--decode" {
        return batch::decode_file(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]));
    }
    if args.len() == 4 && args[1] == "--cryptnek" {
        let source = fs::read_to_string(&args[2]).map_err(|e| e.to_string())?;
        return cryptnek::recover(&source, &PathBuf::from(&args[3]));
    }
    if args.len() == 4 && args[1] == "--lift" {
        if PathBuf::from(&args[3]).exists() {
            return Err("Output directory already exists; choose a new directory".into());
        }
        let source = fs::read_to_string(&args[2]).map_err(|e| e.to_string())?;
        return vm::lift(&source, &PathBuf::from(&args[3]));
    }
    if args.len() == 4 && args[1] == "--recover" {
        let input = PathBuf::from(&args[2]);
        let output = PathBuf::from(&args[3]);
        if output.exists() {
            return Err("Output directory already exists; choose a new directory".into());
        }
        let original = fs::read(&input).map_err(|e| e.to_string())?;
        let status = std::process::Command::new(env::current_exe().map_err(|e| e.to_string())?)
            .arg(&input)
            .arg(output.join("stage1"))
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("Outer decoding failed".into());
        }
        let outer = fs::read_to_string(output.join("stage1/chess.outer-decoded.luau"))
            .map_err(|e| e.to_string())?;
        let extraction = vm::extract(&outer, &output.join("stage2"));
        let native = output.join("stage2/chess.native-decoded.luau");
        let result = if native.exists() {
            fs::read_to_string(native).map_err(|e| e.to_string())?
        } else {
            outer
        };
        mlua::chunk::Compiler::new()
            .compile(&result)
            .map_err(|e| format!("Recovered intermediate failed Luau syntax validation: {e}"))?;
        let notice = "-- PARTIAL RECOVERY: string layers decoded; custom VM and original control flow remain.\n-- This is an intermediate artifact, not verified devirtualized source.\n";
        fs::write(
            output.join("result.partial.luau"),
            format!("{notice}{result}"),
        )
        .map_err(|e| e.to_string())?;
        use sha2::{Digest, Sha256};
        if fs::read(&input).map_err(|e| e.to_string())? != original {
            return Err("Input changed during recovery".into());
        }
        let outer_stats: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(output.join("stage1/stats.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let native_stats: serde_json::Value =
            fs::read_to_string(output.join("stage2/native-stats.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null);
        let vm_stats: serde_json::Value =
            fs::read_to_string(output.join("stage2/extraction-stats.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null);
        let artifacts: Vec<_> = [
            "result.partial.luau",
            "stage1/outer-strings.tsv",
            "stage2/native-strings.tsv",
            "stage2/instructions.json",
        ]
        .into_iter()
        .filter(|name| output.join(name).is_file())
        .collect();
        let report = serde_json::json!({
            "status":"partial", "obfuscator":"Voltfuscator v8.1", "input_bytes":original.len(),
            "input_sha256":format!("{:x}",Sha256::digest(&original)),
            "outer_recovery":outer_stats, "native_recovery":native_stats,"vm_coverage":vm_stats,
            "syntax_validation":"passed with Luau compiler", "behavioral_equivalence":"not verified",
            "vm_recovery": extraction.err().unwrap_or_else(||"Linear root records and contextual constants extracted; reachability, compound handlers, child prototypes and operand meanings remain unverified".into()),
            "scope":"Adapter derived from chess.luau; other Voltfuscator 8.1 builds can differ and are not guaranteed supported",
            "application_entry":"Extraction uses a patched loader that captures before application execution; result.partial.luau retains the original application entry",
            "artifacts":artifacts
        });
        fs::write(
            output.join("report.json"),
            serde_json::to_string_pretty(&report).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        println!("Partial recovery saved to {}", output.display());
        return Ok(());
    }
    if args.len() == 4 && args[1] == "--extract" {
        let source = fs::read_to_string(&args[2]).map_err(|e| e.to_string())?;
        return vm::extract(&source, &PathBuf::from(&args[3]));
    }
    if args.len() != 3 {
        return Err("Usage: chess-deobf [--auto|--decode|--recover|--lift|--extract|--cryptnek] INPUT OUTPUT_DIRECTORY\n       chess-deobf --batch INPUT_DIRECTORY OUTPUT_DIRECTORY".into());
    }
    let source = fs::read_to_string(&args[1]).map_err(|e| e.to_string())?;
    let out = PathBuf::from(&args[2]);
    if out.exists() {
        return Err("Output directory already exists; choose a new directory".into());
    }
    let tokens = lex(&source)?;
    let index = pool_index(field_string(&source, &tokens, "qK")?)?;
    let pool = field_string(&source, &tokens, "qE")?;
    if index.len() != 130 || index.iter().map(|r| r.2).sum::<usize>() != pool.len() {
        return Err("Outer pool structure differs from inspected sample".into());
    }
    let mut decoded = BTreeMap::new();
    let mut listing = String::new();
    for (id, offset, len) in &index {
        let encoded = pool
            .get(*offset..offset + len)
            .ok_or("Pool offset out of bounds")?;
        let (seed, bytes) = [0, 51615 * 51615]
            .into_iter()
            .find_map(|seed| decrypt_record(*id, seed, encoded).ok().map(|v| (seed, v)))
            .ok_or_else(|| format!("No validated seed for record {id}"))?;
        listing.push_str(&format!("{id}\tseed={seed}\t{}\n", lua_string(&bytes)));
        decoded.insert(*id, bytes);
    }
    let mut result = String::new();
    let (mut copied, mut count, mut i) = (0, 0, 0);
    while i + 3 < tokens.len() {
        let t = &tokens[i..i + 4];
        let text = |j: usize| &source[t[j].start..t[j].end];
        if matches!(text(0), "zd" | "zNi")
            && text(1) == "("
            && t[2].kind == "number"
            && text(3) == ")"
        {
            let id = number(text(2))?;
            let value = decoded
                .get(&id)
                .ok_or_else(|| format!("Unresolved outer decoder call {id}"))?;
            result.push_str(&source[copied..t[0].start]);
            result.push_str(&lua_string(value));
            copied = t[3].end;
            count += 1;
            i += 4;
        } else {
            i += 1;
        }
    }
    result.push_str(&source[copied..]);
    let rt = lex(&result)?;
    let mut formatted = String::new();
    let mut last = 0;
    for t in &rt {
        formatted.push_str(&result[last..t.end]);
        if matches!(
            &result[t.start..t.end],
            ";" | "then" | "do" | "else" | "end"
        ) {
            formatted.push('\n');
        }
        last = t.end;
    }
    formatted.push_str(&result[last..]);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    fs::write(out.join("outer-strings.tsv"), listing).map_err(|e| e.to_string())?;
    fs::write(out.join("chess.outer-decoded.luau"), formatted).map_err(|e| e.to_string())?;
    fs::write(
        out.join("stats.json"),
        serde_json::json!({"strings_validated":decoded.len(),"decoder_calls_replaced":count})
            .to_string(),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Validated {} outer strings; replaced {count} decoder calls. VM remains for the next stage.",
        decoded.len()
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
