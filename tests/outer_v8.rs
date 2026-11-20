pub use chess_deobf::{Token, ascii85, lex, long_value, lua_string, number};
#[path = "../src/outer_v8.rs"]
mod outer_v8;

use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn sample(name: &str, records: u64, index: &str, pool: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root
        .parent()
        .unwrap()
        .join("voltfusctarosamples")
        .join(name);
    let original = fs::read(&path).expect("authorized v8 sample must be present");
    let hash = format!("{:x}", Sha256::digest(&original));
    let source = std::str::from_utf8(&original).unwrap();
    let (decoded, stats) = outer_v8::recover(source).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(stats["records_validated"], records);
    assert_eq!(stats["index_field"], index);
    assert_eq!(stats["pool_field"], pool);
    assert_eq!(stats["status"], "partial");
    assert!(stats["calls_replaced"].as_u64().unwrap() > records);
    assert!(decoded.contains("Voltfuscator: C052"));
    assert_ne!(decoded, source);
    // Compile only: no application or original sample is executed.
    mlua::Lua::new()
        .load(&decoded)
        .into_function()
        .expect("recovered Luau must compile");
    compare_isolated_helper(source, &stats);
    assert_eq!(
        hash,
        format!("{:x}", Sha256::digest(fs::read(&path).unwrap()))
    );
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let out = root
        .join("output/v8-probe-new")
        .join(format!("{name}-{stamp}"));
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("outer.partial.luau"), decoded).unwrap();
    fs::write(
        out.join("stats.json"),
        serde_json::to_string_pretty(&stats).unwrap(),
    )
    .unwrap();
    fs::write(out.join("input.sha256"), hash).unwrap();
    println!(
        "{name}: {} records, {} calls; output={}",
        stats["records_validated"],
        stats["calls_replaced"],
        out.display()
    );
}

fn compare_isolated_helper(source: &str, stats: &serde_json::Value) {
    let start = stats["helper_byte_start"].as_u64().unwrap() as usize;
    let end = stats["helper_byte_end"].as_u64().unwrap() as usize;
    let helper = &source[start..end];
    // recover() has matched this WHOLE helper against the closed arithmetic template.
    // Only its function expression is evaluated; the application entry is outside it.
    let tokens = lex(helper).unwrap();
    assert_eq!(&helper[tokens[2].start..tokens[2].end], "function");
    let code = format!("return {}", &helper[tokens[2].start..]);
    let lua = mlua::Lua::new_with(mlua::StdLib::STRING, mlua::LuaOptions::default()).unwrap();
    lua.set_memory_limit(16 * 1024 * 1024).unwrap();
    for key in [
        "require",
        "loadstring",
        "load",
        "dofile",
        "loadfile",
        "io",
        "os",
        "package",
        "debug",
        "print",
    ] {
        lua.globals().set(key, mlua::Nil).unwrap();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    lua.set_interrupt(move |_| {
        if std::time::Instant::now() >= deadline {
            return Err(mlua::Error::RuntimeError(
                "helper comparison timed out".into(),
            ));
        }
        Ok(mlua::VmState::Continue)
    });
    lua.sandbox(true).unwrap();
    let fields = lua.create_table().unwrap();
    let source_tokens = lex(source).unwrap();
    for key in [
        stats["index_field"].as_str().unwrap(),
        stats["pool_field"].as_str().unwrap(),
    ] {
        let i = source_tokens
            .windows(3)
            .position(|t| {
                &source[t[0].start..t[0].end] == key
                    && &source[t[1].start..t[1].end] == "="
                    && t[2].kind == "string"
            })
            .unwrap();
        let value =
            long_value(&source[source_tokens[i + 2].start..source_tokens[i + 2].end]).unwrap();
        fields.set(key, lua.create_string(value).unwrap()).unwrap();
    }
    let factory: mlua::Function = lua.load(&code).eval().unwrap();
    let (decoder, setter): (mlua::Function, mlua::Function) = factory.call(fields).unwrap();
    for record in stats["records"]
        .as_array()
        .expect("record evidence must be present")
    {
        setter.call::<()>(record["seed"].as_u64().unwrap()).unwrap();
        let result: mlua::LuaString = decoder.call(record["id"].as_u64().unwrap()).unwrap();
        let expected: Vec<u8> = record["decoded_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(
            result.as_bytes().as_ref(),
            expected,
            "independent helper mismatch for id {}",
            record["id"]
        );
    }
}

#[test]
fn script_outer_records() {
    sample("script.lua", 133, "HK", "HZ");
}

#[test]
fn fetched2_outer_records() {
    sample("fetched (2).lua", 89, "Rr", "RN");
}

#[test]
fn fetched4_outer_records() {
    sample("fetched (4).lua", 128, "wk", "wG");
}

#[test]
fn rejects_unrecognized_source() {
    assert!(outer_v8::recover("return 'Voltfuscator v8.0'").is_err());
}

fn script() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("voltfusctarosamples/script.lua"),
    )
    .unwrap()
}

#[test]
fn rejects_decoder_operation_changes() {
    let source = script().replacen("Xj*140+", "Xj*141-", 1);
    assert!(outer_v8::recover(&source).is_err());
}

#[test]
fn rejects_index_corruption() {
    let source = script().replacen("HK=[=[U", "HK=[=[V", 1);
    assert!(outer_v8::recover(&source).unwrap_err().contains("index"));
}

#[test]
fn rejects_record_corruption() {
    let source = script().replacen("HZ=[=[_", "HZ=[=[^", 1);
    assert!(
        outer_v8::recover(&source)
            .unwrap_err()
            .contains("valid seed candidates")
    );
}

#[test]
fn rejects_decoder_shadowing() {
    let source = script().replacen("local function BV(...)", "local function BV(BC,...)", 1);
    assert!(outer_v8::recover(&source).unwrap_err().contains("Shadowed"));
}

#[test]
fn preserves_comments_strings_and_member_calls() {
    let source=script().replacen("local function BV(...)", "local function BV(...) -- BC(0x3bdfe4a2)\nlocal unrelated='BC(0x3bdfe4a2)';local holder={};holder.BC(0x3bdfe4a2);holder:BC(0x3bdfe4a2);", 1);
    let (output, _) = outer_v8::recover(&source).unwrap();
    assert!(output.contains("-- BC(0x3bdfe4a2)\n"));
    assert!(output.contains("'BC(0x3bdfe4a2)'"));
    assert!(output.contains("holder.BC(0x3bdfe4a2);holder:BC(0x3bdfe4a2)"));
}

#[test]
fn rejects_record_calls_in_the_wrong_seed_phase() {
    let source = script().replacen("BC(0Xaf0ea44)", "BC(0X526c73d9)", 1);
    assert!(
        outer_v8::recover(&source)
            .unwrap_err()
            .contains("seed phase")
    );
}

#[test]
fn rejects_bootstrap_decoder_shadowing() {
    let source = script().replacen("function(lH,...)", "function(lH,lf,...)", 1);
    assert!(outer_v8::recover(&source).unwrap_err().contains("Shadowed"));
}

#[test]
fn rejects_decoder_assignment_lists() {
    let source = script().replacen(
        "local function BV(...)",
        "local function BV(...) BC,unused=function()end,0;",
        1,
    );
    assert!(outer_v8::recover(&source).unwrap_err().contains("Mutated"));
}

#[test]
fn rejects_extra_seed_setter_calls() {
    let source = script().replacen(
        "local li,lg=lk:HS(lf,ln);",
        "local li,lg=lk:HS(lf,ln);lx(1);",
        1,
    );
    assert!(outer_v8::recover(&source).unwrap_err().contains("setter"));
}

#[test]
fn preserves_dynamic_calls() {
    let source = script().replacen("BC(0Xaf0ea44)", "BC(runtime_id)", 1);
    let (output, stats) = outer_v8::recover(&source).unwrap();
    assert!(output.contains("BC(runtime_id)"));
    assert_eq!(stats["dynamic_calls_retained"], 1);
    assert_eq!(stats["calls_replaced"], 653);
}

#[test]
fn keeps_bom_and_original_byte_offsets() {
    let original = script();
    let source = format!("\u{feff}{original}");
    let (output, stats) = outer_v8::recover(&source).unwrap();
    assert!(output.starts_with('\u{feff}'));
    let offset = stats["helper_byte_start"].as_u64().unwrap() as usize;
    assert!(source[offset..].starts_with("Hn=function"));
}
