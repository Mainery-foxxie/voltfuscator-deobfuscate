use std::{fs, process::Command};

fn test_folder(label: &str) -> std::path::PathBuf {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|p| p.join("Temp/opencode"))
        .unwrap_or_else(std::env::temp_dir);
    root.join(format!("voltfuscator-{label}-{}", std::process::id()))
}

#[test]
fn batch_reports_each_file_deduplicates_and_preserves_inputs() {
    let base = test_folder("batch");
    assert!(!base.exists());
    let input = base.join("input");
    let output = base.join("output");
    fs::create_dir_all(&input).unwrap();
    let unsupported = b"-- Voltfuscator 7.7 Nyx\nreturn 42\n";
    fs::write(input.join("first.lua"), unsupported).unwrap();
    fs::write(input.join("duplicate.lua"), unsupported).unwrap();
    fs::write(input.join("invalid.lua"), [0xff, 0xfe]).unwrap();
    fs::write(input.join("unrelated.png"), b"skip").unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--batch")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["input_files"], 3);
    assert_eq!(manifest["unique_inputs"], 2);
    assert_eq!(manifest["partial"], 0);
    assert_eq!(manifest["unsupported"], 3);
    assert_eq!(manifest["results"].as_array().unwrap().len(), 3);
    for name in ["first.lua", "duplicate.lua", "invalid.lua"] {
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join(format!("{name}.report.json"))).unwrap())
                .unwrap();
        assert_eq!(report["input_file"], name);
        assert_eq!(report["status"], "unsupported");
        assert_eq!(report["application_executed"], false);
        assert!(!report["error"].as_str().unwrap().is_empty());
        assert!(!output.join(format!("{name}.partial.luau")).exists());
    }
    assert_eq!(fs::read(input.join("first.lua")).unwrap(), unsupported);
    assert_eq!(fs::read(input.join("duplicate.lua")).unwrap(), unsupported);
    assert_eq!(fs::read(input.join("invalid.lua")).unwrap(), [0xff, 0xfe]);
    let before = fs::read(output.join("manifest.json")).unwrap();
    let duplicate = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--batch")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert_eq!(fs::read(output.join("manifest.json")).unwrap(), before);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn decode_uses_verified_structure_despite_misleading_banner() {
    let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("voltfusctarosamples/script.lua");
    if !sample.is_file() {
        eprintln!("External v8 sample unavailable: {}", sample.display());
        return;
    }
    let original = fs::read_to_string(sample).unwrap();
    let source = original.replacen("Voltfuscator v8.0", "Voltfuscator v7.5", 1);
    let base = test_folder("decode-routing");
    assert!(!base.exists());
    fs::create_dir_all(&base).unwrap();
    let input = base.join("misleading.lua");
    let output = base.join("decoded");
    fs::write(&input, &source).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--decode")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "partial", "{report}");
    assert_eq!(report["decoder_adapter"], "outer_v8");
    assert_eq!(report["decoder"]["records_validated"], 133);
    assert_eq!(report["application_executed"], false);
    assert_eq!(fs::read_to_string(&input).unwrap(), source);
    let before = fs::read(output.join("report.json")).unwrap();
    let rerun = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--decode")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(!rerun.status.success());
    assert_eq!(fs::read(output.join("report.json")).unwrap(), before);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn decode_reports_oversized_inputs_without_a_source_artifact() {
    let base = test_folder("decode-limit");
    assert!(!base.exists());
    fs::create_dir_all(&base).unwrap();
    let input = base.join("large.lua");
    let output = base.join("decoded");
    fs::write(&input, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--decode")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "unsupported");
    assert!(report["error"].as_str().unwrap().contains("4 MiB"));
    assert_eq!(report["source_file"], serde_json::Value::Null);
    assert!(!output.join("source.partial.luau").exists());
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn batch_writes_individual_partial_sources_for_supported_duplicates() {
    let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("voltfusctarosamples/script.lua");
    if !sample.is_file() {
        eprintln!("External v8 sample unavailable: {}", sample.display());
        return;
    }
    let bytes = fs::read(sample).unwrap();
    let base = test_folder("batch-partial");
    assert!(!base.exists());
    let input = base.join("input");
    let output = base.join("output");
    fs::create_dir_all(&input).unwrap();
    for name in ["first.lua", "second.lua"] {
        fs::write(input.join(name), &bytes).unwrap();
    }
    let result = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--batch")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"], "finished");
    assert_eq!(manifest["unique_inputs"], 1);
    assert_eq!(manifest["partial"], 2);
    assert_eq!(manifest["fully_devirtualized"], 0);
    let first = fs::read(output.join("first.lua.partial.luau")).unwrap();
    assert_eq!(
        first,
        fs::read(output.join("second.lua.partial.luau")).unwrap()
    );
    mlua::chunk::Compiler::new().compile(&first).unwrap();
    let second: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("second.lua.report.json")).unwrap()).unwrap();
    assert_eq!(second["duplicate_of"], "first.lua");
    assert_eq!(second["source_file"], "second.lua.partial.luau");
    for name in ["first.lua", "second.lua"] {
        assert_eq!(fs::read(input.join(name)).unwrap(), bytes);
    }
    fs::remove_dir_all(base).unwrap();
}
