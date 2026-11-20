use std::{fs, process::Command};

fn base(label: &str) -> std::path::PathBuf {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|p| p.join("Temp/opencode"))
        .unwrap_or_else(std::env::temp_dir);
    root.join(format!("auto-{label}-{}", std::process::id()))
}

fn run(input: &std::path::Path, output: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .args(["--auto"])
        .arg(input)
        .arg(output)
        .output()
        .unwrap()
}

fn read_report(output: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(output.join("report.json")).unwrap()).unwrap()
}

#[test]
fn auto_reports_unsupported_without_source() {
    let root = base("unsupported");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    fs::write(&input, b"return 42\n").unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "unsupported");
    assert_eq!(report["application_executed"], false);
    assert_eq!(report["artifacts"], serde_json::json!(["report.json"]));
    assert!(report["stage_errors"].as_array().unwrap().len() >= 1);
    assert!(!output.join("source.partial.luau").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn auto_reports_malformed_utf8_without_source() {
    let root = base("malformed");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    fs::write(&input, [0xff, 0xfe, 0x00]).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "unsupported");
    assert_eq!(report["format"], "unknown");
    assert!(
        report["stage_errors"][0]
            .as_str()
            .unwrap()
            .contains("UTF-8")
    );
    assert_eq!(report["artifacts"], serde_json::json!(["report.json"]));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn auto_reports_missing_input_without_source() {
    let root = base("missing");
    let input = root.join("missing.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "error");
    assert_eq!(report["input_bytes"], serde_json::Value::Null);
    assert_eq!(report["input_sha256"], serde_json::Value::Null);
    assert_eq!(report["artifacts"], serde_json::json!(["report.json"]));
    assert!(!output.join("source.partial.luau").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn auto_refuses_existing_output_directory_without_modifying_it() {
    let root = base("existing");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&output).unwrap();
    fs::write(&input, b"return 42\n").unwrap();
    fs::write(output.join("sentinel"), b"keep").unwrap();

    let result = run(&input, &output);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("already exists"));
    assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"keep");
    assert!(!output.join("report.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn auto_accepts_validated_outer_input_even_with_a_misleading_banner() {
    let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("voltfusctarosamples/script.lua");
    if !sample.is_file() {
        eprintln!("External v8 sample unavailable: {}", sample.display());
        return;
    }
    let root = base("misleading");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    let source = fs::read_to_string(sample)
        .unwrap()
        .replace("Voltfuscator v8.0", "Voltfuscator v7.5");
    fs::write(&input, source).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "partial");
    assert_eq!(report["format"], "voltfuscator_outer");
    assert!(
        report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == "source.partial.luau")
    );
    assert!(
        !report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == "chess.lifted.luau")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn auto_accepts_representative_validated_outer_input_as_partial() {
    let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("voltfusctarosamples/script.lua");
    if !sample.is_file() {
        eprintln!("External v8 sample unavailable: {}", sample.display());
        return;
    }
    let root = base("outer");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    fs::copy(sample, &input).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "partial");
    assert_eq!(report["application_executed"], false);
    assert!(output.join("source.partial.luau").is_file());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn auto_rejects_modified_cryptnek_bytes() {
    let Ok(sample) = std::env::var("CRYPTNEK_SAMPLE") else {
        eprintln!("CRYPTNEK_SAMPLE unavailable");
        return;
    };
    let root = base("cryptnek-modified");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    let mut bytes = fs::read(sample).unwrap();
    bytes[0] ^= 1;
    fs::write(&input, bytes).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_ne!(report["status"], "clean_lift");
    assert!(!output.join("CoPlay_Legit_Trivia_Only.clean.luau").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires the local sample via CRYPTNEK_SAMPLE"]
fn auto_routes_exact_cryptnek_to_clean_lift() {
    let sample = std::env::var("CRYPTNEK_SAMPLE").unwrap();
    let root = base("cryptnek");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    fs::copy(sample, &input).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "clean_lift");
    assert_eq!(report["format"], "cryptnek");
    for name in [
        "CoPlay_Legit_Trivia_Only.clean.luau",
        "anti-tamper-report.json",
        "report.json",
    ] {
        assert!(
            report["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item == name)
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires the local sample via CHESS_SAMPLE"]
fn auto_routes_exact_chess_to_clean_lift() {
    let sample = std::env::var("CHESS_SAMPLE").unwrap();
    let root = base("chess");
    let input = root.join("input.lua");
    let output = root.join("output");
    fs::create_dir_all(&root).unwrap();
    fs::copy(sample, &input).unwrap();

    let result = run(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = read_report(&output);
    assert_eq!(report["status"], "clean_lift");
    assert_eq!(report["format"], "voltfuscator_v8_1_chess");
    assert!(output.join("chess.lifted.luau").is_file());
    assert!(output.join("lift-report.json").is_file());
    fs::remove_dir_all(root).unwrap();
}
