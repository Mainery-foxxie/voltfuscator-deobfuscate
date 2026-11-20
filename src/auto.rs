use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    path::Path,
    process::{Command, Stdio},
};

const CRYPTNEK_SHA256: &str = "d3e200a3840ed5c46592083fbcb8c4b516095d48f9c4c55306d29c4c56543de3";
const CHESS_SHA256: &str = "8ec257c05b1e57e60631fe27da430cb50993f37b7fd25c76bab5704420db3ec6";
const MAX_AUTO_INPUT: u64 = 64 * 1024 * 1024;

// shortcut: a forced process kill can leave this lock; remove it before retrying that output path.
struct OutputReservation(std::path::PathBuf);

impl Drop for OutputReservation {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn reserve_output_directory(output: &Path) -> Result<OutputReservation, String> {
    if output.exists() {
        return Err("Output directory already exists; choose a new directory".into());
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut name = OsString::from(".");
    name.push(
        output
            .file_name()
            .ok_or_else(|| "Output path must name a new directory".to_string())?,
    );
    name.push(".auto-lock");
    let lock = parent.join(name);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "Output directory is already being processed; choose a new directory".to_string()
            } else {
                error.to_string()
            }
        })?;
    let reservation = OutputReservation(lock);
    if output.exists() {
        return Err("Output directory already exists; choose a new directory".into());
    }
    Ok(reservation)
}

fn create_output_directory(output: &Path) -> Result<(), String> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    fs::create_dir(output).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            "Output directory already exists; choose a new directory".to_string()
        } else {
            error.to_string()
        }
    })
}

fn write_report(output: &Path, report: &Value) -> Result<(), String> {
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn input_name(input: &Path) -> String {
    input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "input".into())
}

fn base_report(
    input: &Path,
    bytes: &[u8],
    input_sha256: &str,
    format: &str,
    status: &str,
) -> Value {
    json!({
        "status": status,
        "format": format,
        "detected_format": format,
        "input_file": input_name(input),
        "input_bytes": bytes.len(),
        "input_sha256": input_sha256,
        "application_executed": false,
        "stage_results": [],
        "stage_errors": [],
        "coverage": {},
        "limits": ["Application code and anti-tamper checks were not executed."],
        "artifacts": ["report.json"]
    })
}

fn with_stage(mut report: Value, name: &str, status: &str, details: Value) -> Value {
    report["stage_results"] = json!([{
        "stage": name,
        "status": status,
        "details": details
    }]);
    report
}

fn add_error(report: &mut Value, error: impl Into<String>) {
    report["stage_errors"]
        .as_array_mut()
        .expect("base report has stage_errors")
        .push(json!(error.into()));
}

fn finish_error(output: &Path, mut report: Value, error: impl Into<String>) -> Result<(), String> {
    add_error(&mut report, error);
    report["status"] = json!("error");
    report["artifacts"] = json!(["report.json"]);
    write_report(output, &report)
}

fn normalize_cryptnek(output: &Path, input: &Path, bytes: &[u8], hash: &str) -> Result<(), String> {
    let stage_report: Value = fs::read(output.join("report.json"))
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))?;
    let mut report = base_report(input, bytes, hash, "cryptnek", "clean_lift");
    report = with_stage(report, "cryptnek_recovery", "passed", stage_report.clone());
    report["coverage"] = json!({
        "prototypes": stage_report["prototypes"],
        "reachable_instructions": stage_report["reachable_instructions"],
        "unsupported_instructions": stage_report["unsupported_instructions"],
        "syntax_validation": stage_report["clean_syntax_validation"]
    });
    report["limits"] = json!([
        "Only the exact inspected Cryptnek SHA-256 build is admitted.",
        "Names are inferred or neutral; original identifiers are not claimed.",
        "Application code and anti-tamper checks were not executed."
    ]);
    let artifacts = [
        "CoPlay_Legit_Trivia_Only.clean.luau",
        "anti-tamper-report.json",
        "report.json",
    ];
    if artifacts[..2]
        .iter()
        .any(|name| !output.join(name).is_file())
    {
        report["status"] = json!("error");
        add_error(
            &mut report,
            "Cryptnek recovery omitted a required clean artifact",
        );
    } else {
        report["artifacts"] = json!(artifacts);
    }
    write_report(output, &report)
}

fn normalize_batch(output: &Path, input: &Path, bytes: &[u8], hash: &str) -> Result<(), String> {
    let stage_report: Value = fs::read(output.join("report.json"))
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))?;
    let accepted = stage_report["status"] == "partial";
    let format = if accepted {
        "voltfuscator_outer"
    } else {
        "unknown"
    };
    let mut report = base_report(
        input,
        bytes,
        hash,
        format,
        if accepted { "partial" } else { "unsupported" },
    );
    report = with_stage(
        report,
        "outer_adapter",
        if accepted { "passed" } else { "failed" },
        json!({
            "adapter": stage_report["decoder_adapter"],
            "banner": stage_report["banner_family"],
            "details": stage_report
        }),
    );
    if let Some(error) = stage_report["error"].as_str() {
        add_error(&mut report, error);
    }
    report["coverage"] = if accepted {
        json!({"outer": stage_report["decoder"], "syntax_validation": stage_report["syntax_validation"]})
    } else {
        json!({"outer": "no validated adapter"})
    };
    report["limits"] = json!([
        "Only validated outer string adapters are accepted.",
        "The custom VM, original control flow, and protected application remain unrecovered.",
        "Application code was not executed."
    ]);
    if accepted && output.join("source.partial.luau").is_file() {
        report["artifacts"] = json!(["source.partial.luau", "report.json"]);
    } else if accepted {
        report["status"] = json!("error");
        add_error(
            &mut report,
            "Validated outer adapter did not produce its partial source artifact",
        );
    }
    write_report(output, &report)
}

fn copy_artifact(output: &Path, stage: &Path, name: &str) -> Result<(), String> {
    if !stage.join(name).is_file() {
        return Err(format!("Required lift artifact is missing: {name}"));
    }
    fs::copy(stage.join(name), output.join(name)).map_err(|e| e.to_string())?;
    Ok(())
}

fn exact_chess(input: &Path, output: &Path, bytes: &[u8], hash: &str) -> Result<(), String> {
    create_output_directory(output)?;
    let stage1 = output.join("stage1");
    let result = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg(input)
        .arg(&stage1)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| "Cannot start the outer decoder".to_string())?;
    if !result.status.success() {
        let report = base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "error");
        return finish_error(
            output,
            report,
            "Outer decode failed for the exact chess input",
        );
    }
    let outer_report: Value = fs::read(stage1.join("stats.json"))
        .map_err(|e| e.to_string())
        .and_then(|data| serde_json::from_slice(&data).map_err(|e| e.to_string()))?;
    let outer_source = stage1.join("chess.outer-decoded.luau");
    if !outer_source.is_file() {
        let mut report = base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "error");
        report = with_stage(report, "outer_decode", "failed", outer_report.clone());
        add_error(
            &mut report,
            "Outer decoder did not produce the expected decoded source",
        );
        return write_report(output, &report);
    }
    let stage2 = output.join("stage2");
    let lifted = fs::read_to_string(&outer_source)
        .map_err(|_| "Decoded outer source is not valid UTF-8".to_string())
        .and_then(|source| crate::vm::lift(&source, &stage2));
    match lifted {
        Ok(()) => {
            if let Err(error) = copy_artifact(output, &stage2, "chess.lifted.luau")
                .and_then(|()| copy_artifact(output, &stage2, "lift-report.json"))
            {
                let mut report =
                    base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "error");
                report = with_stage(report, "outer_decode", "passed", outer_report);
                return finish_error(output, report, error);
            }
            let lift_report: Value = match fs::read(stage2.join("lift-report.json"))
                .map_err(|e| e.to_string())
                .and_then(|data| serde_json::from_slice(&data).map_err(|e| e.to_string()))
            {
                Ok(report) => report,
                Err(error) => {
                    let mut report =
                        base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "error");
                    report = with_stage(report, "outer_decode", "passed", outer_report);
                    return finish_error(
                        output,
                        report,
                        format!("Lift report is unavailable: {error}"),
                    );
                }
            };
            let mut report =
                base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "clean_lift");
            report = with_stage(report, "outer_decode", "passed", outer_report.clone());
            report["stage_results"].as_array_mut().unwrap().push(json!({
                "stage": "vm_lift",
                "status": "passed",
                "details": lift_report
            }));
            report["coverage"] = json!({"outer": outer_report["decoder"], "lift": lift_report});
            report["limits"] = json!([
                "Only the exact inspected chess v8.1 SHA-256 build is admitted for clean lift.",
                "The lift is static and does not execute the protected application.",
                "External modules and live Roblox behavior remain unvalidated."
            ]);
            report["artifacts"] = json!(["chess.lifted.luau", "lift-report.json", "report.json"]);
            write_report(output, &report)
        }
        Err(error) => {
            let partial = output.join("chess.partial.luau");
            if let Err(copy_error) = fs::copy(&outer_source, &partial) {
                let mut report =
                    base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "error");
                report = with_stage(report, "outer_decode", "passed", outer_report);
                return finish_error(
                    output,
                    report,
                    format!("Cannot write partial output: {copy_error}"),
                );
            }
            let mut report = base_report(input, bytes, hash, "voltfuscator_v8_1_chess", "partial");
            report = with_stage(report, "outer_decode", "passed", outer_report);
            report["stage_results"].as_array_mut().unwrap().push(json!({
                "stage": "vm_lift",
                "status": "failed",
                "details": error
            }));
            add_error(&mut report, format!("VM lift failed: {error}"));
            report["coverage"] = json!({"outer": "validated", "vm_lift": "failed"});
            report["limits"] = json!([
                "Outer strings were validated, but the VM lift did not complete.",
                "The partial artifact is not verified devirtualized source.",
                "Application code was not executed."
            ]);
            report["artifacts"] = json!(["chess.partial.luau", "report.json"]);
            write_report(output, &report)
        }
    }
}

pub fn run(input: &Path, output: &Path) -> Result<(), String> {
    let _reservation = reserve_output_directory(output)?;
    let size = match fs::metadata(input) {
        Ok(metadata) => metadata.len(),
        Err(_) => {
            create_output_directory(output)?;
            let mut report = base_report(input, &[], "", "unknown", "error");
            report["input_bytes"] = Value::Null;
            report["input_sha256"] = Value::Null;
            return finish_error(output, report, "Input file could not be read");
        }
    };
    if size > MAX_AUTO_INPUT {
        create_output_directory(output)?;
        let report = base_report(input, &[], "", "unknown", "unsupported");
        return finish_error(
            output,
            report,
            "Input exceeds the 64 MiB auto-recovery limit",
        );
    }
    let bytes = match fs::read(input) {
        Ok(bytes) => bytes,
        Err(_) => {
            create_output_directory(output)?;
            let report = base_report(input, &[], "", "unknown", "error");
            return finish_error(output, report, "Input could not be read");
        }
    };
    let hash = format!("{:x}", Sha256::digest(&bytes));
    if hash == CRYPTNEK_SHA256 {
        let source = std::str::from_utf8(&bytes)
            .map_err(|e| format!("Exact Cryptnek input is not UTF-8: {e}"))?;
        match crate::cryptnek::recover(source, output) {
            Ok(()) => normalize_cryptnek(output, input, &bytes, &hash),
            Err(error) => {
                if !output.exists() {
                    create_output_directory(output)?;
                }
                let report = base_report(input, &bytes, &hash, "cryptnek", "error");
                finish_error(output, report, format!("Cryptnek recovery failed: {error}"))
            }
        }
    } else if hash == CHESS_SHA256 {
        exact_chess(input, output, &bytes, &hash)
    } else {
        crate::batch::decode_file(input, output)?;
        normalize_batch(output, input, &bytes, &hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_reservation_excludes_a_second_auto_job() {
        let parent = std::env::temp_dir().join(format!("auto-lock-{}", std::process::id()));
        let output = parent.join("output");
        fs::create_dir_all(&parent).unwrap();

        let reservation = reserve_output_directory(&output).unwrap();
        assert!(reserve_output_directory(&output).is_err());
        drop(reservation);
        let retry = reserve_output_directory(&output).unwrap();
        drop(retry);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn output_directory_creation_is_atomic_and_preserves_existing_contents() {
        let parent = std::env::temp_dir().join(format!("auto-output-{}", std::process::id()));
        let output = parent.join("output");
        fs::create_dir_all(&parent).unwrap();
        create_output_directory(&output).unwrap();
        fs::write(output.join("preserve.txt"), b"keep").unwrap();

        assert!(create_output_directory(&output).is_err());
        assert_eq!(fs::read(output.join("preserve.txt")).unwrap(), b"keep");
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn report_has_only_basename_artifacts() {
        let report = base_report(
            Path::new("C:\\secret\\input.lua"),
            b"",
            "hash",
            "unknown",
            "unsupported",
        );
        assert_eq!(report["input_file"], "input.lua");
        assert_eq!(report["artifacts"], json!(["report.json"]));
    }
}
