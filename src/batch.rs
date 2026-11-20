use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const INPUT_LIMIT: usize = 4 * 1024 * 1024;

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn banner(source: &str) -> &str {
    let Some(start) = source.find("Voltfuscator") else {
        return "unknown";
    };
    let header: String = source[start..].chars().take(100).collect();
    for family in [
        "7.6 Nyx", "7.7 Nyx", "v7.5", "v7.6", "7.7", "7.8", "v8.0", "v8.1",
    ] {
        if header.contains(family) {
            return family;
        }
    }
    "unknown"
}

fn recover(source: &str) -> Result<(String, Value, &'static str), String> {
    type Adapter = fn(&str) -> Result<(String, Value), String>;
    let mut adapters: [(&str, Adapter); 3] = [
        ("outer_v8", crate::outer_v8::recover),
        ("outer_nyx", crate::outer_nyx::recover),
        ("outer_legacy", crate::outer_legacy::recover),
    ];
    let preferred = match banner(source) {
        "7.6 Nyx" | "7.7 Nyx" | "7.7" | "7.8" => 1,
        "v7.5" | "v7.6" => 2,
        _ => 0,
    };
    adapters.swap(0, preferred);
    let mut errors = Vec::new();
    // Banners only prioritize attempts; each adapter must validate its real decoder.
    for (name, adapter) in adapters {
        match adapter(source) {
            Ok((decoded, stats)) => return Ok((decoded, stats, name)),
            Err(error) => errors.push(format!("{name}: {error}")),
        }
    }
    if banner(source) == "v8.1" {
        errors.push(
            "Use the existing 8.1 --recover/--lift pipeline for the inspected chess sample".into(),
        );
    }
    Err(format!(
        "No inspected decoder accepted this input. {}",
        errors.join("; ")
    ))
}

pub fn decode_file(input: &Path, output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err("Output directory already exists; choose a new directory".into());
    }
    let bytes = fs::read(input).map_err(|e| e.to_string())?;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::create_dir(output).map_err(|e| e.to_string())?;
    let mut report = json!({
        "input_file":input.file_name().map(|name|name.to_string_lossy().into_owned()),
        "input_bytes":bytes.len(), "input_sha256":format!("{:x}",Sha256::digest(&bytes)),
        "status":"unsupported", "application_executed":false,
        "source_file":null, "error":null,
        "note":"String decoding is partial recovery; the custom VM and protected application may remain"
    });
    let attempt = (|| -> Result<(), String> {
        if bytes.len() > INPUT_LIMIT {
            return Err("Input exceeds the 4 MiB batch limit".into());
        }
        let source = std::str::from_utf8(&bytes).map_err(|e| format!("Input is not UTF-8: {e}"))?;
        report["banner_family"] = json!(banner(source));
        let (decoded, stats, adapter) = recover(source)?;
        if decoded == source {
            return Err("Decoder returned unchanged source; no recovery accepted".into());
        }
        mlua::chunk::Compiler::new()
            .compile(&decoded)
            .map_err(|e| format!("Transformed source failed Luau syntax validation: {e}"))?;
        if fs::read(input).map_err(|e| e.to_string())? != bytes {
            return Err("Input changed during recovery".into());
        }
        let artifact = format!(
            "-- PARTIAL RECOVERY: validated string layers decoded; VM/application behavior is not fully recovered.\n{}",
            decoded.strip_prefix('\u{feff}').unwrap_or(&decoded)
        );
        mlua::chunk::Compiler::new()
            .compile(&artifact)
            .map_err(|e| format!("Final partial artifact failed Luau syntax validation: {e}"))?;
        fs::write(output.join("source.partial.luau"), artifact).map_err(|e| e.to_string())?;
        report["status"] = json!("partial");
        report["source_file"] = json!("source.partial.luau");
        report["decoder"] = stats;
        report["decoder_adapter"] = json!(adapter);
        report["syntax_validation"] = json!("passed with Luau compiler");
        Ok(())
    })();
    if let Err(error) = attempt {
        report["error"] = json!(error);
    }
    write_json(&output.join("report.json"), &report)
}

fn worker(input: &Path, output: &Path) -> Result<Value, String> {
    let log_path = output.with_extension("stderr.log");
    let log = fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg("--decode")
        .arg(input)
        .arg(output)
        .env_remove("DISCORD_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                if !status.success() {
                    let detail: String = fs::read_to_string(&log_path)
                        .unwrap_or_default()
                        .chars()
                        .take(2000)
                        .collect();
                    return Err(format!(
                        "Recovery worker exited with {status}: {}",
                        detail.trim()
                    ));
                }
                return serde_json::from_slice(
                    &fs::read(output.join("report.json")).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string());
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Recovery worker exceeded the 90-second limit".into());
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

pub fn run(input: &Path, output: &Path) -> Result<(), String> {
    if !input.is_dir() {
        return Err("Batch input must be a directory".into());
    }
    if output.exists() {
        return Err("Output directory already exists; choose a new directory".into());
    }
    let mut files: Vec<PathBuf> = fs::read_dir(input)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    files.retain(|path| {
        path.is_file()
            && path.extension().is_some_and(|extension| {
                ["lua", "luau", "txt"]
                    .iter()
                    .any(|allowed| extension.to_string_lossy().eq_ignore_ascii_case(allowed))
            })
    });
    files.sort();
    if files.is_empty() {
        return Err("No .lua, .luau or .txt files found".into());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::create_dir(output).map_err(|e| e.to_string())?;
    let work = output.join("stages");
    fs::create_dir(&work).map_err(|e| e.to_string())?;
    let mut cache: HashMap<String, (Value, PathBuf, String)> = HashMap::new();
    let mut results = Vec::new();
    let mut partial = 0;
    for (index, path) in files.iter().enumerate() {
        let name = path
            .file_name()
            .ok_or("Missing input filename")?
            .to_string_lossy()
            .into_owned();
        let bytes = fs::read(path).map_err(|e| format!("Cannot read {name}: {e}"))?;
        let hash = format!("{:x}", Sha256::digest(&bytes));
        if !cache.contains_key(&hash) {
            let stage = work.join(&hash);
            let report = worker(path,&stage).unwrap_or_else(|error| json!({
                "status":"unsupported","error":error,"application_executed":false,"source_file":null
            }));
            cache.insert(hash.clone(), (report, stage, name.clone()));
        }
        let (cached, stage, first) = &cache[&hash];
        let mut report = cached.clone();
        report["input_file"] = json!(name);
        report["input_sha256"] = json!(hash);
        report["input_bytes"] = json!(bytes.len());
        report["duplicate_of"] = if *first == name {
            Value::Null
        } else {
            json!(first)
        };
        if report["status"] == "partial" {
            let artifact = format!("{name}.partial.luau");
            fs::copy(stage.join("source.partial.luau"), output.join(&artifact))
                .map_err(|e| e.to_string())?;
            report["source_file"] = json!(artifact);
            partial += 1;
        }
        if fs::read(path).map_err(|e| e.to_string())? != bytes {
            return Err(format!("Input changed during batch: {name}"));
        }
        let report_file = format!("{name}.report.json");
        write_json(&output.join(&report_file), &report)?;
        println!(
            "[{}/{}] {}: {}",
            index + 1,
            files.len(),
            name,
            report["status"].as_str().unwrap_or("unknown")
        );
        results.push(json!({"input_file":name,"input_sha256":hash,"status":report["status"],"source_file":report["source_file"],"report":report_file}));
        write_json(
            &output.join("manifest.json"),
            &json!({
                "status":if results.len()==files.len(){"finished"}else{"running"},
                "input_files":files.len(),"unique_inputs":cache.len(),"attempted_files":results.len(),
                "fully_devirtualized":0,"partial":partial,"unsupported":results.len()-partial,
                "application_executed":false,"results":results
            }),
        )?;
    }
    let mut index = format!(
        "# Sample recovery results\n\nAttempted {} files / {} unique inputs.\n\nFully devirtualized: 0. Partial string recovery: {partial}. Unsupported: {}.\n\nPartial files still contain the custom VM. Unsupported files have a report only. Original inputs were preserved, and application code was not executed.\n\n| Input | Status | Source | Details |\n| --- | --- | --- | --- |\n",
        files.len(),
        cache.len(),
        files.len() - partial
    );
    for result in &results {
        let name = result["input_file"]
            .as_str()
            .ok_or("Missing result filename")?;
        let status = result["status"].as_str().ok_or("Missing result status")?;
        let source = result["source_file"]
            .as_str()
            .map(|name| format!("[Partial source](<{name}>)"))
            .unwrap_or_else(|| "—".into());
        let report = result["report"].as_str().ok_or("Missing report path")?;
        index.push_str(&format!(
            "| {name} | {status} | {source} | [Report](<{report}>) |\n"
        ));
    }
    fs::write(output.join("RESULTS.md"), index).map_err(|e| e.to_string())?;
    println!(
        "Attempted {} files / {} unique inputs: {partial} partial, {} unsupported. No full-VM recovery is claimed.",
        files.len(),
        cache.len(),
        files.len() - partial
    );
    Ok(())
}
