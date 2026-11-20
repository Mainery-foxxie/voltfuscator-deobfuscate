use std::{fs, process::Command};

#[test]
#[ignore = "requires the local sample via CRYPTNEK_SAMPLE"]
fn cryptnek_recovers_all_prototypes_without_running_the_application() {
    let input = std::env::var("CRYPTNEK_SAMPLE").expect("Set CRYPTNEK_SAMPLE");
    let original = fs::read(&input).unwrap();
    let output = std::env::temp_dir().join(format!("cryptnek-recovery-{}", std::process::id()));
    assert!(!output.exists());
    let mut worker = Command::new(env!("CARGO_BIN_EXE_chess-deobf"))
        .arg("--cryptnek")
        .arg(&input)
        .arg(&output)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        if worker.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            worker.kill().unwrap();
            let result = worker.wait_with_output().unwrap();
            panic!(
                "Cryptnek recovery exceeded 90 seconds: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let result = worker.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["prototypes"], 9);
    assert_eq!(report["payload_checksum"], 1810995613u64);
    assert_eq!(report["application_executed"], false);
    assert_eq!(report["unsupported_instructions"], 0);
    let source = fs::read_to_string(output.join("CoPlay_Legit_Trivia_Only.lifted.luau")).unwrap();
    assert!(!source.contains("IlD9uz58"));
    assert!(!source.contains("airKoR"));
    mlua::chunk::Compiler::new().compile(source).unwrap();
    let lifted = fs::read_to_string(output.join("CoPlay_Legit_Trivia_Only.lifted.luau")).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        format!("{:x}", Sha256::digest(lifted.as_bytes())),
        "0135f43644842ac4bd1b8f69741004879003e6c3650b61cb4167f59b5545e3e2",
        "The existing diagnostic lift changed"
    );
    let clean_path = output.join("CoPlay_Legit_Trivia_Only.clean.luau");
    assert!(clean_path.is_file(), "Missing readable application source");
    let clean = fs::read_to_string(clean_path).unwrap();
    assert!(
        !clean.contains("R["),
        "Clean output still indexes registers"
    );
    mlua::chunk::Compiler::new().compile(&clean).unwrap();
    let source_map: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("clean-source-map.json")).unwrap()).unwrap();
    assert_eq!(source_map["prototypes"].as_object().unwrap().len(), 9);
    let generated_lines = clean.lines().count() as u64;
    for span in source_map["generated_spans"].as_array().unwrap() {
        let start = span["start_line"].as_u64().unwrap();
        let end = span["end_line"].as_u64().unwrap();
        assert!(start > 0 && start <= end && end <= generated_lines);
    }
    for mapping in source_map["mappings"].as_array().unwrap() {
        let start = mapping["start_line"].as_u64().unwrap();
        let end = mapping["end_line"].as_u64().unwrap();
        assert!(
            source_map["generated_spans"]
                .as_array()
                .unwrap()
                .iter()
                .all(|span| {
                    end < span["start_line"].as_u64().unwrap()
                        || start > span["end_line"].as_u64().unwrap()
                }),
            "instruction mapping overlaps generated span"
        );
    }
    let anti_tamper: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("anti-tamper-report.json")).unwrap()).unwrap();
    assert_eq!(anti_tamper["analysis_mode"], "static_only");
    assert_eq!(anti_tamper["application_executed"], false);
    assert!(!anti_tamper["evidence"].as_array().unwrap().is_empty());
    let original_source = std::str::from_utf8(&original).unwrap();
    for (check, needle) in anti_tamper["checks"].as_array().unwrap().iter().zip([
        "if nDyNp8h7==398617549",
        "if n_CrYz~=1810995613",
        "Nw3EQlP~=1552315542",
        "YA4t7w[n_CrYz]==#wOSlm4Q",
    ]) {
        let offset = check["evidence_offset"].as_u64().unwrap() as usize;
        assert!(original_source.get(offset..).unwrap().starts_with(needle));
    }
    for evidence in anti_tamper["evidence"].as_array().unwrap() {
        let offset = evidence["source_offset"].as_u64().unwrap() as usize;
        assert!(original_source.get(offset..).is_some());
    }
    let original_boundary = "return VbYWBrZz(mqg6GkND[1],{},{n=0})";
    assert_eq!(original_source.matches(original_boundary).count(), 1);
    let original_helpers=original_source.replace(original_boundary,
        "local functions={} for id=1,9 do functions[id]=function(...) return VbYWBrZz(mqg6GkND[id],{},table.pack(...)) end end return functions");
    let lifted_helpers=lifted.replace("return prototypes[1]({}, ...)","local functions={} for id=1,9 do functions[id]=function(...) return prototypes[id]({},...) end end return functions");
    let mut expected = None;
    for helper in [original_helpers, lifted_helpers] {
        let lua = chess_deobf::vm::restricted_lua().unwrap();
        lua.load(r#"
            local env = getfenv()
            function getgenv() return env end
            local trace = {}
            function setclipboard(text) table.insert(trace, text) end
            local character = {PivotTo = function(self, ...) trace.pivot = table.pack(...) end}
            CFrame = {new = function(...) return ... end}
            game = {Players = {LocalPlayer = {Character=character, PlayerGui={JinxPoints={JinxPointsGuiPane={PointsMount={Face={Content={Total={Text="42"}}}}}}}}}}
            _TEST_TRACE = trace
        "#).exec().unwrap();
        let functions: mlua::Table = lua.load(helper).eval().unwrap();
        let setter: mlua::Function = functions.get(2).unwrap();
        setter.call::<()>("fixture-value").unwrap();
        assert_eq!(lua.globals().get::<String>("f").unwrap(), "fixture-value");
        let mut results = Vec::new();
        for id in [4, 5, 6, 8, 9] {
            let function: mlua::Function = functions.get(id).unwrap();
            let values: mlua::MultiValue = function.call(()).unwrap();
            results.push(format!("{id}:{values:?}"));
        }
        let trace: mlua::Table = lua.globals().get("_TEST_TRACE").unwrap();
        let first: String = trace.get(1).unwrap();
        let second: String = trace.get(2).unwrap();
        let pivot: mlua::Table = trace.get("pivot").unwrap();
        let snapshot = (
            results,
            first,
            second,
            pivot.get::<i32>("n").unwrap(),
            pivot.get::<f64>(1).unwrap(),
            pivot.get::<f64>(2).unwrap(),
            pivot.get::<f64>(3).unwrap(),
        );
        if let Some(expected) = &expected {
            assert_eq!(
                &snapshot, expected,
                "Lifted callbacks differ from the original interpreter"
            );
        } else {
            expected = Some(snapshot);
        }
    }
    let mut expected_application = None;
    for (variant, application) in [
        ("original", original_source),
        ("lifted", lifted.as_str()),
        ("clean", clean.as_str()),
    ] {
        let lua = chess_deobf::vm::restricted_lua().unwrap();
        let fixture: mlua::Table = lua
            .load(include_str!("fixtures/cryptnek-standins.luau"))
            .eval()
            .unwrap();
        if let Err(error) = lua.load(application).set_name(variant).exec() {
            assert!(
                error.to_string().contains("fixture-yield"),
                "Unexpected {variant} application fixture error: {error}"
            );
        }
        let callbacks: mlua::Table = fixture.get("callbacks").unwrap();
        assert!(callbacks.raw_len() > 0, "No callbacks were created");
        for callback in callbacks.sequence_values::<mlua::Table>() {
            let callback = callback.unwrap();
            let function: mlua::Function = callback.get("callback").unwrap();
            if callback.get::<String>("kind").unwrap() == "list" {
                let values: mlua::Table = callback.get("values").unwrap();
                if values.raw_len() > 0 {
                    function
                        .call::<()>(values.get::<mlua::Value>(1).unwrap())
                        .unwrap();
                }
            } else {
                function.call::<()>(()).unwrap();
            }
        }
        let jobs: mlua::Table = fixture.get("jobs").unwrap();
        for function in jobs.sequence_values::<mlua::Function>() {
            fixture
                .get::<mlua::Function>("setBudget")
                .unwrap()
                .call::<()>(1)
                .unwrap();
            let result = function.unwrap().call::<()>(());
            if let Err(error) = result {
                assert!(
                    error.to_string().contains("fixture-yield"),
                    "Unexpected {variant} background-job fixture error: {error}"
                );
            }
        }
        let snapshot: mlua::Function = fixture.get("snapshot").unwrap();
        let snapshot: String = snapshot.call(()).unwrap();
        if let Some(expected) = &expected_application {
            assert_eq!(&snapshot, expected, "Application fixture effects differ");
        } else {
            expected_application = Some(snapshot);
        }
    }
    assert_eq!(fs::read(&input).unwrap(), original);
    fs::remove_dir_all(output).unwrap();
}

#[test]
#[ignore = "requires the local sample via CRYPTNEK_SAMPLE"]
fn changed_cryptnek_handlers_are_rejected_before_creating_artifacts() {
    let input = std::env::var("CRYPTNEK_SAMPLE").expect("Set CRYPTNEK_SAMPLE");
    let original = fs::read_to_string(input).unwrap();
    let modified = original.replacen("R[a]=SqTuTAn[b]", "R[a]=nil", 1);
    assert_ne!(original, modified);
    let output =
        std::env::temp_dir().join(format!("cryptnek-changed-handler-{}", std::process::id()));
    assert!(!output.exists());
    assert!(chess_deobf::cryptnek::recover(&modified, &output).is_err());
    assert!(
        !output.exists(),
        "Modified loader was accepted and created artifacts"
    );
}

#[test]
#[ignore = "requires the local sample via CRYPTNEK_SAMPLE"]
fn cryptnek_recovery_refuses_an_existing_output_directory() {
    let input = std::env::var("CRYPTNEK_SAMPLE").expect("Set CRYPTNEK_SAMPLE");
    let source = fs::read_to_string(input).unwrap();
    let output =
        std::env::temp_dir().join(format!("cryptnek-existing-output-{}", std::process::id()));
    fs::create_dir(&output).unwrap();
    let marker = output.join("keep.txt");
    fs::write(&marker, b"preserve").unwrap();

    assert!(chess_deobf::cryptnek::recover(&source, &output).is_err());
    assert_eq!(fs::read(marker).unwrap(), b"preserve");
    fs::remove_dir_all(output).unwrap();
}
