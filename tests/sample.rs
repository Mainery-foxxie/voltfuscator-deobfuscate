use std::{fs, process::Command};

#[test]
#[ignore = "requires the original local sample via CHESS_SAMPLE"]
fn sample_recovery_keeps_the_input_and_reports_partial_coverage() {
    let input = std::env::var("CHESS_SAMPLE").expect("Set CHESS_SAMPLE to the original chess.luau");
    let original = fs::read(&input).unwrap();
    let destination =
        std::env::temp_dir().join(format!("chess-recovery-check-{}", std::process::id()));
    assert!(
        !destination.exists(),
        "Choose a fresh test process/output directory"
    );
    let worker = env!("CARGO_BIN_EXE_chess-deobf");
    let result = Command::new(worker)
        .arg("--recover")
        .arg(&input)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(
        report["input_sha256"],
        "8ec257c05b1e57e60631fe27da430cb50993f37b7fd25c76bab5704420db3ec6"
    );
    assert_eq!(report["outer_recovery"]["strings_validated"], 130);
    assert_eq!(report["outer_recovery"]["decoder_calls_replaced"], 672);
    assert_eq!(report["native_recovery"]["decoder_calls_replaced"], 1332);
    assert_eq!(report["native_recovery"]["unresolved_calls"], 0);
    let instructions: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("stage2/instructions.json")).unwrap())
            .unwrap();
    assert_eq!(instructions["instruction_count"], 103);
    assert_eq!(
        instructions["rows"][1]["constants"]["63489"]["luau_string"],
        "\"game\""
    );
    assert_eq!(
        instructions["rows"][2]["constants"]["41985"]["luau_string"],
        "\"GetService\""
    );
    assert_eq!(instructions["coverage"]["application_handlers_executed"], 0);
    let partial = fs::read(destination.join("result.partial.luau")).unwrap();
    assert!(partial.starts_with(b"-- PARTIAL RECOVERY:"));
    let duplicate = Command::new(worker)
        .arg("--recover")
        .arg(&input)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert_eq!(
        fs::read(destination.join("result.partial.luau")).unwrap(),
        partial
    );
    assert_eq!(fs::read(&input).unwrap(), original);
    fs::remove_dir_all(destination).unwrap();
}

#[test]
#[ignore = "requires the original local sample via CHESS_SAMPLE"]
fn lift_skips_junk_and_recovers_nested_functions() {
    let sample = std::env::var("CHESS_SAMPLE").expect("Set CHESS_SAMPLE");
    let outer = std::env::temp_dir().join(format!("chess-lift-outer-{}", std::process::id()));
    let destination = std::env::temp_dir().join(format!("chess-lift-check-{}", std::process::id()));
    let worker = env!("CARGO_BIN_EXE_chess-deobf");
    let result = Command::new(worker)
        .arg(sample)
        .arg(&outer)
        .output()
        .unwrap();
    assert!(result.status.success());
    let result = Command::new(worker)
        .arg("--lift")
        .arg(outer.join("chess.outer-decoded.luau"))
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let ir: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("lifted-ir.json")).unwrap()).unwrap();
    let rows = ir["prototypes"]["root"]["rows"].as_object().unwrap();
    assert_eq!(ir["predicate"]["nil"], false);
    assert_eq!(ir["predicate"]["function"], true);
    let row = rows.values().find(|row| row["pc"] == 89).unwrap();
    assert_eq!(row["opcode"], 53);
    assert!(
        ir["prototypes"].as_object().unwrap().len() > 1,
        "Nested prototypes were not decoded"
    );
    assert!(
        destination.join("chess.lifted.luau").is_file(),
        "Readable source lift is missing"
    );
    let source = fs::read_to_string(destination.join("chess.lifted.luau")).unwrap();
    let clean_source = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("output/devirtualized/chess.clean.luau"),
    )
    .expect("Clean standalone source is missing");
    assert_eq!(ir["prototypes"].as_object().unwrap().len(), 18);
    for (name, prototype) in ir["prototypes"].as_object().unwrap() {
        assert!(
            prototype["error"].is_null(),
            "{name}: {}",
            prototype["error"]
        );
        for row in prototype["rows"].as_object().unwrap().values() {
            assert!(
                row["frame_error"].is_null(),
                "{name}: {}",
                row["frame_error"]
            );
        }
    }
    for (job_id, quest_failure, purchase_failure, clipboard) in [
        ("fixture-job", 0, false, true),
        ("", 2, true, true),
        ("fixture-job", 0, false, false),
    ] {
        let mut lifted_snapshot = None;
        for variant in ["lifted", "clean", "reference"] {
            let lua = chess_deobf::vm::restricted_lua().unwrap();
            if variant == "reference" {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
                lua.set_interrupt(move |_| {
                    if std::time::Instant::now() >= deadline {
                        return Err(mlua::Error::RuntimeError(
                            "Reference fixture time limit reached".into(),
                        ));
                    }
                    Ok(mlua::VmState::Continue)
                });
            }
            let options = lua.create_table().unwrap();
            options.set("jobId", job_id).unwrap();
            options.set("questFailAt", quest_failure).unwrap();
            options.set("purchaseFails", purchase_failure).unwrap();
            options.set("clipboardEnabled", clipboard).unwrap();
            let events: mlua::Table = lua
                .load(include_str!("fixtures/roblox-standins.luau"))
                .call(options)
                .unwrap();
            if variant == "reference" {
                lua.load(r#"
                workspace.ClassName="Workspace"; game.ClassName="DataModel"; workspace.Parent=game
                Instance={new=function() error("Unexpected Instance.new") end}
                function typeof(value) if type(value)=="table" and value.ClassName then return "Instance" end return type(value) end
                function getgenv() return {} end
                _G=getfenv(); _ENV=_G
                __voltfuscator_ZEVcKRZyIzxyQy="File protected by Voltfuscator v8.1"
            "#).exec().unwrap();
                let original_outer =
                    fs::read_to_string(outer.join("chess.outer-decoded.luau")).unwrap();
                let start = original_outer.find("return({qf=").unwrap();
                let end = original_outer.rfind("}):qt()").unwrap();
                let loader = format!("{})", &original_outer[start..end + 1]);
                let pack: mlua::Table = lua.load(loader).eval().unwrap();
                let factory: mlua::Function = pack.get("qf").unwrap();
                let (entry, _): (mlua::Function, mlua::Value) =
                    factory.call((pack, mlua::Nil, lua.globals())).unwrap();
                entry.call::<()>(()).expect("Reference interpreter failed");
            } else {
                lua.load(if variant == "clean" {
                    &clean_source
                } else {
                    &source
                })
                .exec()
                .unwrap();
            }
            lua.globals().set("events", events).unwrap();
            lua.globals().set("questFailure", quest_failure).unwrap();
            lua.globals()
                .set("purchaseFailure", purchase_failure)
                .unwrap();
            lua.globals().set("clipboardEnabled", clipboard).unwrap();
            lua.load(r#"
            local count=0; for _ in events.buttons do count+=1 end
            assert(count==14, `Unexpected number of buttons: {count}`)
            events.buttons["Instant Quest"]()
            assert(#events.quests==35, `Quest coverage: {#events.quests}`)
            assert(#events.waits==35, `Quest waits: {#events.waits}`)
            assert(events.quests[1][1]=="Action" and events.quests[1][2]=="CatchSpirits" and events.quests[1][3]=="Tier3Catcher" and events.quests[1][4]==300)
            assert(events.quests[35][3]=="BananyaStarCollected" and events.quests[35][4]==80)
            local claims={
                {"Claim Jacket","PufferJacketUGC"}, {"Claim Helmet","HimesAviatorHelmet"},
                {"Claim Bananya","BananyaWeek1"}, {"Claim Bananya Week 3","BananyaWeek3"},
                {"Claim Enchanted Forest Premium","EnchantedForestUGC"}, {"Claim Skellybun Premium","SkellybunHeadUGC"},
                {"Claim Kabushi Premium","KabushiHelmetUGC"}, {"Claim Cucumboar Premium","CucumboarUGC"},
                {"Claim Erbbit Premium","ErbbitHatUGC"}, {"Claim Initial Bee","InitialBeeUGC"}, {"Claim Bee Premium","InitialBeePremiumUGC"}
            }
            for i,claim in claims do
                events.buttons[claim[1]]()
                assert(#events.purchases==i and events.purchases[i][2]==claim[2])
            end
            local questErrors=questFailure==0 and 0 or 1
            assert(#events.warned==questErrors+(purchaseFailure and 11 or 0), `Warnings: {#events.warned}`)
            assert(#events.printed==35-questErrors+(purchaseFailure and 0 or 11), `Prints: {#events.printed}`)
            events.buttons["Copy YouTube"](); events.buttons["Copy Discord"]()
            assert(#events.clipboard==(clipboardEnabled and 2 or 0))
            assert(#events.notifications==(clipboardEnabled and 2 or 0))
            if clipboardEnabled then
                assert(events.clipboard[1]=="https://youtube.com/@oxireunn?si=S0wXYpSBX3RAs2MB")
                assert(events.clipboard[2]=="https://discord.gg/qgV6v9WcE9")
            end
        "#).exec().unwrap();
            let snapshot:String=lua.load(r#"
            local function encode(value)
                if type(value)=="string" then return string.format("%q",value) end
                if type(value)~="table" then return tostring(value) end
                local keys={}; for key in value do keys[#keys+1]=key end
                table.sort(keys,function(a,b) return tostring(a)<tostring(b) end)
                local parts={}; for _,key in keys do parts[#parts+1]=encode(key)..":"..encode(value[key]) end
                return "{"..table.concat(parts,",").."}"
            end
            local snapshot={}
            for key,value in events do if key~="buttons" then snapshot[key]=value end end
            snapshot.buttons={}; for name in events.buttons do snapshot.buttons[#snapshot.buttons+1]=name end
            table.sort(snapshot.buttons)
            return encode(snapshot)
        "#).eval().unwrap();
            if variant != "lifted" {
                assert_eq!(
                    lifted_snapshot.as_ref(),
                    Some(&snapshot),
                    "{variant} effects differ from the generated lift"
                );
            } else {
                lifted_snapshot = Some(snapshot);
            }
        }
    }
    fs::remove_dir_all(outer).unwrap();
    fs::remove_dir_all(destination).unwrap();
}
