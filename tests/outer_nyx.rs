use chess_deobf::{ascii85, lex, lua_string, number};
mod vm {
    pub use chess_deobf::vm::restricted_lua;
}
#[path = "../src/outer_nyx.rs"]
mod outer_nyx;

const DECODER: &str = r#"local mY;do local mu=("")["byte"];local my=("")["char"];local mn=("")["sub"];local mo=("")["gsub"];local mx=error;local mR;local mj={};mY=function(mq)local mS=mj[mq];if mS~=nil then return mS end;local mU=(mq+48831)%65521;local me=(mq+48831)%2147483647;local mC=0;local function mb(mc)mU=(mU*187+1058+mC)%65521;mC+=1;local mJ=(mc-mU%256)%256;mU=(mU+mc)%65521;if mC<=4 or mC>8 then me=(me*33+mJ)%2147483647 end;return mJ end;local ms=mo(mR[mq],".....",function(mk)local mv,mP,mi,mN,mK=mu(mk,1,5);local mZ=((((mv-33)*85+mP-33)*85+mi-33)*85+mN-33)*85+mK-33;local mW=mZ%16777216;local mV=mZ%65536;local mr=mZ%256;local mE=mb((mZ-mW)/16777216);local mh=mb((mW-mV)/65536);local mA=mb((mV-mr)/256);local mf=mb(mr);return my(mE,mh,mA,mf)end);local mz,lm,ll,lL=mu(ms,1,4);local lH=mz+lm*256+ll*65536+lL*16777216;local lO,lD,lF,lw=mu(ms,5,8);if not lw or mC~=#ms or lH>#ms-8 or#ms-8-lH>3 or me~=lO+lD*256+lF*65536+lw*16777216 then mx("Voltfuscator: C052",0)end;ms=mn(ms,9,lH+8);if lH<=64 then mj[mq]=ms end;return ms end;mR={[967066640]=">;&aZ<+_q`rd2'5",[1664385257]="qB)(==G*UT&-+$(",[975737686]="O^k)YM7Hpb.7-ga"};end;"#;

const LENGTH_ONLY: &str = r#"local P;do local O={[617498143]="7QIP7DkJ&@"};local w={};local Y=("")["byte"];local F=("")["char"];local S=("")["sub"];local Z=("")["gsub"];P=function(X)local T=w[X];if T~=nil then return T end;local V=(X+5439)%65521;local Q=0;local function L(D)V=(V*175+1019+Q)%65521;Q+=1;local G=(D-V%256)%256;V=(V+D)%65521;return G end;local fl=Z(O[X],".....",function(U)local K,ff,ft,fa,fN=Y(U,1,5);local fg=((((K-33)*85+ff-33)*85+ft-33)*85+fa-33)*85+fN-33;local fp=fg%16777216;local fW=fg%65536;local fP=fg%256;local fm=L((fg-fp)/16777216);local fI=L((fp-fW)/65536);local fy=L((fW-fP)/256);local fu=L(fP);return F(fm,fI,fy,fu)end);local fH,fR,fJ,fz=Y(fl,1,4);local fM=fH+fR*256+fJ*65536+fz*16777216;fl=S(fl,5,fM+4);if fM<=64 then w[X]=fl end;return fl end end;"#;

#[test]
fn checksum_free_records_match_original_helper_without_application_execution() {
    let source = format!("{LENGTH_ONLY} return P(617498143),error('application must not execute')");
    let (out, stats) = outer_nyx::recover(&source).unwrap();
    assert!(out.starts_with(LENGTH_ONLY));
    assert!(out.ends_with("return \"eb\",error('application must not execute')"));
    assert_eq!(stats["layout"], "length-only-id-ascii85");
    assert_eq!(stats["cipher"]["checksum"], "not present in this layout");
    assert_eq!(stats["cipher"]["integrity_verified"], false);
    assert_eq!(stats["strings_decoded"], 1);
    // A well-framed ciphertext change is decodable but cannot be authenticated in this format.
    let (changed, changed_stats) =
        outer_nyx::recover(&source.replace("7QIP7DkJ&@", "7QIP7EkJ&@")).unwrap();
    assert!(changed.ends_with("return \"hq\",error('application must not execute')"));
    assert_eq!(changed_stats["cipher"]["integrity_verified"], false);
}

#[test]
fn checksum_free_malformed_records_and_uninspected_code_fail_closed() {
    let source = format!("{LENGTH_ONLY} return P(617498143)");
    for malformed in [
        "",
        "7QIP7DkJ&",
        "7QIP7DkJ&v",
        "uuuuuDkJ&@",
        "?QIP7DkJ&@",
        "7QIP7DkJ&@!!!!!",
    ] {
        assert!(
            outer_nyx::recover(&source.replace("7QIP7DkJ&@", malformed)).is_err(),
            "accepted {malformed:?}"
        );
    }
    assert!(outer_nyx::recover(&source.replace("Q+=1", "Q+=2")).is_err());
    assert!(outer_nyx::recover(&source.replace("V=(V+D)", "V=(V+G)")).is_err());
    assert!(
        outer_nyx::recover(&source.replace(
            "[617498143]=",
            "[617498143]=error('table must not execute'),[1]="
        ))
        .is_err()
    );
    assert!(
        outer_nyx::recover(&source.replace("};local w", ",[617498143]=\"7QIP7DkJ&@\"};local w"))
            .is_err()
    );
    assert!(outer_nyx::recover(&format!("{LENGTH_ONLY} return P(123)")).is_err());
    assert!(
        outer_nyx::recover(&format!(
            "{LENGTH_ONLY} local P=function()return 'shadow' end; return P(617498143)"
        ))
        .is_err()
    );
}

#[test]
fn checksum_free_helper_locals_do_not_alias_outer_wrapper_fields() {
    let source = format!("return({{Z=function(){LENGTH_ONLY} return P(617498143) end}}):Z()");
    let (out, stats) = outer_nyx::recover(&source).unwrap();
    assert!(out.ends_with("return \"eb\" end}):Z()"));
    assert_eq!(stats["calls_replaced"], 1);
}

#[test]
fn validated_calls_become_exact_strings_without_running_application() {
    let source = format!(
        "{DECODER} return mY(967066640),mY(1664385257),mY(975737686),error('application must not execute')"
    );
    let (out, stats) = outer_nyx::recover(&source).unwrap();
    assert!(out.starts_with(DECODER));
    assert!(
        out.ends_with("return \"type\",\"bxor\",\"_ENV\",error('application must not execute')")
    );
    assert_eq!(stats["strings_decoded"], 3);
    assert_eq!(stats["calls_replaced"], 3);
    assert_eq!(stats["status"], "partial");
}

#[test]
fn corruption_and_altered_decoder_are_rejected() {
    let source = format!("{DECODER} return mY(967066640)");
    assert!(outer_nyx::recover(&source.replace(">;&aZ", "?;&aZ")).is_err());
    assert!(outer_nyx::recover(&source.replace("me*33+mJ", "me*31+mJ")).is_err());
    assert!(outer_nyx::recover(&source.replace("mC+=1", "mC+=2")).is_err());
}

#[test]
fn comments_and_strings_are_immutable_and_shadowing_fails_closed() {
    let source = format!("{DECODER} -- mY(967066640)\nreturn 'mY(967066640)',mY(967066640)");
    let (out, _) = outer_nyx::recover(&source).unwrap();
    assert!(out.ends_with("-- mY(967066640)\nreturn 'mY(967066640)',\"type\""));
    for tail in [
        "local mY=function()return 'shadow' end;return mY(967066640)",
        "return function(mY)return mY(967066640)end",
        "mY=print;return mY(967066640)",
    ] {
        assert!(outer_nyx::recover(&format!("{DECODER}{tail}")).is_err());
    }
}

#[test]
fn inaccessible_binding_and_mutated_decoder_state_are_rejected() {
    let unrelated = DECODER.replacen("local mY;", "do local mY end;", 1);
    assert!(outer_nyx::recover(&format!("{unrelated} return mY(967066640)")).is_err());
    let mutated = DECODER.replacen(";end;", ";mj[967066640]='wrong';end;", 1);
    assert!(outer_nyx::recover(&format!("{mutated} return mY(967066640)")).is_err());
    let unrelated_table = DECODER
        .replace("mR={[", "local function uncalled() mR={[")
        .replace("};end;", "};end end;");
    assert!(outer_nyx::recover(&format!("{unrelated_table} return mY(967066640)")).is_err());
}

#[test]
fn multiline_call_replacement_preserves_debug_line_counts_and_inner_comments() {
    let source = format!("{DECODER} return mY(\n967066640\n),mY(-- keep this\n1664385257)");
    let (out, stats) = outer_nyx::recover(&source).unwrap();
    assert_eq!(
        out.bytes().filter(|b| *b == b'\n').count(),
        source.bytes().filter(|b| *b == b'\n').count()
    );
    assert!(out.contains("mY(-- keep this\n1664385257)"));
    assert_eq!(stats["calls_replaced"], 1);
}

#[test]
fn individually_attempt_supplied_nyx_corpus() {
    let Ok(folder) = std::env::var("NYX_SAMPLES") else {
        return;
    };
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read("output/sample-inventory.json").unwrap()).unwrap();
    let mut rows = Vec::new();
    for sample in inventory["samples"].as_array().unwrap() {
        let banner = sample["banners"][0].as_str().unwrap_or_default();
        if ![
            "Voltfuscator 7.6 Nyx",
            "Voltfuscator 7.7",
            "Voltfuscator 7.8",
        ]
        .iter()
        .any(|prefix| banner.starts_with(prefix))
        {
            continue;
        }
        let name = sample["name"].as_str().unwrap();
        let bytes = std::fs::read(std::path::Path::new(&folder).join(name)).unwrap();
        let source = std::str::from_utf8(&bytes).unwrap();
        let before = sha2::Sha256::digest(&bytes);
        assert_eq!(
            format!("{before:x}"),
            sample["sha256"].as_str().unwrap(),
            "Original sample changed: {name}"
        );
        let result = outer_nyx::recover(source);
        let row = match result {
            Ok((out, stats)) => {
                mlua::chunk::Compiler::new()
                    .compile(&out)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(stats["calls_replaced"].as_u64().unwrap() > 0, "{name}");
                if name == "fetched (24).lua" {
                    assert_eq!(stats["layout"], "positional-ascii85");
                    assert!(out.contains("Jq[\"string\"][\"byte\"]"));
                }
                if name == "fetched (1).lua" {
                    assert_eq!(stats["cipher"]["seed"], 5720);
                    assert!(out.contains("HQ[\"getfenv\"]"));
                    assert!(
                        outer_nyx::recover(&source.replace("if LY~=0 then", "if LY==0 then"))
                            .is_err()
                    );
                }
                if name == "fetched (13).lua" {
                    assert_eq!(stats["cipher"]["seed"], 288369);
                    assert!(
                        outer_nyx::recover(&source.replace(":IsClient()", ":IsStudio()")).is_err()
                    );
                }
                if [
                    "fetched (32).lua",
                    "fetched (33).lua",
                    "fetched (35).lua",
                    "fetched (36).lua",
                ]
                .contains(&name)
                {
                    let (salt, mul, add) = match name {
                        "fetched (35).lua" => (63536, 204, 4080),
                        "fetched (36).lua" => (5699, 218, 2709),
                        _ => (5439, 175, 1019),
                    };
                    assert_eq!(stats["layout"], "length-only-id-ascii85");
                    assert_eq!(stats["cipher"]["salt"], salt);
                    assert_eq!(stats["cipher"]["multiplier"], mul);
                    assert_eq!(stats["cipher"]["addend"], add);
                    assert_eq!(stats["cipher"]["integrity_verified"], false);
                }
                serde_json::json!({"name":name,"result":"partial","stats":stats})
            }
            Err(error) => {
                serde_json::json!({"name":name,"result":"unsupported","error":error,"original_syntax_error":mlua::chunk::Compiler::new().compile(source).err().map(|e|e.to_string())})
            }
        };
        assert_eq!(
            before.as_slice(),
            sha2::Sha256::digest(std::fs::read(std::path::Path::new(&folder).join(name)).unwrap())
                .as_slice()
        );
        println!("{}: {}", name, row);
        rows.push(row);
    }
    std::fs::create_dir_all("output/nyx-probes").unwrap();
    std::fs::write(
        "output/nyx-probes/corpus-validation.json",
        serde_json::to_string_pretty(&rows).unwrap(),
    )
    .unwrap();
    for required in [
        "fetched (24).lua",
        "fetched (26).lua",
        "fetched (1).lua",
        "fetched (13).lua",
        "fetched (32).lua",
        "fetched (33).lua",
        "fetched (35).lua",
        "fetched (36).lua",
    ] {
        let row = rows.iter().find(|row| row["name"] == required).unwrap();
        assert_eq!(row["result"], "partial", "{row}");
    }
}

use sha2::Digest;
