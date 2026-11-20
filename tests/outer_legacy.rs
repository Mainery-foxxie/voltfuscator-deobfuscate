pub use chess_deobf::{Token, lex, lua_string, number, vm};
#[path = "../src/outer_legacy.rs"]
mod outer_legacy;

fn samples() -> std::path::PathBuf {
    std::env::var_os("VOLTFUSCATOR_SAMPLE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("voltfusctarosamples")
        })
}

#[test]
fn legacy_representatives_decode_strings_preserving_wrappers() {
    for name in ["fetched (52).lua", "fetched (17).lua"] {
        let path = samples().join(name);
        if !path.exists() {
            eprintln!("External corpus unavailable: {}", path.display());
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let (decoded, report) =
            outer_legacy::recover(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(report["status"], "partial");
        assert!(
            report["replaced_calls"].as_u64().unwrap() > 10,
            "{name}: {report}"
        );
        assert!(decoded.starts_with(&source[..source.find("return({").unwrap()]));
        assert!(decoded.contains("getfenv"));
        assert!(decoded.len() < source.len());
    }
}

#[test]
fn unsupported_banner_has_clear_error() {
    assert!(
        outer_legacy::recover("return 42")
            .unwrap_err()
            .contains("Unsupported")
    );
    assert!(outer_legacy::recover(&format!("{}é", "x".repeat(199))).is_err());
}

#[test]
fn changed_decoder_is_never_evaluated() {
    let path = samples().join("fetched (52).lua");
    if !path.exists() {
        return;
    }
    let source = std::fs::read_to_string(path).unwrap();
    let source = source.replacen("local p={0x66782A67", "local p={0x66782A68", 1);
    assert!(
        outer_legacy::recover(&source)
            .unwrap_err()
            .contains("verified")
    );
}

#[test]
fn changed_decoder_environment_is_unsupported() {
    let path = samples().join("fetched (52).lua");
    if !path.exists() {
        return;
    }
    let source = std::fs::read_to_string(path).unwrap().replacen(
        "h=function(V,...)",
        "h=function(V,...)string.byte=function() return 0 end;",
        1,
    );
    assert!(outer_legacy::recover(&source).is_err());
}

fn application(app: &str) -> Option<String> {
    let path = samples().join("fetched (52).lua");
    if !path.exists() {
        return None;
    }
    let source = std::fs::read_to_string(path).unwrap();
    let boundary = source
        .find("return(function(q,Z,H,G,p,d,L,u,A,D,g,v,M,N,y,t,w,E,z,k,W,s,Q)")
        .unwrap();
    Some(format!(
        "{}return (function() {app} end)() end}}):h()",
        &source[..boundary]
    ))
}

#[test]
fn lexical_calls_preserve_strings_comments_and_shadowed_parameters() {
    let Some(source) = application(
        r#"local text='l.k(0x12CA,0x7861,0)'; -- l.k(0x12CA,0x7861,0)
        local function shadow(l) return l.k(0x12CA,0x7861,0) end
        return l.k(0x12CA,0x7861,0), (l).k((0b1001011000000 + 0xA),30817.0__,0_),
            l.k(4810,30817,0)..(l).k(4810,30817,0)
    "#,
    ) else {
        return;
    };
    let (decoded, report) = outer_legacy::recover(&source).unwrap();
    assert_eq!(report["replaced_calls"], 4, "{report}");
    assert!(decoded.contains("local text='l.k(0x12CA,0x7861,0)'"));
    assert!(decoded.contains("-- l.k(0x12CA,0x7861,0)"));
    assert!(decoded.contains("return l.k(0x12CA,0x7861,0) end"));
    assert!(decoded.contains("return \"t\", \"t\","));
    assert!(decoded.contains("\"t\"..\"t\""));
}

#[test]
fn mutated_or_escaped_alias_is_unsupported() {
    for app in [
        r#"l.k=function() return 'changed' end; return l.k(0x12CA,0x7861,0)"#,
        r#"local escaped=l; change(escaped); return l.k(0x12CA,0x7861,0)"#,
        r#"l={k=function() return 'changed' end}; return l.k(0x12CA,0x7861,0)"#,
        r#"do local l=l; change(l) end; return l.k(0x12CA,0x7861,0)"#,
        r#"function l.k() return 'changed' end; return l.k(0x12CA,0x7861,0)"#,
        r#"for l in iterator(l) do change(l) end; return l.k(0x12CA,0x7861,0)"#,
    ] {
        let Some(source) = application(app) else {
            return;
        };
        assert!(
            outer_legacy::recover(&source).is_err(),
            "Unsafe alias was replaced: {app}"
        );
    }
}

#[test]
fn invalid_admission_and_side_effectful_arguments_are_preserved() {
    let Some(source) = application(
        "return l.k(4810,30817,0), l.k(4810,30818,0), l.k(4810,30817,explode()), l.k(48 .. 10,30817,0)",
    ) else {
        return;
    };
    let (decoded, report) = outer_legacy::recover(&source).unwrap();
    assert_eq!(report["replaced_calls"], 1);
    assert_eq!(report["rejected_constant_calls"], 1);
    assert_eq!(report["dynamic_calls"], 2);
    assert!(decoded.contains("return \"t\", l.k(4810,30818,0), l.k(4810,30817,explode())"));
    assert!(decoded.contains("l.k(48 .. 10,30817,0)"));
}

#[test]
fn all_legacy_corpus_files_are_attempted() {
    let directory = samples();
    if !directory.exists() {
        return;
    }
    let mut names: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|p| p.unwrap().path())
        .collect();
    names.sort();
    let mut attempted = 0;
    let mut failures = Vec::new();
    for path in names {
        let source = std::fs::read_to_string(&path).unwrap();
        if !source[..source.len().min(200)].contains("dsc.gg/Obfuscating") {
            continue;
        }
        attempted += 1;
        match outer_legacy::recover(&source) {
            Ok((decoded, report)) => {
                let lua = vm::restricted_lua().unwrap();
                if let Err(error) = lua.load(&decoded).into_function() {
                    failures.push(format!("{} compile only: {error}", path.display()));
                }
                eprintln!("{}: {report}", path.file_name().unwrap().to_string_lossy());
            }
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }
    assert_eq!(attempted, 13);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
