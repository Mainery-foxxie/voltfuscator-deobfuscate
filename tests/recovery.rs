use chess_deobf::{ascii85, lex, number};

#[test]
fn lua_number_bases() {
    assert_eq!(number("0Xc99f").unwrap(), 51615);
    assert_eq!(number("0b101010").unwrap(), 42);
    assert_eq!(number("2664108225").unwrap(), 2664108225);
    assert!(number("0xGG").is_err());
}

#[test]
fn strings_and_comments_are_not_decoder_calls() {
    let source = "zd(42); 'zd(43)\\\"'; [==[zd(44)]==] -- zd(45)\nzd(46)";
    let tokens = lex(source).unwrap();
    let identifiers: Vec<_> = tokens
        .iter()
        .filter(|t| t.kind == "ident")
        .map(|t| &source[t.start..t.end])
        .collect();
    assert_eq!(identifiers, ["zd", "zd"]);
    assert!(lex("[=[unterminated").is_err());
    assert!(lex("'unterminated").is_err());
    assert!(lex("`zd(47)`").is_err());
}

#[test]
fn ascii85_checks_length_and_overflow() {
    assert_eq!(ascii85(b"!!!!!").unwrap(), [0, 0, 0, 0]);
    assert_eq!(ascii85(b"s8W-!").unwrap(), [255, 255, 255, 255]);
    assert!(ascii85(b"!!!!").is_err());
    assert!(ascii85(b"uuuuu").is_err());
}

#[test]
fn extraction_runtime_has_no_host_capabilities() {
    let lua = chess_deobf::vm::restricted_lua().unwrap();
    let denied: bool = lua.load("return io == nil and os == nil and require == nil and loadstring == nil and debug == nil").eval().unwrap();
    assert!(denied);
    assert_eq!(
        lua.load("return bit32.bxor(12, 10)").eval::<u32>().unwrap(),
        6
    );
}

#[test]
fn authentic_outer_record_validates_and_corruption_is_rejected() {
    let ciphertext = r"CL1.]1PT=m%E8Rh%0Z\^";
    assert_eq!(
        chess_deobf::decrypt_record(1850342387, 2664108225, ciphertext).unwrap(),
        b"floor"
    );
    assert!(chess_deobf::decrypt_record(1850342387, 0, ciphertext).is_err());
    let mut corrupt = ciphertext.as_bytes().to_vec();
    corrupt[10] = b'!';
    assert!(
        chess_deobf::decrypt_record(
            1850342387,
            2664108225,
            std::str::from_utf8(&corrupt).unwrap()
        )
        .is_err()
    );
}

#[test]
fn binary_strings_use_unambiguous_luau_escapes() {
    assert_eq!(
        chess_deobf::lua_string(&[0, b'1', b'"', b'\\', 255]),
        r#""\0001\"\\\255""#
    );
}
