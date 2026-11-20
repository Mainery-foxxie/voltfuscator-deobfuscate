use chess_deobf::{source, vm};
use serde_json::{Value, json};

fn row(pc: i64, opcode: i64, a: i64, b: i64, c: i64, successors: &[i64]) -> Value {
    json!({"pc":pc,"opcode":opcode,"a":a,"b":b,"c":c,"successors":successors})
}

fn program(rows: Vec<Value>, constants: Value) -> Value {
    json!({"prototypes":{"root":{"parameters":0,"registers":8,"vararg":false,"rows":rows}},"frames":constants})
}

#[test]
fn test_branch_keeps_the_native_skip_polarity() {
    for (input, expected) in [(false, 10), (true, 20)] {
        let ir = program(
            vec![
                row(1, 53, 0, i64::from(input), 0, &[5]),
                row(5, 1, 0, 0, 0, &[9, 13]),
                row(9, 32, 0, 1, 512, &[17]),
                row(13, 32, 0, 1, 1024, &[17]),
                row(17, 97, 0, 2, 1, &[]),
            ],
            json!({"root:9":{"constants":{"513":10}},"root:13":{"constants":{"1025":20}}}),
        );
        let code = source::emit(&ir).unwrap();
        let result: i64 = vm::restricted_lua().unwrap().load(code).eval().unwrap();
        assert_eq!(result, expected, "input={input}");
    }
}

#[test]
fn variable_arguments_keep_the_fixed_prefix_and_nil_results() {
    let ir = program(
        vec![
            row(1, 213, 512, 0, 0, &[5]),
            row(5, 32, 0, 1, 1024, &[9]),
            row(9, 213, 1536, 0, 2, &[13]),
            row(13, 72, 1, 2, 0, &[17]),
            row(17, 72, 0, 0, 0, &[21]),
            row(21, 97, 0, 0, 0, &[]),
        ],
        json!({
            "root:1":{"constants":{"513":{"luau_string":"\"collect\""}}},
            "root:5":{"constants":{"1025":42}},
            "root:9":{"constants":{"1537":{"luau_string":"\"produce\""}}}
        }),
    );
    let lua = vm::restricted_lua().unwrap();
    lua.load("function produce() return 88, nil, 90 end; function collect(...) return select('#', ...), ... end").exec().unwrap();
    let result: (i64, i64, i64, Option<i64>, i64) =
        lua.load(source::emit(&ir).unwrap()).eval().unwrap();
    assert_eq!(result, (4, 42, 88, None, 90));
}

#[test]
fn missing_constants_are_errors_instead_of_invented_nil() {
    let ir = program(
        vec![row(1, 32, 0, 0, 512, &[5]), row(5, 97, 0, 2, 0, &[])],
        json!({}),
    );
    assert!(source::emit(&ir).is_err());
}

#[test]
fn open_call_preserves_registers_beyond_its_actual_results() {
    let ir = program(
        vec![
            row(1, 32, 0, 5, 512, &[5]),
            row(5, 213, 1024, 0, 0, &[9]),
            row(9, 72, 1, 0, 0, &[13]),
            row(13, 97, 0, 2, 5, &[]),
        ],
        json!({"root:1":{"constants":{"513":42}},"root:5":{"constants":{"1025":{"luau_string":"\"empty\""}}}}),
    );
    let lua = vm::restricted_lua().unwrap();
    lua.load("function empty() end").exec().unwrap();
    let value: Option<i64> = lua.load(source::emit(&ir).unwrap()).eval().unwrap();
    assert_eq!(value, Some(42));
}

#[test]
fn structured_loop_revisits_its_header_and_takes_its_exit() {
    let ir = program(
        vec![
            row(1, 213, 512, 0, 1, &[5]),
            row(5, 158, 1, 0, 0, &[9]),
            row(9, 72, 1, 0, 2, &[13]),
            row(13, 1, 0, 0, 0, &[21, 5]),
            row(21, 97, 0, 1, 0, &[]),
        ],
        json!({"root:1":{"constants":{"513":{"luau_string":"\"tick\""}}}}),
    );
    let lua = vm::restricted_lua().unwrap();
    lua.load("count=0; function tick() count+=1; assert(count<=3); return count<3 end")
        .exec()
        .unwrap();
    lua.load(source::emit(&ir).unwrap()).exec().unwrap();
    assert_eq!(lua.globals().get::<i64>("count").unwrap(), 3);
}

#[test]
fn fused_quest_handler_writes_four_entries_and_starts_the_next() {
    let mut fused = row(9, 81, 512, 0, 0, &[133]);
    let mut tuples = json!({});
    let mut frames = json!({});
    let mut token = 1024;
    let values = [
        "Visit",
        "NotSpecified",
        "QuestHat",
        "1",
        "5",
        "Action",
        "NotSpecified",
        "LinkAccount",
        "1",
        "6",
        "Action",
        "CatchSpirits",
        "CatchSpirits",
        "50",
        "7",
        "Action",
        "NotSpecified",
        "LoginStreak14",
        "14",
        "8",
        "Action",
        "PlayGacha",
        "Bananya",
    ];
    for (i, value) in values.iter().enumerate() {
        let current = if i == 0 {
            512
        } else {
            let t = token;
            token += 512;
            t
        };
        frames[(current + 1).to_string()] = if let Ok(number) = value.parse::<i64>() {
            json!(number)
        } else {
            json!({"luau_string":format!("\"{value}\"")})
        };
    }
    let mut next = 1024;
    for (group, len) in [(2, 4), (3, 4), (4, 4), (5, 4), (6, 4), (7, 2)] {
        for index in 1..=len {
            tuples[group.to_string()][index.to_string()] = json!(next);
            next += 512;
        }
    }
    fused["tuples"] = tuples;
    let ir = program(
        vec![
            row(1, 8, 0, 0, 0, &[5]),
            row(5, 8, 0, 1, 0, &[9]),
            fused,
            row(133, 97, 0, 6, 0, &[]),
        ],
        json!({"root:9":{"constants":frames}}),
    );
    let lua = vm::restricted_lua().unwrap();
    let result: (mlua::Table, mlua::Table, String, String, String) =
        lua.load(source::emit(&ir).unwrap()).eval().unwrap();
    assert_eq!(
        result
            .0
            .get::<mlua::Table>(5)
            .unwrap()
            .get::<String>(1)
            .unwrap(),
        "Visit"
    );
    assert_eq!(
        result
            .0
            .get::<mlua::Table>(8)
            .unwrap()
            .get::<i64>(4)
            .unwrap(),
        14
    );
    assert_eq!(result.1.raw_len(), 0);
    assert_eq!(
        (result.2.as_str(), result.3.as_str(), result.4.as_str()),
        ("Action", "PlayGacha", "Bananya")
    );
}
