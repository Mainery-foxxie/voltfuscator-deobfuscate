use mlua::{Lua, LuaOptions, StdLib, Value, VmState};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    path::Path,
    rc::Rc,
    time::{Duration, Instant},
};

pub fn restricted_lua() -> mlua::Result<Lua> {
    let lua = Lua::new_with(
        StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::BIT,
        LuaOptions::default(),
    )?;
    lua.set_memory_limit(256 * 1024 * 1024)?;
    for key in [
        "require",
        "loadstring",
        "load",
        "dofile",
        "loadfile",
        "io",
        "os",
        "package",
        "debug",
        "print",
    ] {
        lua.globals().set(key, mlua::Nil)?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    lua.set_interrupt(move |_| {
        if Instant::now() >= deadline {
            return Err(mlua::Error::RuntimeError(
                "Decoder time limit reached".into(),
            ));
        }
        Ok(VmState::Continue)
    });
    Ok(lua)
}

fn replace_once(source: &str, marker: &str, replacement: &str) -> Result<String, String> {
    if source.matches(marker).count() != 1 {
        return Err(format!(
            "Expected a single inspected extraction boundary: {marker}"
        ));
    }
    Ok(source.replacen(marker, replacement, 1))
}

pub fn extract(source: &str, output: &Path) -> Result<(), String> {
    extract_mode(source, output, false)
}

pub fn lift(source: &str, output: &Path) -> Result<(), String> {
    extract_mode(source, output, true)
}

fn extract_mode(source: &str, output: &Path, lifting: bool) -> Result<(), String> {
    let start = source
        .find("return({qf=")
        .ok_or("Missing inspected loader table")?;
    let end = source
        .rfind("}):qt()")
        .ok_or("Missing inspected loader invocation")?;
    if start > end {
        return Err("Invalid loader boundaries".into());
    }
    let code = format!("{})", &source[start..end + 1]);
    let code = replace_once(
        &code,
        "return dv(dM,dB,nil,{},0,47,true,dc)",
        "return {root=dM, reader=dB, metadata=dw, constants=zs, key=zj, constantContext=dW, predicate=dF(dc,\"__volt_predicate_262dee66401d0dac\")}",
    )?;
    let code = replace_once(&code, "for gF,gn in", "_SAVE(\"gB\",gB); for gF,gn in")?;
    let code = replace_once(
        &code,
        "))()return(function(zzq",
        "))()_SAVE(\"zzM\",zzM); return(function(zzq",
    )?;
    let code = replace_once(
        &code,
        "local oL,ob,oY,ot,of,oe,oZ=Xg(oW)",
        "local oL,ob,oY,ot,of,oe,oZ=Xg(oW); _WIDTH_RECORD(oW,oZ);",
    )?;
    let code = replace_once(
        &code,
        "local zaC,zaD,zaH,zaI,zaL,zab,zaY=zKA(zal)",
        "local zaC,zaD,zaH,zaI,zaL,zab,zaY=zKA(zal); _WIDTH_RECORD(zal,zaY);",
    )?;
    let code = replace_once(
        &code,
        "local zca,zcG,zcO,zcc,zci,zcx,zcM=zGR(zOj)",
        "local zca,zcG,zcO,zcc,zci,zcx,zcM=zGR(zOj); _WIDTH_RECORD(zOj,zcM);",
    )?;
    let code = replace_once(
        &code,
        "local oP=XZ if oP then",
        "local oP=XZ if oP and not _LIFTING then",
    )?;
    let code = replace_once(
        &code,
        "elseif oW~=1 then",
        "elseif not _LIFTING and oW~=1 then",
    )?;
    let code = replace_once(
        &code,
        "local zaW=zKe if zaW then",
        "local zaW=zKe if zaW and not _LIFTING then",
    )?;
    let code = replace_once(
        &code,
        "elseif zal~=1 then",
        "elseif not _LIFTING and zal~=1 then",
    )?;
    let code = replace_once(
        &code,
        "local zcS=zON if zcS then",
        "local zcS=zON if zcS and not _LIFTING then",
    )?;
    let code = replace_once(
        &code,
        "elseif zOj~=1 then",
        "elseif not _LIFTING and zOj~=1 then",
    )?;
    let constant_start = code
        .find("local mb=zu[\"setmetatable\"]")
        .ok_or("Missing inspected constant facade")?;
    let constant_end = constant_start
        + code[constant_start..]
            .find("return ow,mS,mb,mi")
            .ok_or("Missing constant facade end")?;
    let code = format!(
        "{}local mb=Xn; {}",
        &code[..constant_start],
        &code[constant_end..]
    );
    let code = replace_once(
        &code,
        "local function mi(mx)local mM=XZ",
        "local function mi(mx)if _LIFTING then return function() return true end end; local mM=XZ",
    )?;
    let code = replace_once(
        &code,
        "Bk=Ak BP={}Bx=BP for xc=1,#AB[8][1],1 do",
        "_BINDINGS(AB[8][1]); Bk=Ak BP={}Bx=BP for xc=1,#AB[8][1],1 do",
    )?;
    let code = replace_once(
        &code,
        "zuP={}zSG=zuP for zAj=1,#zdy[0x8][1],1 do",
        "_BINDINGS(zdy[8][1]); zuP={}zSG=zuP for zAj=1,#zdy[0x8][1],1 do",
    )?;
    let code = replace_once(&code, "Bp=AD[2]BB[1]=Bp", "Bp=AD[2]BB[1]=Bp _BINDINGS(Bp);")?;
    let code = replace_once(
        &code,
        "zdf=zuL[2]zuH[1]=zdf",
        "zdf=zuL[2]zuH[1]=zdf _BINDINGS(zdf);",
    )?;
    let code = replace_once(
        &code,
        "Ag=AB[5][1][Bp]BK=Ag",
        r#"
        if BD and BD._capture then
            local meta=AB[5][1][Bp]
            if meta and meta[3] and meta[3][1] and meta[3][1][1]==-2 then
                return AB[10][1](Bp,AD,BD)
            end
            return nil
        end
        if BD and BD._tuples then
            local tuples={}
            local offsets={
                [25]={{7,11,19}},[119]={{7,11,19}},[163]={{7}},[180]={{8,11}},
                [157]={{8,11}},[253]={{7,12,16}},[171]={{7,12,16}},[100]={{7}},[128]={{7}},
                [110]={{7,20,23,27},{31,35,39,43}},
                [90]={{7,11,24,27},{31,35,39,43},{47}},
                [81]={{7,11,15,23},{31,35,39,43},{51,59,63,67},{71,79,87,91},{95,99,107,115},{119,123}}
            }
            for group,indices in offsets[Bp] or {} do
                    local values={}
                    for j,index in indices do
                        values[j]=AB[11][1](AD[3],index)-AB[5][1][Bp][2]
                    end
                    tuples[group+1]=values
            end
            return tuples
        end
        local op,aa,bb,cc=AB[11][1](AD[3])
        if _LIFTING then
            AD[7],AD[8],AD[9],AD[10]=op,aa+AD[15],bb+AD[15],cc+AD[15]
            local words={}
            for i=2,AD[4] do
                if i%4~=1 then words[i]=AB[11][1](AD[3],i)-AB[5][1][Bp][2] end
            end
            return {op,AD[8],AD[9],AD[10],words}
        end
        do return {op,aa,bb,cc} end
        Ag=AB[5][1][Bp]BK=Ag
    "#,
    )?;
    // Linear inspection supplies the current PC because application handlers never advance it.
    let code = replace_once(
        &code,
        "Bk,BD,AV,BK=Ak,AK,An,6",
        "Bk,BD,AV,BK=Ak,AK,An,6 AB[4][1]=Bk[5]",
    )?;
    let code = replace_once(
        &code,
        "Bb()BZ,Bb,Bl=BI",
        "_RUNTIME(AV,Bk,AU,Bn); BE[6]=BI[6]; AB[15][1]=nil; AB[14][1]=true; BZ,Bb,Bl=BI",
    )?;
    let byte_guard = "AV,Bk=An,Ak if not AB[0X2][1][0xb](Bk,AV,AB[1][1])";
    let code = replace_once(
        &code,
        byte_guard,
        &format!("do return _STRINGBYTE(AB,An) end; {byte_guard}"),
    )?;
    let second_byte_guard = "zuU,zSS=zdA,zdB if not zdy[0X2][1][11](zSS,zuU,zdy[1][1])";
    let code = replace_once(
        &code,
        second_byte_guard,
        &format!("do return _STRINGBYTE(zdy,zdA) end; {second_byte_guard}"),
    )?;
    let code = replace_once(
        &code,
        "local zdG=0 local zdO={}",
        "_ENTRY(zdy); local zdG=0 local zdO={}",
    )?;
    let code = replace_once(
        &code,
        "local Ax=0 local AM={}",
        "_ENTRY(AB); local Ax=0 local AM={}",
    )?;
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    std::fs::write(output.join("extraction-loader.luau"), &code).map_err(|e| e.to_string())?;

    let lua = restricted_lua().map_err(|e| e.to_string())?;
    lua.globals()
        .set("_LIFTING", lifting)
        .map_err(|e| e.to_string())?;
    lua.globals()
        .set(
            "_BINDINGS",
            lua.create_function(|lua, data: mlua::Table| lua.globals().set("_CAPTURES", data))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let decoders = Rc::new(RefCell::new(BTreeMap::new()));
    let decoder_copy = decoders.clone();
    lua.globals()
        .set(
            "_SAVE",
            lua.create_function(move |_, (name, function): (String, mlua::Function)| {
                decoder_copy.borrow_mut().insert(name, function);
                Ok(())
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let entries = Rc::new(RefCell::new(VecDeque::<mlua::Table>::new()));
    let descriptors = Rc::new(RefCell::new(Vec::<mlua::Table>::new()));
    let descriptor_copy = descriptors.clone();
    let entry_copy = entries.clone();
    lua.globals()
        .set(
            "_ENTRY",
            lua.create_function(move |_, upvalues: mlua::Table| {
                let mut entries = entry_copy.borrow_mut();
                if entries.len() == 64 {
                    entries.pop_front();
                }
                entries.push_back(upvalues);
                Ok(())
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    lua.globals()
        .set(
            "_STRINGBYTE",
            lua.create_function(|_, (ab, index): (mlua::Table, usize)| {
                let cell = |i| ab.raw_get::<mlua::Table>(i);
                let length: usize = cell(4)?.raw_get(1)?;
                if index == 0 || index > length {
                    return Err(mlua::Error::RuntimeError(
                        "Protected string index out of range".into(),
                    ));
                }
                let mut state: u64 = cell(8)?.raw_get(1)?;
                let multiplier: u64 = cell(9)?.raw_get(1)?;
                let cipher: mlua::LuaString = cell(10)?.raw_get(1)?;
                let mut power = multiplier % 2147483647;
                let mut exponent = index;
                state %= 2147483647;
                while exponent > 0 {
                    if exponent % 2 == 1 {
                        state = state * power % 2147483647;
                    }
                    power = power * power % 2147483647;
                    exponent /= 2;
                }
                let byte = *cipher.as_bytes().get(4 + index).ok_or_else(|| {
                    mlua::Error::RuntimeError("Truncated protected string".into())
                })?;
                Ok((byte as i64 - (state % 256) as i64).rem_euclid(256) as u8)
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let frames = Rc::new(RefCell::new(BTreeMap::new()));
    let frame_copy = frames.clone();
    lua.globals().set("_RUNTIME",lua.create_function(move |lua,(opcode,instruction,operands,frame):(u64,mlua::Table,mlua::Table,mlua::Table)|{
        let constants:mlua::Table=lua.globals().get("_ROOTCONSTANTS")?;
        let mut decoded=serde_json::Map::new();
        let extra=lua.globals().get::<mlua::Table>("_TUPLES").ok();
        let mut candidates=operands.clone().sequence_values::<u64>().collect::<mlua::Result<Vec<_>>>()?;
        if let Some(tuples)=extra{for pair in tuples.pairs::<u64,mlua::Table>(){for pair in pair?.1.pairs::<u64,Value>(){if let Ok(token)=lua.unpack::<u64>(pair?.1){candidates.push(token);}}}}
        for token in candidates {
            if token>=256 {
                let index=token-token%256-(if token%512>=256{256}else{0})+1;
                let value=match constants.get::<Value>(index) {
                    Ok(value)=>recover_value(lua,value,&entries,&descriptor_copy)?,
                    Err(error)=>serde_json::json!({"error":error.to_string()}),
                };
                decoded.insert(index.to_string(),value);
            }
        }
        let prototype=lua.globals().get::<String>("_PROTOTYPE").unwrap_or_else(|_|"root".into());
        frame_copy.borrow_mut().insert(format!("{prototype}:{}",instruction.get::<u64>(5)?),serde_json::json!({"opcode":opcode,"handler_tag":frame.get::<u64>(7)?,"constants":decoded,"operands":dump_value(Value::Table(operands),&mut HashSet::new(),0)?}));
        Ok(())
    }).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let widths = Rc::new(RefCell::new(HashMap::new()));
    let width_copy = widths.clone();
    lua.globals()
        .set(
            "_WIDTH_RECORD",
            lua.create_function(move |_, (pc, width): (u64, u64)| {
                if width == 0 || width > 65536 {
                    return Err(mlua::Error::RuntimeError(
                        "Invalid instruction record width".into(),
                    ));
                }
                width_copy.borrow_mut().insert(pc, width);
                Ok(())
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    lua.globals()
        .set(
            "_WIDTH",
            lua.create_function(move |_, pc: u64| {
                Ok(widths.borrow().get(&pc).copied().unwrap_or(4))
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    lua.load(
        r#"
        workspace={ClassName="Workspace",__kind="Instance"}
        game={ClassName="DataModel",__kind="Instance"}
        workspace.Parent=game
        function game:GetService(name)
            if name=="Workspace" then return workspace end
            error("Extraction attempted an unprovided service: "..name)
        end
        Instance={new=function() error("Application Instance.new blocked") end}
        function typeof(value)
            if type(value)=="table" and rawget(value,"__kind") then return value.__kind end
            return type(value)
        end
        function getgenv() return {} end
        _G=getfenv()
        _ENV=_G
        __voltfuscator_ZEVcKRZyIzxyQy="File protected by Voltfuscator v8.1"
    "#,
    )
    .exec()
    .map_err(|e| e.to_string())?;
    lua.sandbox(true).map_err(|e| e.to_string())?;
    let pack: mlua::Table = lua
        .load(&code)
        .set_name("patched-loader")
        .eval()
        .map_err(|e| e.to_string())?;
    let factory: mlua::Function = pack.get("qf").map_err(|e| e.to_string())?;
    let (entry, _): (mlua::Function, Value) = factory
        .call((pack, mlua::Nil, lua.globals()))
        .map_err(|e| e.to_string())?;
    let captured: mlua::Table = entry.call(()).map_err(|e| e.to_string())?;
    let constants: mlua::Table = captured.get("constants").map_err(|e| e.to_string())?;
    crate::native::recover(source, &constants, &decoders.borrow(), output)?;
    let tokens = crate::lex(source)?;
    let shifts = lua.create_table().map_err(|e| e.to_string())?;
    for t in tokens.windows(12) {
        let text = |i: usize| &source[t[i].start..t[i].end];
        if text(0) == "Rc"
            && text(1) == "="
            && text(2) == "="
            && t[3].kind == "number"
            && text(4) == "then"
            && text(5) == "RJ"
            && text(6) == "="
            && text(7) == "zs"
            && text(8) == "["
            && t[9].kind == "number"
            && text(10) == "]"
        {
            shifts
                .set(
                    crate::number(text(3))?,
                    constants
                        .get::<Value>(crate::number(text(9))?)
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
        }
    }
    captured.set("shifts", shifts).map_err(|e| e.to_string())?;
    for key in ["root", "metadata", "constants"] {
        let value: Value = captured.get(key).map_err(|e| e.to_string())?;
        write_json(
            output,
            &format!("{key}.json"),
            &dump_value(value, &mut HashSet::new(), 0).map_err(|e| e.to_string())?,
        )?;
    }
    let records: mlua::Table = lua
        .load(if lifting {
            include_str!("lift.luau")
        } else {
            include_str!("extract.luau")
        })
        .set_name("instruction-extractor")
        .call(captured)
        .map_err(|e| e.to_string())?;
    if lifting {
        let mut result =
            dump_value(Value::Table(records), &mut HashSet::new(), 0).map_err(|e| e.to_string())?;
        result["frames"] = serde_json::json!(*frames.borrow());
        write_json(output, "lifted-ir.json", &result)?;
        let source = crate::source::emit(&result)?;
        mlua::chunk::Compiler::new()
            .compile(&source)
            .map_err(|e| e.to_string())?;
        std::fs::write(output.join("chess.lifted.luau"), &source).map_err(|e| e.to_string())?;
        let prototypes = result["prototypes"]
            .as_object()
            .ok_or("Missing decoded prototypes")?;
        let rows: Vec<_> = prototypes
            .values()
            .flat_map(|prototype| {
                prototype["rows"]
                    .as_object()
                    .into_iter()
                    .flat_map(|rows| rows.values())
            })
            .collect();
        let opcodes: std::collections::BTreeSet<_> = rows
            .iter()
            .filter_map(|row| row["opcode"].as_u64())
            .collect();
        let report = serde_json::json!({
            "status":"lifted", "adapter":"chess.luau / Voltfuscator v8.1", "prototypes":prototypes.len(),
            "reachable_records":rows.len(), "opcode_count":opcodes.len(), "opcodes":opcodes,
            "source":"chess.lifted.luau", "ir":"lifted-ir.json", "source_bytes":source.len(),
            "syntax_validation":"passed with Luau compiler", "unsupported_reachable_instructions":0,
            "behavioral_validation":"Run the CHESS_SAMPLE regression to compare with the native interpreter using local stand-ins; this command performs extraction and syntax checks only",
            "scope":"Adapter for the supplied sample; external modules and live Roblox or Discord behavior are not validated"
        });
        write_json(output, "lift-report.json", &report)?;
        println!(
            "Lifted {} prototypes, {} reachable records and {} opcodes to chess.lifted.luau",
            prototypes.len(),
            rows.len(),
            opcodes.len()
        );
        return Ok(());
    }
    let mut rows = Vec::new();
    for record in records.sequence_values::<Value>() {
        let mut row = dump_value(record.map_err(|e| e.to_string())?, &mut HashSet::new(), 0)
            .map_err(|e| e.to_string())?;
        if let Some(frame) = row["pc"]
            .as_u64()
            .and_then(|pc| frames.borrow().get(&format!("root:{pc}")).cloned())
        {
            row.as_object_mut()
                .ok_or("Invalid instruction record")?
                .extend(frame.as_object().ok_or("Invalid frame record")?.clone());
        }
        rows.push(row);
    }
    let stats = serde_json::json!({"instruction_records":rows.len(),"standard_frames_captured":frames.borrow().len(),"compound_or_unresolved_records":rows.len()-frames.borrow().len(),"application_handlers_executed":0,"behavioral_equivalence":"not verified"});
    let result = serde_json::json!({"status":"partial","instruction_count":rows.len(),"rows":rows,"coverage":stats,"note":"Linear record scan; reachability, compound handlers, child prototypes and contextual operand values are not fully verified. Constant handles apply only within their instruction record."});
    write_json(output, "instructions.json", &result)?;
    write_json(output, "extraction-stats.json", &stats)?;
    println!(
        "Extracted {} root records; captured {} standard frames before handler execution.",
        rows.len(),
        frames.borrow().len()
    );
    Ok(())
}

fn recover_value(
    lua: &Lua,
    value: Value,
    entries: &Rc<RefCell<VecDeque<mlua::Table>>>,
    descriptors: &Rc<RefCell<Vec<mlua::Table>>>,
) -> mlua::Result<serde_json::Value> {
    if !matches!(value, Value::Table(_)) {
        return dump_value(value, &mut HashSet::new(), 0);
    }
    let mut descriptor = None;
    for map in descriptors.borrow().iter() {
        if let Value::Table(found) = map.raw_get::<Value>(value.clone())? {
            descriptor = Some(found);
            break;
        }
    }
    if descriptor.is_none() {
        'search: for upvalues in entries.borrow().iter().rev().take(40) {
            for cell in upvalues.clone().sequence_values::<mlua::Table>() {
                if let Value::Table(map) = cell?.raw_get::<Value>(1)? {
                    if let Value::Table(found) = map.raw_get::<Value>(value.clone())? {
                        descriptor = Some(found);
                        descriptors.borrow_mut().push(map);
                        break 'search;
                    }
                }
            }
        }
    }
    let Some(descriptor) = descriptor else {
        return Ok(serde_json::json!({"unresolved":"protected value wrapper"}));
    };
    if let Value::Function(byte) = descriptor.raw_get::<Value>(5)? {
        let length = descriptor.raw_get::<usize>(1)?;
        if length > 2 * 1024 * 1024 {
            return Err(mlua::Error::RuntimeError(
                "Protected string length limit".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(length);
        for index in 1..=length {
            bytes.push(byte.call::<u8>((index, lua.create_table()?))?);
        }
        return Ok(serde_json::json!({"luau_string":crate::lua_string(&bytes)}));
    }
    Ok(serde_json::json!({"unresolved":"unrecognized protected value descriptor"}))
}

fn write_json(output: &Path, name: &str, value: &serde_json::Value) -> Result<(), String> {
    std::fs::write(
        output.join(name),
        serde_json::to_string_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn dump_value(
    value: Value,
    seen: &mut HashSet<usize>,
    depth: usize,
) -> mlua::Result<serde_json::Value> {
    Ok(match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(b) => b.into(),
        Value::Integer(n) => n.into(),
        Value::Number(n) if n.is_nan() => serde_json::json!({"luau_number":"0/0"}),
        Value::Number(n) if n.is_infinite() => {
            serde_json::json!({"luau_number":if n.is_sign_negative(){"-math.huge"}else{"math.huge"}})
        }
        Value::Number(n) if n == 0.0 && n.is_sign_negative() => {
            serde_json::json!({"luau_number":"-0.0"})
        }
        Value::Number(n) => serde_json::json!(n),
        Value::String(s) => serde_json::json!({"luau_string":crate::lua_string(&s.as_bytes())}),
        Value::Table(table) => {
            if depth > 40 || seen.len() > 100000 {
                return Err(mlua::Error::RuntimeError("Dump size/nesting limit".into()));
            }
            if !seen.insert(table.to_pointer() as usize) {
                serde_json::json!({"reference":true})
            } else {
                let mut values = BTreeMap::new();
                for pair in table.pairs::<Value, Value>() {
                    let (key, value) = pair?;
                    let key = match key {
                        Value::Integer(n) => n.to_string(),
                        Value::Number(n) => n.to_string(),
                        Value::String(s) => s
                            .to_str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|_| crate::lua_string(&s.as_bytes())),
                        other => format!("{other:?}"),
                    };
                    values.insert(key, dump_value(value, seen, depth + 1)?);
                }
                serde_json::json!(values)
            }
        }
        Value::Function(_) => serde_json::json!({"function":true}),
        other => serde_json::json!({"type":other.type_name()}),
    })
}
