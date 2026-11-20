use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::Path,
};

fn xs(mut value: u32) -> u32 {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    value
}

fn rc4(data: &mut [u8], key: &[u8]) {
    let mut state: Vec<u8> = (0..=255).collect();
    let mut j = 0;
    for i in 0..256 {
        j = (j + state[i] as usize + key[i % key.len()] as usize) % 256;
        state.swap(i, j);
    }
    let (mut i, mut j) = (0, 0);
    for byte in data {
        i = (i + 1) % 256;
        j = (j + state[i] as usize) % 256;
        state.swap(i, j);
        *byte ^= state[(state[i] as usize + state[j] as usize) % 256];
    }
}

fn hash(data: &[u8]) -> u32 {
    data.iter().fold(5381u32, |state, byte| {
        state.wrapping_mul(33).wrapping_add(*byte as u32)
    })
}

fn quarter(mut s: [u32; 4]) -> [u32; 4] {
    for _ in 0..6 {
        s[0] = s[0].wrapping_add(s[1]);
        s[3] = (s[3] ^ s[0]).rotate_left(16);
        s[2] = s[2].wrapping_add(s[3]);
        s[1] = (s[1] ^ s[2]).rotate_left(12);
        s[0] = s[0].wrapping_add(s[1]);
        s[3] = (s[3] ^ s[0]).rotate_left(8);
        s[2] = s[2].wrapping_add(s[3]);
        s[1] = (s[1] ^ s[2]).rotate_left(7);
    }
    s
}
fn absorb(s: &mut [u32; 4], word: u32) {
    s[0] ^= word;
    *s = quarter(*s);
}
fn squeeze(s: &mut [u32; 4]) -> u32 {
    *s = quarter(*s);
    s[0]
}
fn initial(seed: u32) -> [u32; 4] {
    [1819631974 ^ seed, 1869771890, 1702064929, 1982947890]
}

fn quoted<'a>(source: &'a str, marker: &str) -> Result<&'a [u8], String> {
    let rest = source
        .split_once(marker)
        .ok_or_else(|| format!("Missing inspected Cryptnek field {marker}"))?
        .1;
    let end = rest.find('"').ok_or("Unterminated payload string")?;
    let value = &rest.as_bytes()[..end];
    if value.contains(&b'\\') {
        return Err("Unexpected payload escape".into());
    }
    Ok(value)
}

fn payload(source: &str) -> Result<Vec<u8>, String> {
    let data = quoted(source, "local airKoR=\"")?;
    let alphabet = quoted(source, "local lCbJBez0=\"")?;
    if data.len() != 30520 || alphabet.len() != 64 {
        return Err("Cryptnek layout differs from inspected input".into());
    }
    let mut digits = [None; 256];
    for (i, &byte) in alphabet.iter().enumerate() {
        if digits[byte as usize].replace(i as u32).is_some() {
            return Err("Duplicate base64 alphabet byte".into());
        }
    }
    let mut packed = Vec::with_capacity(22890);
    for chunk in data.chunks_exact(4) {
        let mut word = 0;
        for byte in chunk {
            word = (word << 6) | digits[*byte as usize].ok_or("Invalid payload alphabet byte")?;
        }
        packed.extend_from_slice(&[(word >> 16) as u8, (word >> 8) as u8, word as u8]);
    }
    let mut permutation: Vec<_> = (0..packed.len()).collect();
    let mut state = 1588031802;
    for i in (1..permutation.len()).rev() {
        state = xs(state);
        permutation.swap(i, state as usize % (i + 1));
    }
    let mut plain = vec![0; packed.len()];
    for (i, byte) in packed.iter().enumerate() {
        plain[permutation[i]] = *byte;
    }
    rc4(
        &mut plain,
        &[
            17, 225, 215, 96, 168, 1, 118, 160, 84, 223, 19, 26, 138, 18, 144, 183,
        ],
    );
    let mut state = 2555164698;
    for byte in &mut plain {
        state = xs(state);
        *byte ^= state as u8;
    }
    if hash(&plain) != 1810995613 {
        return Err("Cryptnek payload checksum mismatch".into());
    }
    Ok(plain)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.pos.checked_add(n).ok_or("Length overflow")?;
        let b = self
            .data
            .get(self.pos..end)
            .ok_or("Truncated Cryptnek payload")?;
        self.pos = end;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }
    fn word(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Constant {
    Nil,
    Bool(bool),
    Number(f64),
    String(Vec<u8>),
}
impl Constant {
    fn literal(&self) -> String {
        match self {
            Self::Nil => "nil".into(),
            Self::Bool(b) => b.to_string(),
            Self::Number(n) => n.to_string(),
            Self::String(s) => crate::lua_string(s),
        }
    }
    fn json(&self) -> Value {
        match self {
            Self::Nil => Value::Null,
            Self::Bool(b) => json!({"boolean":b}),
            Self::Number(n) => json!({"number":n}),
            Self::String(s) => json!({"luau_string":crate::lua_string(s)}),
        }
    }
}
#[derive(Debug, Clone)]
struct Prototype {
    start: usize,
    parameters: usize,
    vararg: bool,
    captures: Vec<(u8, usize)>,
    offset: usize,
    length: usize,
    tag: u32,
    native: u32,
}
#[derive(Debug, Clone)]
struct Instruction {
    pc: usize,
    opcode: u8,
    operands: Vec<usize>,
    next: usize,
}
struct Program {
    constants: Vec<Constant>,
    prototypes: Vec<Prototype>,
    code: Vec<u8>,
    payload: Vec<u8>,
    code_offset: usize,
}

fn parse(source: &str) -> Result<Program, String> {
    let data = payload(source)?;
    let mut reader = Reader {
        data: &data,
        pos: 0,
    };
    let count = reader.word()? as usize;
    if count > 10000 {
        return Err("Constant count limit".into());
    }
    let mut constants = Vec::new();
    for _ in 0..count {
        let tag = reader.byte()?;
        if tag == 1 {
            constants.push(Constant::Bool(reader.byte()? != 0));
        } else {
            let len = reader.word()? as usize;
            let value = reader.bytes(len)?;
            constants.push(if tag == 2 {
                Constant::Number(
                    std::str::from_utf8(value)
                        .map_err(|e| e.to_string())?
                        .parse::<f64>()
                        .map_err(|e| e.to_string())?,
                )
            } else {
                Constant::String(value.to_vec())
            });
        }
    }
    let count = reader.word()? as usize;
    if count != 9 {
        return Err(format!("Expected nine Cryptnek prototypes, got {count}"));
    }
    let mut prototypes = Vec::new();
    for _ in 0..count {
        let start = reader.word()? as usize;
        let vararg = reader.byte()? != 0;
        let parameters = reader.word()? as usize;
        let count = reader.word()? as usize;
        if count > 1000 {
            return Err("Capture count limit".into());
        }
        let mut captures = Vec::new();
        for _ in 0..count {
            captures.push((reader.byte()?, reader.word()? as usize));
        }
        prototypes.push(Prototype {
            start,
            parameters,
            vararg,
            captures,
            offset: reader.word()? as usize,
            length: reader.word()? as usize,
            tag: reader.word()?,
            native: reader.word()?,
        });
    }
    let count = reader.word()? as usize;
    let code_offset = reader.pos;
    let code = reader.bytes(count)?.to_vec();
    if reader.pos != data.len() {
        return Err("Unexpected trailing Cryptnek payload".into());
    }
    if hash(&code) != 398617549 {
        return Err("Cryptnek bytecode checksum mismatch".into());
    }
    Ok(Program {
        constants,
        prototypes,
        code,
        payload: data,
        code_offset,
    })
}

fn canonical(op: u8) -> u8 {
    match op {
        159 | 33 => 196,
        10 | 246 => 155,
        122 => 185,
        131 => 99,
        80 | 154 => 90,
        103 => 41,
        170 => 175,
        49 | 119 => 223,
        172 | 205 => 67,
        61 | 249 => 211,
        144 => 44,
        220 | 43 => 252,
        104 | 22 => 135,
        63 | 165 => 68,
        9 | 163 => 114,
        132 => 232,
        57 => 203,
        118 => 208,
        35 | 96 => 88,
        173 | 134 => 111,
        15 => 238,
        219 | 1 => 97,
        221 => 14,
        102 | 13 => 87,
        46 => 95,
        214 | 145 => 125,
        161 => 105,
        53 | 253 => 32,
        59 | 251 => 191,
        127 | 188 => 100,
        47 => 162,
        112 => 178,
        153 | 130 => 74,
        40 => 89,
        73 | 140 => 242,
        235 => 77,
        37 => 81,
        190 | 206 => 255,
        202 => 107,
        215 => 156,
        218 => 136,
        110 => 72,
        93 => 225,
        _ => op,
    }
}
fn operand_count(op: u8) -> Result<usize, String> {
    Ok(match canonical(op) {
        162 | 117 | 32 => 0,
        0 | 211 | 186 | 105 | 191 => 1,
        196 | 155 | 185 | 99 | 90 | 41 | 175 | 66 | 223 | 67 | 88 | 34 | 65 | 194 | 25 | 238
        | 97 | 14 | 87 | 184 | 139 | 178 | 74 => {
            if canonical(op) == 25 {
                1
            } else {
                2
            }
        }
        44 | 252 | 135 | 68 | 232 | 203 | 208 | 111 | 95 | 137 | 125 | 89 | 151 | 242 | 92
        | 255 | 107 | 136 => 3,
        114 | 100 | 77 | 81 | 48 | 156 | 72 | 31 | 225 | 237 | 50 => 4,
        _ => return Err(format!("Unknown Cryptnek opcode {op}")),
    })
}

fn instruction(code: &[u8], pc: usize, mask: &[u8]) -> Result<Instruction, String> {
    let offset = pc.checked_sub(1).ok_or("Invalid zero PC")?;
    let opcode =
        *code.get(offset).ok_or("PC past bytecode")? ^ mask.get(offset).copied().unwrap_or(0);
    let count = operand_count(opcode)?;
    let end = offset + 1 + count * 2;
    let data = code.get(offset + 1..end).ok_or("Truncated instruction")?;
    let operands = data
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .collect();
    Ok(Instruction {
        pc,
        opcode,
        operands,
        next: end + 1,
    })
}

fn dump(program: &Program) -> Value {
    json!({
        "constants":program.constants.iter().map(Constant::json).collect::<Vec<_>>(),
        "prototypes":program.prototypes.iter().enumerate().map(|(i,p)|json!({"id":i+1,"start":p.start,"parameters":p.parameters,"vararg":p.vararg,"captures":p.captures,"offset":p.offset,"length":p.length,"tag":p.tag,"native":p.native})).collect::<Vec<_>>()
    })
}

fn arithmetic(b: f64, c: f64, d: usize) -> Result<f64, String> {
    if d % 127 == 0 {
        Ok(b + c)
    } else if d % 193 == 0 {
        Ok(b - c)
    } else if d % 163 == 0 {
        Ok(b * c)
    } else if d % 151 == 0 {
        Ok(b / c)
    } else if d % 197 == 0 {
        Ok(b.powf(c))
    } else {
        Err(format!("Unrecognized arithmetic selector {d}"))
    }
}
fn bitword(value: f64) -> u32 {
    value.trunc().rem_euclid(4294967296.0) as u32
}
fn shift(a: u32, b: i64, left: bool) -> u32 {
    if b < 0 {
        return shift(a, -b, !left);
    }
    if b >= 32 {
        return 0;
    }
    if left { a << b } else { a >> b }
}
fn bitoperation(b: f64, c: f64, d: usize) -> Result<f64, String> {
    let (b, cw) = (bitword(b), bitword(c));
    Ok(if d % 167 == 0 {
        b ^ cw
    } else if d % 103 == 0 {
        b & cw
    } else if d % 107 == 0 {
        b | cw
    } else if d % 163 == 0 {
        shift(b, c as i64, true)
    } else if d % 193 == 0 {
        shift(b, c as i64, false)
    } else if d % 191 == 0 {
        b.rotate_left((c as i64).rem_euclid(32) as u32)
    } else {
        return Err(format!("Unrecognized bit selector {d}"));
    } as f64)
}

fn bootstrap(program: &Program) -> Result<u32, String> {
    let mut registers: HashMap<usize, f64> = HashMap::new();
    let mut packs: HashMap<usize, Vec<f64>> = HashMap::new();
    let mut pc = program.prototypes[8].start;
    for _ in 0..10000 {
        let row = instruction(&program.code, pc, &[])?;
        pc = row.next;
        let args = &row.operands;
        let reg = |i: usize| {
            registers
                .get(&i)
                .copied()
                .ok_or_else(|| format!("Uninitialized bootstrap register {i}"))
        };
        match canonical(row.opcode) {
            196 => {
                let Some(Constant::Number(value)) = program.constants.get(args[1]) else {
                    return Err("Bootstrap constant is not a number".into());
                };
                registers.insert(args[0], *value);
            }
            72 => {
                let value = arithmetic(reg(args[1])?, reg(args[2])?, args[3])?;
                registers.insert(args[0], value);
            }
            31 => {
                let value = bitoperation(reg(args[1])?, reg(args[2])?, args[3])?;
                registers.insert(args[0], value);
            }
            186 => {
                packs.insert(args[0], Vec::new());
            }
            14 => {
                let value = reg(args[1])?;
                packs
                    .get_mut(&args[0])
                    .ok_or("Bootstrap pack missing")?
                    .push(value);
            }
            105 => {
                return Ok(bitword(
                    *packs
                        .get(&args[0])
                        .and_then(|p| p.first())
                        .ok_or("Bootstrap did not return a numeric key")?,
                ));
            }
            117 | 162 => {}
            other => {
                return Err(format!(
                    "Bootstrap has non-arithmetic operation {other}; execution blocked"
                ));
            }
        }
    }
    Err("Bootstrap instruction limit".into())
}

fn unlock(program: &mut Program, boot: u32) -> Result<[u32; 4], String> {
    let mut skipped = BTreeSet::new();
    for p in &program.prototypes {
        if p.length > 0 {
            let start = program
                .code_offset
                .checked_add(p.offset.checked_sub(1).ok_or("Invalid encryption offset")?)
                .ok_or("Offset overflow")?;
            let end = start.checked_add(p.length).ok_or("Length overflow")?;
            if end > program.payload.len() {
                return Err("Encrypted region outside payload".into());
            }
            skipped.extend(start..end);
        }
    }
    let context = program
        .payload
        .iter()
        .enumerate()
        .filter(|(i, _)| !skipped.contains(i))
        .fold(5381u32, |state, (_, b)| {
            state.wrapping_mul(33).wrapping_add(*b as u32)
        });
    let mut seed = initial(2660417154);
    absorb(&mut seed, boot);
    absorb(&mut seed, context);
    let key = [
        squeeze(&mut seed),
        squeeze(&mut seed),
        squeeze(&mut seed),
        squeeze(&mut seed),
    ];
    for p in &program.prototypes {
        if p.length == 0 {
            continue;
        }
        let start = p.offset - 1;
        let end = start.checked_add(p.length).ok_or("Length overflow")?;
        let bytes = program
            .code
            .get_mut(start..end)
            .ok_or("Encrypted function outside bytecode")?;
        let mut state = key;
        absorb(&mut state, p.tag);
        for chunk in bytes.chunks_mut(4) {
            let word = squeeze(&mut state).to_le_bytes();
            for (byte, mask) in chunk.iter_mut().zip(word) {
                *byte ^= mask;
            }
        }
    }
    Ok(key)
}

fn mask(program: &Program, p: &Prototype, key: [u32; 4]) -> Vec<u8> {
    let mut masks = vec![0; program.code.len()];
    if p.tag == 0 {
        return masks;
    }
    let mut state = key[0] ^ 219735573 ^ p.tag;
    if state == 0 {
        state = 0x1D2C6F;
    }
    for index in p.start - 1..p.start - 1 + p.length {
        state = xs(state);
        masks[index] = state as u8;
    }
    masks
}

fn successors(row: &Instruction) -> Vec<usize> {
    match canonical(row.opcode) {
        105 | 32 => vec![],
        25 => vec![row.operands[0]],
        238 | 97 => vec![row.operands[1], row.next],
        _ => vec![row.next],
    }
}
fn decode(
    program: &Program,
    id: usize,
    key: [u32; 4],
) -> Result<BTreeMap<usize, Instruction>, String> {
    let p = &program.prototypes[id - 1];
    let masks = mask(program, p, key);
    let end = if p.length > 0 {
        p.start + p.length
    } else {
        program.code.len() + 1
    };
    let mut rows = BTreeMap::new();
    let mut pending = vec![p.start];
    while let Some(pc) = pending.pop() {
        if rows.contains_key(&pc) {
            continue;
        }
        if pc < p.start || pc >= end {
            return Err(format!("Branch outside prototype {id}: {pc}"));
        }
        let row = instruction(&program.code, pc, &masks)
            .map_err(|error| format!("Prototype {id} PC {pc}: {error}"))?;
        pending.extend(successors(&row));
        rows.insert(pc, row);
        if rows.len() > 20000 {
            return Err("Instruction count limit".into());
        }
    }
    let mut previous_end = p.start;
    for row in rows.values() {
        if row.pc < previous_end || row.next > end {
            return Err(format!(
                "Overlapping or out-of-range instruction at {id}:{}",
                row.pc
            ));
        }
        previous_end = row.next;
    }
    Ok(rows)
}

fn selected(d: usize, choices: &[(usize, &str)]) -> Result<String, String> {
    choices
        .iter()
        .find(|(divisor, _)| d % divisor == 0)
        .map(|(_, operation)| operation.to_string())
        .ok_or_else(|| format!("Unknown operation selector {d}"))
}

fn decoded_string(value: &[u8], mut seed: u32) -> Vec<u8> {
    if seed == 0 {
        seed = 0x1D2C6F;
    }
    let mut other = (!seed) ^ ((value.len() as u32).wrapping_mul(2654435761));
    if other == 0 {
        other = 0x9E3779B9;
    }
    value
        .iter()
        .map(|byte| {
            seed = xs(seed);
            other = xs(other);
            byte ^ (seed as u8) ^ (other as u8)
        })
        .collect()
}
fn truth(value: &Constant) -> bool {
    !matches!(value, Constant::Nil | Constant::Bool(false))
}

fn evaluate(
    program: &Program,
    row: &Instruction,
    state: &HashMap<usize, Constant>,
) -> Option<Constant> {
    let args = &row.operands;
    let b = args.get(1).copied().unwrap_or(0);
    let c = args.get(2).copied().unwrap_or(0);
    let d = args.get(3).copied().unwrap_or(0);
    let number = |index: usize| match state.get(&index) {
        Some(Constant::Number(n)) => Some(*n),
        _ => None,
    };
    let k = |index: usize| match program.constants.get(index) {
        Some(Constant::Number(n)) => Some(*n),
        _ => None,
    };
    let number_result = |n: f64| {
        if n.is_finite() {
            Some(Constant::Number(n))
        } else {
            None
        }
    };
    match canonical(row.opcode) {
        196 => program.constants.get(b).cloned(),
        0 => Some(Constant::Nil),
        155 => Some(Constant::Bool(b != 0)),
        185 => state.get(&b).cloned(),
        65 => Some(Constant::Bool(!truth(state.get(&b)?))),
        88 => number_result(-number(b)?),
        178 => number_result(-k(b)?),
        72 => number_result(arithmetic(number(b)?, number(c)?, d).ok()?),
        31 => number_result(bitoperation(number(b)?, number(c)?, d).ok()?),
        81 => number_result(number(b)? * number(c)? + number(d)?),
        156 => number_result(number(d)? + (bitword(number(b)?) & bitword(number(c)?)) as f64),
        89 => number_result(k(b)? * number(c)?),
        136 => number_result(number(c)? * k(b)?),
        107 => number_result(number(c)? + k(b)?),
        208 => {
            let (b, c) = (number(b)?, number(c)?);
            number_result(b - (b / c).floor() * c)
        }
        203 => number_result((number(b)? / number(c)?).floor()),
        194 => number_result((!bitword(number(b)?)) as f64),
        50 => {
            let (b, c) = (state.get(&b)?, state.get(&c)?);
            Some(Constant::Bool(
                ((b == c) as usize * (d % 109 == 0) as usize
                    + (b != c) as usize * (d % 103 == 0) as usize)
                    == 1,
            ))
        }
        225 | 237 => {
            let (b, c) = (number(b)?, number(c)?);
            Some(Constant::Bool(
                ((b < c) as usize * (d % 163 == 0) as usize
                    + (b <= c) as usize * (d % 109 == 0) as usize
                    + (b > c) as usize * (d % 113 == 0) as usize
                    + (b >= c) as usize * (d % 167 == 0) as usize)
                    == 1,
            ))
        }
        100 => match state.get(&b)? {
            Constant::String(bytes) => Some(Constant::String(decoded_string(
                bytes,
                (c + d * 65536) as u32,
            ))),
            _ => None,
        },
        111 => match (state.get(&b)?, state.get(&c)?) {
            (Constant::String(b), Constant::String(c)) => {
                Some(Constant::String([b.as_slice(), c.as_slice()].concat()))
            }
            _ => None,
        },
        34 => match state.get(&b)? {
            Constant::String(bytes) => number_result(bytes.len() as f64),
            _ => None,
        },
        _ => None,
    }
}

// Specialize only the first numeric selector; other registers merge conservatively at joins.
fn specialize(
    program: &mut Program,
    id: usize,
    rows: &BTreeMap<usize, Instruction>,
) -> Result<(BTreeMap<usize, Instruction>, BTreeMap<usize, Vec<usize>>), String> {
    use std::collections::VecDeque;
    #[derive(Clone, Default)]
    struct ConstantState {
        values: HashMap<usize, Constant>,
        source_pcs: HashMap<usize, BTreeSet<usize>>,
    }
    let p = &program.prototypes[id - 1];
    let first = &rows[&p.start];
    let selector = if canonical(first.opcode) == 196
        && matches!(
            program.constants.get(first.operands[1]),
            Some(Constant::Number(_))
        ) {
        Some(first.operands[0])
    } else {
        None
    };
    let context = |pc: usize, state: &ConstantState| {
        (
            pc,
            selector.and_then(|reg| match state.values.get(&reg) {
                Some(Constant::Number(n)) => Some(n.to_bits()),
                _ => None,
            }),
        )
    };
    let entry = (p.start, None);
    let mut states = HashMap::from([(entry, ConstantState::default())]);
    let mut edges = HashMap::new();
    let mut pending = VecDeque::from([entry]);
    let mut iterations = 0;
    while let Some(key) = pending.pop_front() {
        iterations += 1;
        if iterations > 100000 {
            return Err(format!("Prototype {id} selector analysis limit"));
        }
        let row = &rows[&key.0];
        let mut state = states[&key].clone();
        let op = canonical(row.opcode);
        if !matches!(
            op,
            41 | 66 | 67 | 252 | 68 | 114 | 232 | 25 | 238 | 97 | 14 | 87 | 105 | 32 | 162 | 117
        ) {
            let value = evaluate(program, row, &state.values);
            if let Some(value) = value {
                let mut source_pcs = register_reads(program, row)?
                    .iter()
                    .filter_map(|register| state.source_pcs.get(register))
                    .flatten()
                    .copied()
                    .collect::<BTreeSet<_>>();
                source_pcs.insert(key.0);
                state.values.insert(row.operands[0], value);
                state.source_pcs.insert(row.operands[0], source_pcs);
            } else {
                state.values.remove(&row.operands[0]);
                state.source_pcs.remove(&row.operands[0]);
            }
        }
        let mut next = successors(row);
        if matches!(op, 238 | 97) {
            if let Some(value) = state.values.get(&row.operands[0]) {
                let taken = if op == 238 {
                    truth(value)
                } else {
                    !truth(value)
                };
                next = vec![if taken { row.operands[1] } else { row.next }];
            }
        }
        let targets = next
            .into_iter()
            .map(|pc| context(pc, &state))
            .collect::<Vec<_>>();
        for target in &targets {
            if let Some(existing) = states.get_mut(target) {
                let before = existing.values.len();
                existing
                    .values
                    .retain(|reg, value| state.values.get(reg) == Some(value));
                let mut changed = before != existing.values.len();
                existing
                    .source_pcs
                    .retain(|register, _| existing.values.contains_key(register));
                for (register, source_pcs) in &state.source_pcs {
                    if existing.values.contains_key(register) {
                        let current = existing.source_pcs.entry(*register).or_default();
                        let before = current.len();
                        current.extend(source_pcs);
                        changed |= current.len() != before;
                    }
                }
                if changed {
                    pending.push_back(*target);
                }
            } else {
                states.insert(*target, state.clone());
                pending.push_back(*target);
            }
        }
        edges.insert(key, targets);
    }
    let mut order = vec![];
    let mut seen = BTreeSet::new();
    let mut pending = VecDeque::from([entry]);
    while let Some(key) = pending.pop_front() {
        if seen.insert(key) {
            order.push(key);
            pending.extend(&edges[&key]);
        }
    }
    let numbers = order
        .iter()
        .enumerate()
        .map(|(i, key)| (*key, p.start + i))
        .collect::<HashMap<_, _>>();
    let mut result = BTreeMap::new();
    let mut origins = BTreeMap::new();
    for key in order {
        let mut row = rows[&key.0].clone();
        let mut folded_sources = register_reads(program, &row)?
            .iter()
            .filter_map(|register| states[&key].source_pcs.get(register))
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>();
        folded_sources.insert(key.0);
        let mut folded = false;
        if canonical(row.opcode) != 196 {
            if let Some(value) = evaluate(program, &row, &states[&key].values) {
                let index = program.constants.len();
                program.constants.push(value);
                row.opcode = 196;
                row.operands = vec![row.operands[0], index];
                folded = true;
            }
        }
        row.pc = numbers[&key];
        let mut source_pcs = if folded {
            folded_sources
        } else {
            BTreeSet::from([key.0])
        }
        .into_iter()
        .collect::<Vec<_>>();
        if folded {
            source_pcs.retain(|source_pc| *source_pc != key.0);
            source_pcs.insert(0, key.0);
        }
        origins.insert(row.pc, source_pcs);
        let targets = edges[&key]
            .iter()
            .map(|key| numbers[key])
            .collect::<Vec<_>>();
        match targets.as_slice() {
            [] => {}
            [next] => {
                if matches!(canonical(row.opcode), 25 | 238 | 97) {
                    row.opcode = 25;
                    row.operands = vec![*next];
                }
                row.next = *next;
            }
            [yes, no] => {
                row.operands[1] = *yes;
                row.next = *no;
            }
            _ => return Err("Invalid specialized edge count".into()),
        }
        result.insert(row.pc, row);
    }
    remove_dead_constants(program, &mut result)?;
    Ok((result, origins))
}

fn register_reads(program: &Program, row: &Instruction) -> Result<BTreeSet<usize>, String> {
    let args = &row.operands;
    let a = args.first().copied().unwrap_or(0);
    let b = args.get(1).copied().unwrap_or(0);
    let c = args.get(2).copied().unwrap_or(0);
    let d = args.get(3).copied().unwrap_or(0);
    let reads = match canonical(row.opcode) {
        196 | 155 | 0 | 175 | 223 | 74 | 211 | 25 | 186 | 32 | 191 | 178 | 242 | 162 | 117 => {
            vec![]
        }
        185 | 99 | 90 | 88 | 34 | 65 | 194 | 139 | 44 | 125 | 92 | 77 | 48 | 100 => vec![b],
        41 | 14 | 87 => vec![a, b],
        66 | 67 => vec![b],
        252 => vec![a, c],
        135 | 203 | 208 | 111 | 95 | 255 | 72 | 31 | 225 | 237 | 50 => vec![b, c],
        68 => vec![a, b, c],
        114 => std::iter::once(a).chain(b..b + c).collect(),
        232 => vec![a, c],
        238 | 97 | 105 => vec![a],
        137 | 89 | 151 | 107 | 136 => vec![c],
        81 | 156 => vec![b, c, d],
        184 => program
            .prototypes
            .get(b)
            .ok_or("Invalid closure prototype during liveness")?
            .captures
            .iter()
            .filter(|(kind, _)| *kind == 1)
            .map(|(_, register)| *register)
            .collect(),
        op => return Err(format!("No register read semantics for opcode {op}")),
    };
    Ok(reads.into_iter().collect())
}
fn writes_register(op: u8) -> bool {
    !matches!(
        canonical(op),
        41 | 66 | 67 | 252 | 68 | 114 | 232 | 25 | 238 | 97 | 14 | 87 | 105 | 32 | 162 | 117
    )
}
fn remove_dead_constants(
    program: &Program,
    rows: &mut BTreeMap<usize, Instruction>,
) -> Result<(), String> {
    let reads = rows
        .iter()
        .map(|(pc, row)| Ok((*pc, register_reads(program, row)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let mut live = rows
        .keys()
        .map(|pc| (*pc, BTreeSet::<usize>::new()))
        .collect::<BTreeMap<_, _>>();
    loop {
        let mut changed = false;
        for (pc, row) in rows.iter().rev() {
            let mut before = successors(row)
                .iter()
                .flat_map(|next| live[next].iter().copied())
                .collect::<BTreeSet<_>>();
            if writes_register(row.opcode) {
                before.remove(&row.operands[0]);
            }
            before.extend(&reads[pc]);
            if before != live[pc] {
                live.insert(*pc, before);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for row in rows.values_mut() {
        if canonical(row.opcode) == 196
            && !successors(row)
                .iter()
                .any(|next| live[next].contains(&row.operands[0]))
        {
            row.opcode = 162;
            row.operands.clear();
        }
    }
    Ok(())
}

struct ReadableLocals {
    names: BTreeMap<usize, String>,
    cells: BTreeSet<usize>,
    roles: BTreeMap<usize, (String, String, Vec<usize>)>,
    kinds: BTreeMap<usize, String>,
}

impl ReadableLocals {
    fn read(&self, register: usize) -> Result<String, String> {
        let name = self
            .names
            .get(&register)
            .cloned()
            .unwrap_or_else(|| format!("value_{register}"));
        Ok(if self.cells.contains(&register) {
            format!("{name}[1]")
        } else {
            name
        })
    }

    fn write(&self, register: usize) -> Result<String, String> {
        self.read(register)
    }
}

fn identifier_part(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut result = String::new();
    let mut previous_lower = false;
    for ch in text.chars() {
        if ch.is_ascii_uppercase() {
            if previous_lower && !result.ends_with('_') {
                result.push('_');
            }
            result.push(ch.to_ascii_lowercase());
            previous_lower = false;
        } else if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            result.push(ch);
            previous_lower = ch.is_ascii_lowercase();
        } else if !result.is_empty() && !result.ends_with('_') {
            result.push('_');
            previous_lower = false;
        }
    }
    while result.ends_with('_') {
        result.pop();
    }
    (!result.is_empty()).then_some(result)
}

fn safe_global_name(bytes: &[u8]) -> Option<String> {
    let name = identifier_part(bytes)?;
    let reserved = [
        "and",
        "break",
        "continue",
        "do",
        "else",
        "elseif",
        "end",
        "export",
        "false",
        "for",
        "function",
        "if",
        "in",
        "local",
        "nil",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "true",
        "type",
        "typeof",
        "until",
        "while",
        "arguments",
        "cachedGlobal",
        "cachedNames",
        "decodeString",
        "environment",
        "globalCache",
        "method",
        "prototypes",
        "table",
        "string",
        "math",
        "bit32",
        "U",
    ];
    let mut bytes = name.bytes();
    let first = bytes.next()?;
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || reserved.contains(&name.as_str())
    {
        return None;
    }
    Some(name)
}

fn readable_locals(
    program: &Program,
    id: usize,
    rows: &BTreeMap<usize, Instruction>,
) -> Result<ReadableLocals, String> {
    #[derive(Clone)]
    enum Definition {
        Role(String, String, usize),
        Move(usize, usize),
        Unknown,
    }

    let prototype = &program.prototypes[id - 1];
    let mut registers = (0..prototype.parameters).collect::<BTreeSet<_>>();
    let mut definitions: BTreeMap<usize, Vec<Definition>> = BTreeMap::new();
    for register in 0..prototype.parameters {
        definitions
            .entry(register)
            .or_default()
            .push(Definition::Unknown);
    }
    let mut cells = BTreeSet::new();
    for row in rows.values() {
        registers.extend(register_reads(program, row)?);
        if canonical(row.opcode) == 184 {
            let child = program
                .prototypes
                .get(row.operands[1])
                .ok_or_else(|| format!("Invalid child prototype {} in {id}", row.operands[1]))?;
            for (kind, register) in &child.captures {
                if *kind == 1 {
                    cells.insert(*register);
                }
            }
        }
        if writes_register(row.opcode) {
            let destination = row.operands[0];
            registers.insert(destination);
            let role = match canonical(row.opcode) {
                223 | 74 => program.constants.get(row.operands[1]).and_then(|value| {
                    if let Constant::String(bytes) = value {
                        safe_global_name(bytes).map(|name| (name, "global".into()))
                    } else {
                        None
                    }
                }),
                44 => program.constants.get(row.operands[2]).and_then(|value| {
                    if let Constant::String(bytes) = value {
                        safe_global_name(bytes)
                            .map(|name| (format!("field_{name}"), "field".into()))
                    } else {
                        None
                    }
                }),
                242 => program.constants.get(row.operands[2]).and_then(|value| {
                    if let Constant::String(bytes) = value {
                        safe_global_name(bytes)
                            .map(|name| (format!("field_{name}"), "field".into()))
                    } else {
                        None
                    }
                }),
                77 => program.constants.get(row.operands[3]).and_then(|value| {
                    if let Constant::String(bytes) = value {
                        safe_global_name(bytes)
                            .map(|name| (format!("field_{name}"), "field".into()))
                    } else {
                        None
                    }
                }),
                48 => program.constants.get(row.operands[3]).and_then(|value| {
                    if let Constant::String(bytes) = value {
                        safe_global_name(bytes)
                            .map(|name| (format!("field_{name}"), "field".into()))
                    } else {
                        None
                    }
                }),
                99 if cells.contains(&destination) => {
                    Some(("captured_cell".into(), "mutable_capture_cell".into()))
                }
                184 => Some(("function_value".into(), "closure".into())),
                186 => Some(("results".into(), "multi_return_pack".into())),
                _ => None,
            };
            definitions
                .entry(destination)
                .or_default()
                .push(if let Some(role) = role {
                    let (name, kind) = role;
                    Definition::Role(name, kind, row.pc)
                } else if canonical(row.opcode) == 185 {
                    Definition::Move(row.operands[1], row.pc)
                } else {
                    Definition::Unknown
                });
        }
    }

    cells.retain(|register| registers.contains(register));
    let mut roles = BTreeMap::<usize, (String, String, Vec<usize>)>::new();
    for _ in 0..registers.len() {
        let mut changed = false;
        for (register, defs) in &definitions {
            if roles.contains_key(register) || defs.is_empty() {
                continue;
            }
            let resolved = defs
                .iter()
                .map(|definition| match definition {
                    Definition::Role(name, kind, pc) => {
                        Some((name.clone(), kind.clone(), vec![*pc]))
                    }
                    Definition::Move(source, pc) => roles.get(source).map(|(name, kind, pcs)| {
                        let mut pcs = pcs.clone();
                        pcs.push(*pc);
                        (name.clone(), kind.clone(), pcs)
                    }),
                    Definition::Unknown => None,
                })
                .collect::<Option<Vec<_>>>();
            if let Some(resolved) = resolved {
                if resolved
                    .windows(2)
                    .all(|pair| pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1)
                {
                    let mut pcs = resolved
                        .iter()
                        .flat_map(|(_, _, pcs)| pcs.iter().copied())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    pcs.sort_unstable();
                    roles.insert(
                        *register,
                        (resolved[0].0.clone(), resolved[0].1.clone(), pcs),
                    );
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut used = BTreeSet::from([
        "U".to_string(),
        "arguments".into(),
        "cachedGlobal".into(),
        "cachedNames".into(),
        "decodeString".into(),
        "environment".into(),
        "globalCache".into(),
        "method".into(),
        "prototypes".into(),
        "table".into(),
        "string".into(),
        "math".into(),
        "bit32".into(),
        "target".into(),
        "values".into(),
        "callable".into(),
        "extra".into(),
        "captures".into(),
        "i".into(),
        "n".into(),
        "result".into(),
        "name".into(),
    ]);
    let mut names = BTreeMap::new();
    let mut kinds = BTreeMap::new();
    for register in registers {
        let (candidate, kind) = match roles.get(&register) {
            Some((name, kind, _)) => (name.clone(), kind.clone()),
            None if register < prototype.parameters => {
                (format!("argument_{}", register + 1), "parameter".into())
            }
            None => (format!("value_{register}"), "neutral".into()),
        };
        let mut name = candidate.clone();
        if used.contains(&name) {
            name = format!("{candidate}_{register}");
        }
        if used.contains(&name) {
            name = format!("value_{register}");
        }
        used.insert(name.clone());
        names.insert(register, name);
        kinds.insert(register, kind);
    }
    Ok(ReadableLocals {
        names,
        cells,
        roles,
        kinds,
    })
}

fn mapped_instruction_end(lines: &[&str], marker_index: usize) -> usize {
    let Some(next) = lines.get(marker_index + 1).map(|line| line.trim()) else {
        return marker_index + 1;
    };
    if next.starts_with("--")
        || next == "else"
        || next == "end"
        || next == "continue"
        || next == "break"
        || next == "while true do"
        || next.starts_with("if ")
        || next.starts_with("local loopExit")
    {
        marker_index + 1
    } else {
        marker_index + 2
    }
}

fn emit_readable_function(
    program: &Program,
    id: usize,
    rows: &BTreeMap<usize, Instruction>,
    origins: &BTreeMap<usize, Vec<usize>>,
) -> Result<(String, Value), String> {
    use crate::source::Node;
    let prototype = &program.prototypes[id - 1];
    if prototype.native != 0 {
        return Err(format!(
            "Native Cryptnek function {id} cannot be lowered cleanly"
        ));
    }
    let locals = readable_locals(program, id, rows)?;
    let mut nodes = BTreeMap::new();
    let constant = |index: usize| {
        program
            .constants
            .get(index)
            .map(Constant::literal)
            .ok_or_else(|| format!("Invalid constant {index} in readable prototype {id}"))
    };
    for row in rows.values() {
        let args = &row.operands;
        let a = args.first().copied().unwrap_or(0);
        let b = args.get(1).copied().unwrap_or(0);
        let c = args.get(2).copied().unwrap_or(0);
        let d = args.get(3).copied().unwrap_or(0);
        let (ra, rb, rc, rd) = (
            locals.read(a)?,
            locals.read(b)?,
            locals.read(c)?,
            locals.read(d)?,
        );
        let wa = locals.write(a)?;
        let capture = match canonical(row.opcode) {
            175 | 151 => Some(b),
            66 => Some(a),
            _ => None,
        };
        if capture.is_some_and(|index| index >= prototype.captures.len()) {
            return Err(format!(
                "Invalid upvalue in readable prototype {id} at {}",
                row.pc
            ));
        }
        let mut condition = None;
        let code = match canonical(row.opcode) {
            196 => format!("{wa} = {}", constant(b)?),
            155 => format!("{wa} = {}", b != 0),
            0 => format!("{wa} = nil"),
            185 => format!("{wa} = {rb}"),
            99 => format!("{wa} = {{{rb}}}"),
            90 => format!("{wa} = {rb}[1]"),
            41 => format!("{ra}[1] = {rb}"),
            175 => format!("{wa} = U[{b}][1]"),
            66 => format!("U[{a}][1] = {rb}"),
            223 => format!("{wa} = cachedGlobal({})", constant(b)?),
            74 => format!("{wa} = environment[{}]", constant(b)?),
            67 => format!(
                "environment[{}] = {rb}; globalCache[{}] = nil",
                constant(a)?,
                constant(a)?
            ),
            211 => format!("{wa} = {{}}"),
            44 => format!("{wa} = {rb}[{}]", constant(c)?),
            252 => format!("{ra}[{}] = {rc}", constant(b)?),
            135 => format!("{wa} = {rb}[{rc}]"),
            68 => format!("{ra}[{rb}] = {rc}"),
            114 => {
                let mut statements = vec![format!("do local target = {ra}")];
                for index in 0..c {
                    statements.push(format!(
                        "target[{}] = {}",
                        d + index,
                        locals.read(b + index)?
                    ));
                }
                statements.push("end".into());
                statements.join("; ")
            }
            232 => format!(
                "do local target, values = {ra}, {rc}; for i = 1, values.n do target[{b} + i - 1] = values[i] end end"
            ),
            203 => format!("{wa} = math.floor({rb} / {rc})"),
            208 => format!("{wa} = {rb} % {rc}"),
            88 => format!("{wa} = -{rb}"),
            111 => format!("{wa} = {rb} .. {rc}"),
            34 => format!("{wa} = #{rb}"),
            65 => format!("{wa} = not {rb}"),
            194 => format!("{wa} = bit32.bnot({rb})"),
            25 | 162 | 117 => String::new(),
            238 => {
                condition = Some(ra);
                String::new()
            }
            97 => {
                condition = Some(format!("not {ra}"));
                String::new()
            }
            186 => format!("{wa} = {{n = 0}}"),
            14 => format!(
                "do local values = {ra}; local n = values.n + 1; values.n = n; values[n] = {rb} end"
            ),
            87 => format!(
                "do local values, extra = {ra}, {rb}; for i = 1, extra.n do local n = values.n + 1; values.n = n; values[n] = extra[i] end end"
            ),
            95 => format!(
                "do local callable, arguments = {rb}, {rc}; {wa} = table.pack(callable(table.unpack(arguments, 1, arguments.n))) end"
            ),
            137 => format!(
                "do local arguments = {rc}; {wa} = table.pack(method({})(table.unpack(arguments, 1, arguments.n))) end",
                constant(b)?
            ),
            125 => format!("{wa} = {rb}[{c}]"),
            105 => format!("return table.unpack({ra}, 1, {ra}.n)"),
            32 => "return".into(),
            184 => {
                let child = program
                    .prototypes
                    .get(b)
                    .ok_or_else(|| format!("Invalid child prototype {b}"))?;
                let mut captures = Vec::new();
                for (index, (kind, register)) in child.captures.iter().enumerate() {
                    if *kind != 1 && *register >= prototype.captures.len() {
                        return Err(format!(
                            "Invalid inherited capture {register} in readable prototype {id}"
                        ));
                    }
                    let value = if *kind == 1 {
                        if !locals.cells.contains(register) {
                            return Err(format!(
                                "Mutable capture {register} has no shared cell in prototype {id}"
                            ));
                        }
                        locals.read(*register)?
                    } else {
                        format!("U[{register}]")
                    };
                    captures.push(format!("[{index}] = {value}"));
                }
                format!(
                    "do local captures = {{{}}}; {wa} = function(...) return prototypes[{}](captures, ...) end end",
                    captures.join(", "),
                    b + 1
                )
            }
            191 => format!(
                "{wa} = table.pack(table.unpack(arguments, {}, arguments.n))",
                prototype.parameters + 1
            ),
            139 => format!("{wa} = type({rb})"),
            100 => format!("{wa} = decodeString({rb}, {})", c + d * 65536),
            178 => format!("{wa} = -({})", constant(b)?),
            89 => format!("{wa} = ({}) * {rc}", constant(b)?),
            151 => format!("{wa} = U[{b}][1][{rc}]"),
            242 => format!("{wa} = environment[{}][{}]", constant(b)?, constant(c)?),
            92 => format!("{wa} = {{{rb}[{c}]}}"),
            77 => format!("{wa} = {rb}[{}][{}]", constant(c)?, constant(d)?),
            81 => format!("{wa} = ({rb} * {rc}) + {rd}"),
            48 => format!("{wa} = {rb}[{c}][{}]", constant(d)?),
            255 => format!("{wa} = not ({rb}[{rc}])"),
            107 => format!("{wa} = {rc} + ({})", constant(b)?),
            156 => format!("{wa} = {rd} + bit32.band({rb}, {rc})"),
            136 => format!("{wa} = {rc} * ({})", constant(b)?),
            72 => format!(
                "{wa} = {rb} {} {rc}",
                selected(
                    d,
                    &[(127, "+"), (193, "-"), (163, "*"), (151, "/"), (197, "^")]
                )?
            ),
            31 => format!(
                "{wa} = bit32.{}({rb}, {rc})",
                selected(
                    d,
                    &[
                        (167, "bxor"),
                        (103, "band"),
                        (107, "bor"),
                        (163, "lshift"),
                        (193, "rshift"),
                        (191, "lrotate")
                    ]
                )?
            ),
            225 | 237 | 50 => {
                let choices: &[(usize, &str)] = if canonical(row.opcode) == 50 {
                    &[(109, "=="), (103, "~=")]
                } else {
                    &[(163, "<"), (109, "<="), (113, ">"), (167, ">=")]
                };
                let terms = choices
                    .iter()
                    .filter(|(divisor, _)| d % divisor == 0)
                    .map(|(_, op)| format!("(if {rb} {op} {rc} then 1 else 0)"))
                    .collect::<Vec<_>>();
                format!(
                    "{wa} = ({}) == 1",
                    if terms.is_empty() {
                        "0".into()
                    } else {
                        terms.join(" + ")
                    }
                )
            }
            op => {
                return Err(format!(
                    "No readable source semantics for opcode {op} at {id}:{}",
                    row.pc
                ));
            }
        };
        let source_pcs = origins
            .get(&row.pc)
            .ok_or_else(|| format!("Missing source PC for prototype {id}:{}", row.pc))?;
        let source_pc = source_pcs
            .first()
            .ok_or_else(|| format!("Empty source provenance for prototype {id}:{}", row.pc))?;
        nodes.insert(
            (row.pc - prototype.start + 1) as i64,
            Node {
                code: vec![
                    format!(
                        "-- @source {id}:{source_pc}:{}",
                        source_pcs
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    code,
                ]
                .into_iter()
                .filter(|line| !line.is_empty())
                .collect(),
                condition,
                successors: successors(row)
                    .iter()
                    .map(|pc| (*pc - prototype.start + 1) as i64)
                    .collect(),
            },
        );
    }
    let body =
        crate::source::structured(&nodes).map_err(|error| format!("Prototype {id}: {error}"))?;
    let names = locals.names.values().cloned().collect::<Vec<_>>();
    let mut out = format!(
        "prototypes[{id}] = function(U, ...)\n    -- Prototype {id}, bytecode offset {}\n    local arguments = table.pack(...)\n",
        prototype.start
    );
    if !names.is_empty() {
        out.push_str(&format!("    local {}\n", names.join(", ")));
    }
    for index in 0..prototype.parameters {
        let name = &locals.names[&index];
        if locals.cells.contains(&index) {
            out.push_str(&format!("    {name} = {{arguments[{}]}}\n", index + 1));
        } else {
            out.push_str(&format!("    {name} = arguments[{}]\n", index + 1));
        }
    }
    for register in &locals.cells {
        if *register >= prototype.parameters {
            let name = &locals.names[register];
            out.push_str(&format!("    {name} = {{}}\n"));
        }
    }
    for line in body.lines() {
        out.push_str("    ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("end\n");

    let register_map = locals
        .names
        .iter()
        .map(|(register, name)| {
            json!({
                "register": register,
                "name": name,
                "role": locals.kinds[register],
                "role_source_pcs": locals.roles.get(register).map(|(_, _, pcs)| pcs),
                "mutable_capture_cell": locals.cells.contains(register)
            })
        })
        .collect::<Vec<_>>();
    let mut mappings = Vec::new();
    let lines = out.lines().collect::<Vec<_>>();
    for (line, text) in lines.iter().enumerate() {
        let Some((prototype, mapping)) = text
            .trim()
            .strip_prefix("-- @source ")
            .and_then(|mapping| mapping.split_once(':'))
        else {
            continue;
        };
        let Some((source_pc, source_pcs)) = mapping.split_once(':') else {
            return Err(format!("Malformed source mapping in prototype {id}"));
        };
        let mut source_pcs = source_pcs
            .split(',')
            .map(|pc| pc.parse::<usize>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        source_pcs.sort_unstable();
        mappings.push(json!({
            "generated_line": line + 1,
            "start_line": line + 1,
            "end_line": mapped_instruction_end(&lines, line),
            "prototype": prototype.parse::<usize>().map_err(|e| e.to_string())?,
            "source_pc": source_pc.parse::<usize>().map_err(|e| e.to_string())?,
            "source_pcs": source_pcs,
            "kind": "instruction"
        }));
    }
    Ok((
        out,
        json!({
            "prototype": id,
            "registers": register_map,
            "mappings": mappings,
            "capture_cells": locals.cells
        }),
    ))
}

fn emit_clean(
    program: &Program,
    decoded: &BTreeMap<usize, BTreeMap<usize, Instruction>>,
    origins: &BTreeMap<usize, BTreeMap<usize, Vec<usize>>>,
) -> Result<(String, Value), String> {
    let mut out = String::from(
        "-- Readable source reconstructed from verified Cryptnek bytecode dataflow.\n-- Names are inferred roles or neutral locals; they are not claimed original identifiers.\nlocal environment = (getgenv and getgenv()) or (getfenv and getfenv(1)) or _ENV or _G or {}\nlocal globalCache = {}\nlocal cachedNames = {}\n",
    );
    let names = "game workspace script print warn string table math bit32 buffer utf8 os task coroutine debug tostring tonumber type typeof pairs ipairs next select unpack pcall xpcall error assert require tick time setmetatable getmetatable rawget rawset rawequal rawlen newproxy wait spawn delay Instance Vector3 Vector2 CFrame Color3 UDim2 UDim Enum Ray Region3 TweenInfo NumberSequence ColorSequence NumberRange BrickColor Random DateTime Rect getgenv getrenv getreg getgc hookfunction hookmetamethod getnamecallmethod checkcaller iscclosure islclosure newcclosure setreadonly getrawmetatable setrawmetatable getconnections firesignal readfile writefile isfile request identifyexecutor";
    out.push_str(&format!(
        "for name in string.gmatch(\"{names}\", \"%S+\") do cachedNames[name] = true end\n"
    ));
    out.push_str(
        r#"local function cachedGlobal(name)
    if cachedNames[name] then
        local value = globalCache[name]
        if value == nil then value = environment[name]; globalCache[name] = value end
        return value
    end
    return environment[name]
end
local function method(name)
    return function(object, ...) return object[name](object, ...) end
end
local function decodeString(value, seed)
    if seed == 0 then seed = 0x1D2C6F end
    local other = bit32.bxor(bit32.bnot(seed), #value * 2654435761)
    if other == 0 then other = 0x9E3779B9 end
    local bytes = {}
    for i = 1, #value do
        seed = bit32.bxor(seed, bit32.lshift(seed, 13))
        seed = bit32.bxor(seed, bit32.rshift(seed, 17))
        seed = bit32.bxor(seed, bit32.lshift(seed, 5))
        other = bit32.bxor(other, bit32.lshift(other, 13))
        other = bit32.bxor(other, bit32.rshift(other, 17))
        other = bit32.bxor(other, bit32.lshift(other, 5))
        bytes[i] = string.char(bit32.bxor(string.byte(value, i), seed % 256, other % 256))
    end
    return table.concat(bytes)
end
local prototypes = {}
"#,
    );
    let mut prototype_maps = serde_json::Map::new();
    for (id, rows) in decoded {
        let origin = origins
            .get(id)
            .ok_or_else(|| format!("Missing readable source map for prototype {id}"))?;
        let (function, map) = emit_readable_function(program, *id, rows, origin)?;
        out.push_str(&function);
        prototype_maps.insert(id.to_string(), map);
    }
    out.push_str("return prototypes[1]({}, ...)\n");
    let mut mappings = Vec::new();
    let mut mapped_lines = BTreeSet::new();
    let lines = out.lines().collect::<Vec<_>>();
    for (line, text) in lines.iter().enumerate() {
        if let Some((prototype, mapping)) = text
            .trim()
            .strip_prefix("-- @source ")
            .and_then(|mapping| mapping.split_once(':'))
        {
            let Some((source_pc, source_pcs)) = mapping.split_once(':') else {
                return Err("Malformed clean source mapping".into());
            };
            let mut source_pcs = source_pcs
                .split(',')
                .map(|pc| pc.parse::<usize>().map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            source_pcs.sort_unstable();
            let end_line = mapped_instruction_end(&lines, line);
            mapped_lines.extend(line + 1..=end_line);
            mappings.push(json!({
                "generated_line": line + 1,
                "start_line": line + 1,
                "end_line": end_line,
                "prototype": prototype.parse::<usize>().map_err(|e| e.to_string())?,
                "source_pc": source_pc.parse::<usize>().map_err(|e| e.to_string())?,
                "source_pcs": source_pcs,
                "kind": "instruction"
            }));
        }
    }
    let mut generated_spans = Vec::new();
    let mut start = None;
    for line in 1..=out.lines().count() {
        if mapped_lines.contains(&line) {
            if let Some(start_line) = start.take() {
                generated_spans.push(json!({
                    "start_line": start_line,
                    "end_line": line - 1,
                    "reason": "generated source"
                }));
            }
        } else if start.is_none() {
            start = Some(line);
        }
    }
    if let Some(start_line) = start {
        generated_spans.push(json!({
            "start_line": start_line,
            "end_line": out.lines().count(),
            "reason": "generated source"
        }));
    }
    let source_map = json!({
        "format": "cryptnek-clean-source-map-v1",
        "source_file": "CoPlay_Legit_Trivia_Only.clean.luau",
        "prototypes": prototype_maps,
        "mappings": mappings,
        "generated_spans": generated_spans
    });
    Ok((out, source_map))
}

fn anti_tamper_report(source: &str, source_sha256: &str) -> Value {
    let offset = |needle: &str| source.find(needle);
    json!({
        "format": "cryptnek-static-anti-tamper-report-v1",
        "status": "static_analysis_only",
        "analysis_mode": "static_only",
        "input_sha256": source_sha256,
        "application_executed": false,
        "checks": [
            {
                "name": "decoded_bytecode_checksum",
                "evidence_offset": offset("if nDyNp8h7==398617549"),
                "evidence": "The loader compares the decoded bytecode hash with 398617549.",
                "failure_state": "Sets the guard state to 2 when the checksum differs."
            },
            {
                "name": "payload_checksum",
                "evidence_offset": offset("if n_CrYz~=1810995613"),
                "evidence": "The loader compares the decoded payload hash with 1810995613.",
                "failure_state": "Sets the guard state to 2 when the checksum differs."
            },
            {
                "name": "protection_marker_integrity",
                "evidence_offset": offset("Nw3EQlP~=1552315542"),
                "evidence": "The loader type-checks and hashes its protection marker string against 1552315542.",
                "failure_state": "Sets the guard state to 2 when the marker type or checksum differs."
            },
            {
                "name": "environment_name_and_debug_hook_checks",
                "evidence_offset": offset("YA4t7w[n_CrYz]==#wOSlm4Q"),
                "evidence": "A protected call scans environment names using hash/length pairs and checks debug.gethook when available.",
                "failure_state": "Sets the guard state to 2 on a matching name or non-nil hook."
            }
        ],
        "evidence": [
            {
                "source_offset": offset("if nDyNp8h7==398617549"),
                "claim": "decoded bytecode checksum validation"
            },
            {
                "source_offset": offset("if n_CrYz~=1810995613"),
                "claim": "payload checksum validation"
            },
            {
                "source_offset": offset("Nw3EQlP~=1552315542"),
                "claim": "protection marker integrity validation"
            },
            {
                "source_offset": offset("YA4t7w[n_CrYz]==#wOSlm4Q"),
                "claim": "environment name and debug hook validation"
            },
            {
                "source_offset": offset("st.QrMw5ih4I=st.QrMw5ih4I+3"),
                "claim": "guard failure response"
            }
        ],
        "observed_guard_response": {
            "evidence_offset": offset("st.QrMw5ih4I=st.QrMw5ih4I+3"),
            "behavior": "When guard state 2 is observed, the interpreter advances its bytecode position by 3, updates two rolling-state words when present, and XORs numeric values in register slots 0 and 1.",
            "runtime_executed": false,
            "externally_visible_effect": "not established statically"
        },
        "limitations": [
            "Environment-name checks are represented by hash and length pairs; this report does not claim original names for those entries.",
            "The guard response was not executed; its downstream application behavior is not established.",
            "This report is specific to the hash-admitted inspected source and is not a general Cryptnek signature."
        ]
    })
}

fn emit_function(
    program: &Program,
    id: usize,
    rows: &BTreeMap<usize, Instruction>,
) -> Result<String, String> {
    use crate::source::Node;
    let prototype = &program.prototypes[id - 1];
    if prototype.native != 0 {
        return Err("Native Cryptnek functions are unsupported".into());
    }
    let mut nodes = BTreeMap::new();
    let k = |index: usize| {
        program
            .constants
            .get(index)
            .map(Constant::literal)
            .ok_or_else(|| format!("Invalid constant {index} in prototype {id}"))
    };
    for row in rows.values() {
        let args = &row.operands;
        let a = args.first().copied().unwrap_or(0);
        let b = args.get(1).copied().unwrap_or(0);
        let c = args.get(2).copied().unwrap_or(0);
        let d = args.get(3).copied().unwrap_or(0);
        let (ra, rb, rc, rd) = (
            format!("R[{a}]"),
            format!("R[{b}]"),
            format!("R[{c}]"),
            format!("R[{d}]"),
        );
        let capture = match canonical(row.opcode) {
            175 | 151 => Some(b),
            66 => Some(a),
            _ => None,
        };
        if capture.is_some_and(|index| index >= prototype.captures.len()) {
            return Err(format!("Invalid upvalue in prototype {id} at {}", row.pc));
        }
        let mut condition = None;
        let code = match canonical(row.opcode) {
            196 => format!("{ra} = {}", k(b)?),
            155 => format!("{ra} = {}", b != 0),
            0 => format!("{ra} = nil"),
            185 => format!("{ra} = {rb}"),
            99 => format!("{ra} = {{{rb}}}"),
            90 => format!("{ra} = {rb}[1]"),
            41 => format!("{ra}[1] = {rb}"),
            175 => format!("{ra} = U[{b}][1]"),
            66 => format!("U[{a}][1] = {rb}"),
            223 => format!("{ra} = cachedGlobal({})", k(b)?),
            74 => format!("{ra} = environment[{}]", k(b)?),
            67 => format!(
                "environment[{}] = {rb}; globalCache[{}] = nil",
                k(a)?,
                k(a)?
            ),
            211 => format!("{ra} = {{}}"),
            44 => format!("{ra} = {rb}[{}]", k(c)?),
            252 => format!("{ra}[{}] = {rc}", k(b)?),
            135 => format!("{ra} = {rb}[{rc}]"),
            68 => format!("{ra}[{rb}] = {rc}"),
            114 => format!(
                "do local target = {ra}; for i = 0, {} do target[{d} + i] = R[{b} + i] end end",
                c as i64 - 1
            ),
            232 => format!(
                "do local target, values = {ra}, {rc}; for i = 1, values.n do target[{b} + i - 1] = values[i] end end"
            ),
            203 => format!("{ra} = math.floor({rb} / {rc})"),
            208 => format!("{ra} = {rb} % {rc}"),
            88 => format!("{ra} = -{rb}"),
            111 => format!("{ra} = {rb} .. {rc}"),
            34 => format!("{ra} = #{rb}"),
            65 => format!("{ra} = not {rb}"),
            194 => format!("{ra} = bit32.bnot({rb})"),
            25 | 162 | 117 => String::new(),
            238 => {
                condition = Some(ra);
                String::new()
            }
            97 => {
                condition = Some(format!("not {ra}"));
                String::new()
            }
            186 => format!("{ra} = {{n = 0}}"),
            14 => format!(
                "do local values = {ra}; local n = values.n + 1; values.n = n; values[n] = {rb} end"
            ),
            87 => format!(
                "do local values, extra = {ra}, {rb}; for i = 1, extra.n do local n = values.n + 1; values.n = n; values[n] = extra[i] end end"
            ),
            95 => format!(
                "do local callable, arguments = {rb}, {rc}; {ra} = table.pack(callable(table.unpack(arguments, 1, arguments.n))) end"
            ),
            137 => format!(
                "do local arguments = {rc}; {ra} = table.pack(method({})(table.unpack(arguments, 1, arguments.n))) end",
                k(b)?
            ),
            125 => format!("{ra} = {rb}[{c}]"),
            105 => format!("return table.unpack({ra}, 1, {ra}.n)"),
            32 => "return".into(),
            184 => {
                let child = program
                    .prototypes
                    .get(b)
                    .ok_or_else(|| format!("Invalid child prototype {b}"))?;
                let mut captures = Vec::new();
                for (index, (kind, register)) in child.captures.iter().enumerate() {
                    if *kind != 1 && *register >= prototype.captures.len() {
                        return Err(format!(
                            "Invalid inherited capture {register} in prototype {id}"
                        ));
                    }
                    captures.push(format!(
                        "[{index}] = {}[{register}]",
                        if *kind == 1 { "R" } else { "U" }
                    ));
                }
                format!(
                    "do local captures = {{{}}}; {ra} = function(...) return prototypes[{}](captures, ...) end end",
                    captures.join(", "),
                    b + 1
                )
            }
            191 => format!(
                "{ra} = table.pack(table.unpack(arguments, {}, arguments.n))",
                prototype.parameters + 1
            ),
            139 => format!("{ra} = type({rb})"),
            100 => format!("{ra} = decodeString({rb}, {})", c + d * 65536),
            178 => format!("{ra} = -({})", k(b)?),
            89 => format!("{ra} = ({}) * {rc}", k(b)?),
            151 => format!("{ra} = U[{b}][1][{rc}]"),
            242 => format!("{ra} = environment[{}][{}]", k(b)?, k(c)?),
            92 => format!("{ra} = {{{rb}[{c}]}}"),
            77 => format!("{ra} = {rb}[{}][{}]", k(c)?, k(d)?),
            81 => format!("{ra} = ({rb} * {rc}) + {rd}"),
            48 => format!("{ra} = {rb}[{c}][{}]", k(d)?),
            255 => format!("{ra} = not ({rb}[{rc}])"),
            107 => format!("{ra} = {rc} + ({})", k(b)?),
            156 => format!("{ra} = {rd} + bit32.band({rb}, {rc})"),
            136 => format!("{ra} = {rc} * ({})", k(b)?),
            72 => format!(
                "{ra} = {rb} {} {rc}",
                selected(
                    d,
                    &[(127, "+"), (193, "-"), (163, "*"), (151, "/"), (197, "^")]
                )?
            ),
            31 => format!(
                "{ra} = bit32.{}({rb}, {rc})",
                selected(
                    d,
                    &[
                        (167, "bxor"),
                        (103, "band"),
                        (107, "bor"),
                        (163, "lshift"),
                        (193, "rshift"),
                        (191, "lrotate")
                    ]
                )?
            ),
            225 | 237 | 50 => {
                let choices: &[(usize, &str)] = if canonical(row.opcode) == 50 {
                    &[(109, "=="), (103, "~=")]
                } else {
                    &[(163, "<"), (109, "<="), (113, ">"), (167, ">=")]
                };
                let terms = choices
                    .iter()
                    .filter(|(divisor, _)| d % divisor == 0)
                    .map(|(_, op)| format!("(if {rb} {op} {rc} then 1 else 0)"))
                    .collect::<Vec<_>>();
                format!(
                    "{ra} = ({}) == 1",
                    if terms.is_empty() {
                        "0".into()
                    } else {
                        terms.join(" + ")
                    }
                )
            }
            op => {
                return Err(format!(
                    "No source semantics for opcode {op} at {id}:{}",
                    row.pc
                ));
            }
        };
        nodes.insert(
            (row.pc - prototype.start + 1) as i64,
            Node {
                code: if code.is_empty() { vec![] } else { vec![code] },
                condition,
                successors: successors(row)
                    .iter()
                    .map(|pc| (*pc - prototype.start + 1) as i64)
                    .collect(),
            },
        );
    }
    let body = crate::source::structured(&nodes).map_err(|e| format!("Prototype {id}: {e}"))?;
    let mut out = format!(
        "prototypes[{id}] = function(U, ...)\n    -- Prototype {id}, bytecode offset {}\n    local R = {{}}\n    local arguments = table.pack(...)\n",
        prototype.start
    );
    for index in 0..prototype.parameters {
        out.push_str(&format!("    R[{index}] = arguments[{}]\n", index + 1));
    }
    for line in body.lines() {
        out.push_str("    ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("end\n");
    Ok(out)
}

fn emit(
    program: &Program,
    decoded: &BTreeMap<usize, BTreeMap<usize, Instruction>>,
) -> Result<String, String> {
    let mut out = String::from(
        "-- Cryptnek source lift: generated operations and registers, not original author names.\n-- Bytecode encryption and the VM dispatcher have been removed.\nlocal environment = (getgenv and getgenv()) or (getfenv and getfenv(1)) or _ENV or _G or {}\nlocal globalCache = {}\nlocal cachedNames = {}\n",
    );
    let names = "game workspace script print warn string table math bit32 buffer utf8 os task coroutine debug tostring tonumber type typeof pairs ipairs next select unpack pcall xpcall error assert require tick time setmetatable getmetatable rawget rawset rawequal rawlen newproxy wait spawn delay Instance Vector3 Vector2 CFrame Color3 UDim2 UDim Enum Ray Region3 TweenInfo NumberSequence ColorSequence NumberRange BrickColor Random DateTime Rect getgenv getrenv getreg getgc hookfunction hookmetamethod getnamecallmethod checkcaller iscclosure islclosure newcclosure setreadonly getrawmetatable setrawmetatable getconnections firesignal readfile writefile isfile request identifyexecutor";
    out.push_str(&format!(
        "for name in string.gmatch(\"{names}\", \"%S+\") do cachedNames[name] = true end\n"
    ));
    out.push_str(r#"local function cachedGlobal(name)
    if cachedNames[name] then
        local value = globalCache[name]
        if value == nil then value = environment[name]; globalCache[name] = value end
        return value
    end
    return environment[name]
end
local methods = {}
local function method(name)
    if methods[name] == nil then methods[name] = function(object, ...) return object[name](object, ...) end end
    return methods[name]
end
local function decodeString(value, seed)
    if seed == 0 then seed = 0x1D2C6F end
    local other = bit32.bxor(bit32.bnot(seed), #value * 2654435761)
    if other == 0 then other = 0x9E3779B9 end
    local bytes = {}
    for i = 1, #value do
        seed = bit32.bxor(seed, bit32.lshift(seed, 13))
        seed = bit32.bxor(seed, bit32.rshift(seed, 17))
        seed = bit32.bxor(seed, bit32.lshift(seed, 5))
        other = bit32.bxor(other, bit32.lshift(other, 13))
        other = bit32.bxor(other, bit32.rshift(other, 17))
        other = bit32.bxor(other, bit32.lshift(other, 5))
        bytes[i] = string.char(bit32.bxor(string.byte(value, i), seed % 256, other % 256))
    end
    return table.concat(bytes)
end
local prototypes = {}
"#);
    for (id, rows) in decoded {
        out.push_str(&emit_function(program, *id, rows)?);
    }
    out.push_str("return prototypes[1]({}, ...)\n");
    Ok(out)
}

pub fn recover(source: &str, output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err("Output directory already exists; choose a new directory".into());
    }
    use sha2::{Digest, Sha256};
    // shortcut: only this inspected build, add a verified structural matcher when another sample is available.
    if format!("{:x}", Sha256::digest(source.as_bytes()))
        != "d3e200a3840ed5c46592083fbcb8c4b516095d48f9c4c55306d29c4c56543de3"
    {
        return Err(
            "Cryptnek source differs from the inspected build; handler semantics are unverified"
                .into(),
        );
    }
    let mut program = parse(source)?;
    reserve_output_directory(output)?;
    fs::write(
        output.join("program.json"),
        serde_json::to_vec_pretty(&dump(&program)).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(output.join("payload.bin"), &program.payload).map_err(|e| e.to_string())?;
    fs::write(output.join("bytecode.encrypted.bin"), &program.code).map_err(|e| e.to_string())?;
    let mut pc = program.prototypes[8].start;
    let mut rows = Vec::new();
    for _ in 0..1000 {
        let row = instruction(&program.code, pc, &[])?;
        pc = row.next;
        let done = matches!(canonical(row.opcode), 105 | 32);
        rows.push(json!({"pc":row.pc,"opcode":row.opcode,"operands":row.operands,"next":row.next}));
        if done {
            break;
        }
    }
    fs::write(
        output.join("bootstrap.json"),
        serde_json::to_vec_pretty(&rows).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let boot = bootstrap(&program)?;
    let key = unlock(&mut program, boot)?;
    let mut decoded = BTreeMap::new();
    let mut instructions = BTreeMap::new();
    for id in 1..=program.prototypes.len() {
        let rows = decode(&program, id, key)?;
        decoded.insert(id,rows.values().map(|row|json!({"pc":row.pc,"opcode":row.opcode,"canonical":canonical(row.opcode),"operands":row.operands,"successors":successors(row)})).collect::<Vec<_>>());
        instructions.insert(id, rows);
    }
    fs::write(
        output.join("decoded-instructions.json"),
        serde_json::to_vec_pretty(
            &json!({"bootstrap_key":boot,"function_key":key,"prototypes":decoded}),
        )
        .unwrap(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(output.join("bytecode.decoded.bin"), &program.code).map_err(|e| e.to_string())?;
    let mut specialized = BTreeMap::new();
    let original_constants = program.constants.len();
    let mut source_map = BTreeMap::new();
    let mut source_provenance = BTreeMap::new();
    for (id, rows) in &instructions {
        let (rows, origins) = specialize(&mut program, *id, rows)?;
        specialized.insert(*id, rows);
        source_map.insert(
            *id,
            origins
                .iter()
                .map(|(pc, source_pcs)| (*pc, source_pcs.first().copied().unwrap_or(*pc)))
                .collect::<BTreeMap<_, _>>(),
        );
        source_provenance.insert(*id, origins);
    }
    fs::write(
        output.join("source-map.json"),
        serde_json::to_vec_pretty(&source_map).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let cfg=specialized.iter().map(|(id,rows)|(*id,rows.values().map(|row|json!({"pc":row.pc,"source_pc":source_map[id][&row.pc],"source_pcs":source_provenance[id][&row.pc],"opcode":canonical(row.opcode),"operands":row.operands,"successors":successors(row)})).collect::<Vec<_>>())).collect::<BTreeMap<_,_>>();
    fs::write(
        output.join("specialized-cfg.json"),
        serde_json::to_vec_pretty(&cfg).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let lifted = emit(&program, &specialized)?;
    mlua::chunk::Compiler::new()
        .compile(&lifted)
        .map_err(|e| format!("Cryptnek lift failed syntax validation: {e}"))?;
    fs::write(output.join("CoPlay_Legit_Trivia_Only.lifted.luau"), &lifted)
        .map_err(|e| e.to_string())?;
    let (clean, clean_source_map) = emit_clean(&program, &specialized, &source_provenance)?;
    mlua::chunk::Compiler::new()
        .compile(&clean)
        .map_err(|e| format!("Readable Cryptnek source failed syntax validation: {e}"))?;
    fs::write(output.join("CoPlay_Legit_Trivia_Only.clean.luau"), &clean)
        .map_err(|e| e.to_string())?;
    fs::write(
        output.join("clean-source-map.json"),
        serde_json::to_vec_pretty(&clean_source_map).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let input_sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
    fs::write(
        output.join("anti-tamper-report.json"),
        serde_json::to_vec_pretty(&anti_tamper_report(source, &input_sha256))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let strings = program.constants[original_constants..]
        .iter()
        .filter(|value| matches!(value, Constant::String(_)))
        .map(Constant::json)
        .collect::<Vec<_>>();
    fs::write(
        output.join("decoded-strings.json"),
        serde_json::to_vec_pretty(&strings).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        output.join("specialized-constants.json"),
        serde_json::to_vec_pretty(
            &program
                .constants
                .iter()
                .map(Constant::json)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let count: usize = instructions.values().map(BTreeMap::len).sum();
    let report = json!({"status":"lifted","obfuscator":"Cryptnek (inspected CoPlay build)","input_sha256":input_sha256,"payload_checksum":1810995613u32,"prototypes":program.prototypes.len(),"reachable_instructions":count,"materialized_string_literals":strings.len(),"unsupported_instructions":0,"application_executed":false,"syntax_validation":"passed with Luau compiler","clean_syntax_validation":"passed with Luau compiler","behavioral_equivalence":"not universally verified; local fixture comparisons are separate","scope":"Only the inspected sample layout; names are inferred roles or neutral locals, not recovered original identifiers. Original anti-analysis admission gates are omitted; an accepted environment is assumed","source_file":"CoPlay_Legit_Trivia_Only.lifted.luau","clean_source_file":"CoPlay_Legit_Trivia_Only.clean.luau","clean_source_map":"clean-source-map.json","anti_tamper_report":"anti-tamper-report.json"});
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Lifted {} Cryptnek prototypes / {count} instructions to {}",
        program.prototypes.len(),
        output.display()
    );
    Ok(())
}

fn reserve_output_directory(output: &Path) -> Result<(), String> {
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::create_dir(output).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            "Output directory already exists; choose a new directory".into()
        } else {
            error.to_string()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn program(code: Vec<u8>) -> Program {
        let length = code.len();
        Program {
            constants: vec![],
            prototypes: vec![Prototype {
                start: 1,
                parameters: 0,
                vararg: false,
                captures: vec![],
                offset: 1,
                length,
                tag: 0,
                native: 0,
            }],
            code,
            payload: vec![],
            code_offset: 0,
        }
    }
    fn identity_origins(
        decoded: &BTreeMap<usize, BTreeMap<usize, Instruction>>,
    ) -> BTreeMap<usize, BTreeMap<usize, Vec<usize>>> {
        decoded
            .iter()
            .map(|(id, rows)| (*id, rows.keys().map(|pc| (*pc, vec![*pc])).collect()))
            .collect()
    }
    #[test]
    fn branches_into_operands_are_rejected() {
        let p = program(vec![238, 32, 0, 0, 2, 32]);
        assert!(
            decode(&p, 1, [0; 4]).is_err(),
            "A branch into the first instruction's operand was accepted"
        );
    }
    #[test]
    fn missing_upvalue_reads_are_rejected() {
        let p = program(vec![175, 0, 0, 0, 0, 32]);
        let rows = decode(&p, 1, [0; 4]).unwrap();
        assert!(
            emit_function(&p, 1, &rows).is_err(),
            "A prototype without captures read U[0]"
        );
    }

    #[test]
    fn selector_specialization_preserves_an_unknown_branch() {
        let mut p = program(vec![]);
        p.prototypes[0].parameters = 1;
        p.constants = vec![Constant::Number(10.0), Constant::Number(20.0)];
        let rows = BTreeMap::from([
            (
                1,
                Instruction {
                    pc: 1,
                    opcode: 196,
                    operands: vec![1, 0],
                    next: 2,
                },
            ),
            (
                2,
                Instruction {
                    pc: 2,
                    opcode: 238,
                    operands: vec![0, 5],
                    next: 3,
                },
            ),
            (
                3,
                Instruction {
                    pc: 3,
                    opcode: 196,
                    operands: vec![1, 1],
                    next: 4,
                },
            ),
            (
                4,
                Instruction {
                    pc: 4,
                    opcode: 25,
                    operands: vec![5],
                    next: 5,
                },
            ),
            (
                5,
                Instruction {
                    pc: 5,
                    opcode: 186,
                    operands: vec![2],
                    next: 6,
                },
            ),
            (
                6,
                Instruction {
                    pc: 6,
                    opcode: 14,
                    operands: vec![2, 1],
                    next: 7,
                },
            ),
            (
                7,
                Instruction {
                    pc: 7,
                    opcode: 105,
                    operands: vec![2],
                    next: 8,
                },
            ),
        ]);
        let (specialized, _) = specialize(&mut p, 1, &rows).unwrap();
        assert!(specialized.values().any(|row| canonical(row.opcode) == 238));
        for (branch, expected) in [(true, 10), (false, 20)] {
            let source = emit(&p, &BTreeMap::from([(1, specialized.clone())])).unwrap();
            let lua = crate::vm::restricted_lua().unwrap();
            let value: i32 = lua.load(source).call(branch).unwrap();
            assert_eq!(value, expected);
        }
    }

    #[test]
    fn selector_join_restores_a_branch_when_constants_disagree() {
        let mut p = program(vec![]);
        p.prototypes[0].parameters = 1;
        p.constants = vec![
            Constant::Number(10.0),
            Constant::Number(20.0),
            Constant::Number(100.0),
            Constant::Number(200.0),
        ];
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let rows = BTreeMap::from([
            make(1, 196, vec![1, 0], 2),
            make(2, 238, vec![0, 5], 3),
            make(3, 196, vec![2, 1], 4),
            make(4, 25, vec![6], 5),
            make(5, 196, vec![2, 0], 6),
            make(6, 50, vec![3, 2, 1, 109], 7),
            make(7, 238, vec![3, 10], 8),
            make(8, 196, vec![4, 3], 9),
            make(9, 25, vec![11], 10),
            make(10, 196, vec![4, 2], 11),
            make(11, 186, vec![5], 12),
            make(12, 14, vec![5, 4], 13),
            make(13, 105, vec![5], 14),
        ]);
        let (specialized, _) = specialize(&mut p, 1, &rows).unwrap();
        for (input, expected) in [(true, 100), (false, 200)] {
            for graph in [&rows, &specialized] {
                let source = emit(&p, &BTreeMap::from([(1, graph.clone())])).unwrap();
                let lua = crate::vm::restricted_lua().unwrap();
                let actual: i32 = lua.load(source).call(input).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn specialization_materializes_verified_string_literals() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::String(vec![0])];
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let rows = BTreeMap::from([
            make(1, 196, vec![0, 0], 2),
            make(2, 100, vec![1, 0, 1, 0], 3),
            make(3, 186, vec![2], 4),
            make(4, 14, vec![2, 1], 5),
            make(5, 105, vec![2], 6),
        ]);
        let (specialized, _) = specialize(&mut p, 1, &rows).unwrap();
        assert!(
            p.constants.contains(&Constant::String(vec![14])),
            "Known ciphertext was not materialized as a literal"
        );
        let source = emit(&p, &BTreeMap::from([(1, specialized)])).unwrap();
        let lua = crate::vm::restricted_lua().unwrap();
        let output: mlua::LuaString = lua.load(source).eval().unwrap();
        assert_eq!(&*output.as_bytes(), &[14]);
    }

    #[test]
    fn constant_cleanup_drops_dead_noise_and_preserves_the_return() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::Number(123456789.0), Constant::Number(42.0)];
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let rows = BTreeMap::from([
            make(1, 196, vec![0, 0], 2),
            make(2, 196, vec![1, 1], 3),
            make(3, 186, vec![2], 4),
            make(4, 14, vec![2, 1], 5),
            make(5, 105, vec![2], 6),
        ]);
        let (specialized, _) = specialize(&mut p, 1, &rows).unwrap();
        assert!(
            !specialized
                .values()
                .any(|row| canonical(row.opcode) == 196 && row.operands[0] == 0),
            "Unused numeric noise remains"
        );
        let source = emit(&p, &BTreeMap::from([(1, specialized)])).unwrap();
        let lua = crate::vm::restricted_lua().unwrap();
        let result: i32 = lua.load(source).eval().unwrap();
        assert_eq!(result, 42);
    }
    #[test]
    fn source_preserves_nil_returns_and_capture_cells() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::Number(41.0), Constant::Number(42.0)];
        p.prototypes.push(Prototype {
            start: 100,
            parameters: 0,
            vararg: false,
            captures: vec![(1, 0)],
            offset: 0,
            length: 0,
            tag: 0,
            native: 0,
        });
        let make_rows = |ops: Vec<(u8, Vec<usize>)>, start: usize| {
            ops.into_iter()
                .enumerate()
                .map(|(i, (opcode, operands))| {
                    let pc = start + i;
                    (
                        pc,
                        Instruction {
                            pc,
                            opcode,
                            operands,
                            next: pc + 1,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let main = make_rows(
            vec![
                (196, vec![0, 0]),
                (99, vec![0, 0]),
                (184, vec![1, 1]),
                (196, vec![2, 0]),
                (41, vec![0, 2]),
                (186, vec![3]),
                (95, vec![4, 1, 3]),
                (186, vec![5]),
                (14, vec![5, 6]),
                (87, vec![5, 4]),
                (14, vec![5, 6]),
                (105, vec![5]),
            ],
            1,
        );
        let child = make_rows(
            vec![
                (196, vec![2, 1]),
                (66, vec![0, 2]),
                (175, vec![0, 0]),
                (186, vec![1]),
                (14, vec![1, 0]),
                (105, vec![1]),
            ],
            100,
        );
        let decoded = BTreeMap::from([(1, main), (2, child)]);
        let source = emit(&p, &decoded).unwrap();
        let lua = crate::vm::restricted_lua().unwrap();
        let result: mlua::MultiValue = lua.load(source).eval().unwrap();
        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], mlua::Value::Nil));
        assert!(matches!(
            result[1],
            mlua::Value::Integer(42) | mlua::Value::Number(42.0)
        ));
        assert!(matches!(result[2], mlua::Value::Nil));

        let origins = identity_origins(&decoded);
        let (clean, _) = emit_clean(&p, &decoded, &origins).unwrap();
        assert!(!clean.contains("R["));
        mlua::chunk::Compiler::new().compile(&clean).unwrap();
        let result: mlua::MultiValue = lua.load(clean).eval().unwrap();
        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], mlua::Value::Nil));
        assert!(matches!(
            result[1],
            mlua::Value::Integer(42) | mlua::Value::Number(42.0)
        ));
        assert!(matches!(result[2], mlua::Value::Nil));
    }

    #[test]
    fn clean_source_preserves_fixed_and_variable_table_copies() {
        let mut p = program(vec![]);
        p.prototypes[0].parameters = 4;
        p.prototypes[0].vararg = true;
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let decoded = BTreeMap::from([(
            1,
            BTreeMap::from([
                make(1, 191, vec![4], 4),
                make(4, 114, vec![0, 1, 2, 4], 10),
                make(10, 232, vec![0, 7, 4], 17),
                make(17, 186, vec![5], 20),
                make(20, 14, vec![5, 0], 25),
                make(25, 105, vec![5], 28),
            ]),
        )]);
        let origins = identity_origins(&decoded);
        let (clean, _) = emit_clean(&p, &decoded, &origins).unwrap();
        assert!(!clean.contains("R["));
        mlua::chunk::Compiler::new().compile(&clean).unwrap();
        let lua = crate::vm::restricted_lua().unwrap();
        let target = lua.create_table().unwrap();
        target.set(4, 90).unwrap();
        target.set(5, 91).unwrap();
        target.set(7, 92).unwrap();
        target.set(8, 93).unwrap();
        target.set(9, 94).unwrap();
        let _: mlua::Table = lua
            .load(clean)
            .call((
                target.clone(),
                13,
                mlua::Value::Nil,
                21,
                mlua::Value::Nil,
                55,
                mlua::Value::Nil,
            ))
            .unwrap();
        assert_eq!(target.get::<i32>(4).unwrap(), 13);
        assert!(matches!(
            target.get::<mlua::Value>(5).unwrap(),
            mlua::Value::Nil
        ));
        assert!(matches!(
            target.get::<mlua::Value>(7).unwrap(),
            mlua::Value::Nil
        ));
        assert_eq!(target.get::<i32>(8).unwrap(), 55);
        assert!(matches!(
            target.get::<mlua::Value>(9).unwrap(),
            mlua::Value::Nil
        ));
    }

    #[test]
    fn clean_names_use_known_global_roles_and_neutral_fallbacks() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::String(b"game".to_vec())];
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let decoded = BTreeMap::from([(
            1,
            BTreeMap::from([
                make(1, 223, vec![0, 0], 4),
                make(4, 196, vec![1, 0], 7),
                make(7, 186, vec![2], 10),
                make(10, 14, vec![2, 0], 15),
                make(15, 14, vec![2, 1], 20),
                make(20, 105, vec![2], 23),
            ]),
        )]);
        let origins = identity_origins(&decoded);
        let (clean, source_map) = emit_clean(&p, &decoded, &origins).unwrap();
        assert!(clean.contains("game = cachedGlobal(\"game\")"));
        assert!(clean.contains("value_1 = \"game\""));
        assert_eq!(
            source_map["prototypes"]["1"]["registers"][0]["role"],
            "global"
        );
        assert_eq!(
            source_map["prototypes"]["1"]["registers"][1]["role"],
            "neutral"
        );
    }

    #[test]
    fn clean_source_map_spans_are_valid_and_disjoint_from_instruction_mappings() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::Number(7.0)];
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let decoded = BTreeMap::from([(
            1,
            BTreeMap::from([
                make(1, 196, vec![0, 0], 4),
                make(4, 186, vec![1], 7),
                make(7, 14, vec![1, 0], 10),
                make(10, 105, vec![1], 13),
            ]),
        )]);
        let origins = identity_origins(&decoded);
        let (clean, source_map) = emit_clean(&p, &decoded, &origins).unwrap();
        let line_count = clean.lines().count();
        let spans = source_map["generated_spans"].as_array().unwrap();
        let mappings = source_map["mappings"].as_array().unwrap();

        for span in spans {
            let start = span["start_line"].as_u64().unwrap() as usize;
            let end = span["end_line"].as_u64().unwrap() as usize;
            assert!(start > 0 && start <= end && end <= line_count);
        }
        for (index, left) in spans.iter().enumerate() {
            let left = (
                left["start_line"].as_u64().unwrap(),
                left["end_line"].as_u64().unwrap(),
            );
            for right in spans.iter().skip(index + 1) {
                let right = (
                    right["start_line"].as_u64().unwrap(),
                    right["end_line"].as_u64().unwrap(),
                );
                assert!(
                    left.1 < right.0 || right.1 < left.0,
                    "generated spans overlap"
                );
            }
        }
        for (index, mapping) in mappings.iter().enumerate() {
            let start = mapping["start_line"].as_u64().unwrap();
            let end = mapping["end_line"].as_u64().unwrap();
            assert!(start > 0 && start <= end && end <= line_count as u64);
            assert!(
                spans.iter().all(|span| {
                    end < span["start_line"].as_u64().unwrap()
                        || start > span["end_line"].as_u64().unwrap()
                }),
                "instruction mapping overlaps a generated span"
            );
            for other in mappings.iter().skip(index + 1) {
                let other_start = other["start_line"].as_u64().unwrap();
                let other_end = other["end_line"].as_u64().unwrap();
                assert!(
                    end < other_start || start > other_end,
                    "instruction mappings overlap"
                );
            }
        }
    }

    #[test]
    fn folded_literal_provenance_includes_prior_register_definitions() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::Number(6.0), Constant::Number(7.0)];
        let make = |pc, opcode, operands, next| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next,
                },
            )
        };
        let rows = BTreeMap::from([
            make(1, 196, vec![1, 0], 2),
            make(2, 196, vec![2, 1], 3),
            make(3, 72, vec![3, 1, 2, 127], 4),
            make(4, 186, vec![4], 5),
            make(5, 14, vec![4, 3], 6),
            make(6, 105, vec![4], 7),
        ]);
        let (specialized, origins) = specialize(&mut p, 1, &rows).unwrap();
        let (clean, source_map) = emit_clean(
            &p,
            &BTreeMap::from([(1, specialized)]),
            &BTreeMap::from([(1, origins)]),
        )
        .unwrap();
        mlua::chunk::Compiler::new().compile(&clean).unwrap();

        let folded = source_map["mappings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mapping| mapping["source_pc"] == 3)
            .expect("folded operation should keep its own PC mapping");
        let source_pcs = folded["source_pcs"].as_array().unwrap();
        assert_eq!(
            source_pcs,
            &[json!(1), json!(2), json!(3)],
            "folded literal should cite both definitions and the folding instruction"
        );
    }

    #[test]
    fn anti_tamper_evidence_offsets_resolve_to_their_fixture_text() {
        let source = concat!(
            "if nDyNp8h7==398617549\n",
            "if n_CrYz~=1810995613\n",
            "Nw3EQlP~=1552315542\n",
            "YA4t7w[n_CrYz]==#wOSlm4Q\n",
            "st.QrMw5ih4I=st.QrMw5ih4I+3\n",
        );
        let report = anti_tamper_report(source, "fixture");
        for evidence in report["evidence"].as_array().unwrap() {
            let offset = evidence["source_offset"].as_u64().unwrap() as usize;
            assert!(source.get(offset..).is_some());
        }
        for (check, needle) in report["checks"].as_array().unwrap().iter().zip([
            "if nDyNp8h7==398617549",
            "if n_CrYz~=1810995613",
            "Nw3EQlP~=1552315542",
            "YA4t7w[n_CrYz]==#wOSlm4Q",
        ]) {
            let offset = check["evidence_offset"].as_u64().unwrap() as usize;
            assert!(source[offset..].starts_with(needle));
        }
    }

    #[test]
    fn recovery_rejects_an_existing_destination_without_overwriting_it() {
        let output = std::env::temp_dir().join(format!(
            "cryptnek-existing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&output).unwrap();
        let marker = output.join("keep.txt");
        fs::write(&marker, b"preserve").unwrap();

        assert!(recover("not the inspected sample", &output).is_err());
        assert_eq!(fs::read(&marker).unwrap(), b"preserve");
        fs::remove_dir_all(output).unwrap();
    }

    #[test]
    fn destination_reservation_uses_atomic_create_directory_semantics() {
        let output = std::env::temp_dir().join(format!(
            "cryptnek-reservation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        reserve_output_directory(&output).unwrap();
        let marker = output.join("keep.txt");
        fs::write(&marker, b"preserve").unwrap();
        assert!(reserve_output_directory(&output).is_err());
        assert_eq!(fs::read(marker).unwrap(), b"preserve");
        fs::remove_dir_all(output).unwrap();
    }

    #[test]
    fn clean_source_captures_the_cell_value_without_a_second_wrapper() {
        let mut p = program(vec![]);
        p.constants = vec![Constant::Number(41.0)];
        p.prototypes.push(Prototype {
            start: 100,
            parameters: 0,
            vararg: false,
            captures: vec![(1, 1)],
            offset: 0,
            length: 0,
            tag: 0,
            native: 0,
        });
        let make = |pc, opcode, operands| {
            (
                pc,
                Instruction {
                    pc,
                    opcode,
                    operands,
                    next: pc + 1,
                },
            )
        };
        let decoded = BTreeMap::from([
            (
                1,
                BTreeMap::from([
                    make(1, 196, vec![0, 0]),
                    make(2, 99, vec![1, 0]),
                    make(3, 184, vec![2, 1]),
                    make(4, 186, vec![3]),
                    make(5, 95, vec![4, 2, 3]),
                    make(6, 186, vec![5]),
                    make(7, 87, vec![5, 4]),
                    make(8, 105, vec![5]),
                ]),
            ),
            (
                2,
                BTreeMap::from([
                    make(100, 175, vec![0, 0]),
                    make(101, 186, vec![1]),
                    make(102, 14, vec![1, 0]),
                    make(103, 105, vec![1]),
                ]),
            ),
        ]);
        let origins = identity_origins(&decoded);
        let (clean, _) = emit_clean(&p, &decoded, &origins).unwrap();
        let lua = crate::vm::restricted_lua().unwrap();
        let value: i64 = lua.load(clean).eval().unwrap();
        assert_eq!(value, 41);
    }
}
