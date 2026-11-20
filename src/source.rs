use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

fn text(v: &Value) -> Result<String, String> {
    if let Some(s) = v.get("luau_string").and_then(Value::as_str) {
        return Ok(s.into());
    }
    if let Some(s) = v.get("luau_number").and_then(Value::as_str) {
        return Ok(s.into());
    }
    match v {
        Value::Null => Ok("nil".into()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(format!("Unresolved literal {v}")),
    }
}
fn string(v: &Value) -> Result<String, String> {
    v.get("luau_string")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| v.as_str().map(str::to_string))
        .ok_or_else(|| format!("Expected string: {v}"))
}
fn num(v: &Value) -> Result<i64, String> {
    v.as_i64().ok_or_else(|| format!("Expected integer: {v}"))
}
fn sequence(v: &Value) -> Vec<Value> {
    if let Some(a) = v.as_array() {
        return a.clone();
    }
    let mut entries: Vec<_> = v
        .as_object()
        .into_iter()
        .flat_map(|o| o.iter())
        .filter_map(|(k, v)| k.parse::<usize>().ok().map(|k| (k, v.clone())))
        .collect();
    entries.sort_by_key(|e| e.0);
    entries.into_iter().map(|(_, v)| v).collect()
}

#[derive(Clone)]
pub(crate) struct Node {
    pub(crate) code: Vec<String>,
    pub(crate) condition: Option<String>,
    pub(crate) successors: Vec<i64>,
}
struct Emitter<'a> {
    ir: &'a Value,
}
impl Emitter<'_> {
    fn constant(&self, name: &str, row: &Value, token: i64) -> Result<String, String> {
        let index = token - (if token.rem_euclid(512) >= 256 { 256 } else { 0 }) + 1;
        let key = format!("{name}:{}", num(&row["pc"])?);
        let value = self.ir["frames"][&key]["constants"]
            .get(index.to_string())
            .ok_or_else(|| {
                format!(
                    "Missing contextual constant {name}:{} index {index}",
                    row["pc"]
                )
            })?;
        text(value)
    }
    fn operand(&self, name: &str, row: &Value, token: i64) -> Result<String, String> {
        if token >= 256 {
            self.constant(name, row, token)
        } else {
            Ok(format!("r{token}"))
        }
    }
    fn tuple(&self, row: &Value, group: usize, index: usize) -> Result<i64, String> {
        num(&row["tuples"][group.to_string()][index.to_string()])
    }
    fn function(&mut self, name: &str, upvalues: &[String]) -> Result<String, String> {
        let proto = &self.ir["prototypes"][name];
        if !proto["error"].is_null() {
            return Err(format!("Prototype {name} incomplete: {}", proto["error"]));
        }
        let registers = num(&proto["registers"])?;
        let parameters = num(&proto["parameters"])?;
        let mut args: Vec<String> = (0..parameters).map(|i| format!("r{i}")).collect();
        if proto["vararg"] == true {
            args.push("...".into());
        }
        let mut out = format!(
            "function({})\n    -- Decoded prototype: {name}\n",
            args.join(", ")
        );
        let locals: Vec<_> = (parameters..registers).map(|i| format!("r{i}")).collect();
        if !locals.is_empty() {
            out.push_str(&format!("    local {}\n", locals.join(", ")));
        }
        out.push_str("    local returned\n");
        out.push_str("    local branchResult\n");
        let rows = sequence(&proto["rows"]);
        let mut open_bases: HashMap<i64, BTreeSet<Option<i64>>> =
            HashMap::from([(1, BTreeSet::from([None]))]);
        let mut pending = VecDeque::from([1]);
        while let Some(pc) = pending.pop_front() {
            let row = rows
                .iter()
                .find(|row| row["pc"] == pc)
                .ok_or_else(|| format!("Missing instruction {name}:{pc}"))?;
            let states = if row["opcode"] == 72 && row["c"] == 0 {
                BTreeSet::from([Some(num(&row["b"])?)])
            } else {
                open_bases[&pc].clone()
            };
            for next in sequence(&row["successors"]) {
                let next = num(&next)?;
                let target = open_bases.entry(next).or_default();
                let before = target.len();
                target.extend(&states);
                if target.len() != before {
                    pending.push_back(next);
                }
            }
        }
        let mut nodes = BTreeMap::new();
        for row in rows {
            let pc = num(&row["pc"])?;
            for key in ["frame_error", "capture_error", "child_error"] {
                if !row[key].is_null() {
                    return Err(format!("Unresolved {key} at {name}:{pc}: {}", row[key]));
                }
            }
            let a = num(&row["a"])?;
            let b = num(&row["b"])?;
            let c = num(&row["c"])?;
            let op = num(&row["opcode"])?;
            let k = |t| self.constant(name, &row, t);
            let rk = |t| self.operand(name, &row, t);
            let t = |g, i| self.tuple(&row, g, i);
            let variable_values = |first: i64| -> Result<String, String> {
                let states = open_bases.get(&pc).ok_or("Unreachable variable result")?;
                if states.len() != 1 {
                    return Err(format!("Ambiguous open results at {name}:{pc}"));
                }
                let base = states
                    .first()
                    .copied()
                    .flatten()
                    .ok_or_else(|| format!("No open results at {name}:{pc}"))?;
                if first > base {
                    return Ok(format!(
                        "table.unpack(returned, {}, returned.n)",
                        first - base + 1
                    ));
                }
                let mut args: Vec<_> = (first..base).map(|i| format!("r{i}")).collect();
                args.push("table.unpack(returned, 1, returned.n)".into());
                Ok(args.join(", "))
            };
            let mut code = Vec::new();
            let mut condition = None;
            match op{
                1=>{condition=Some(format!("(not r{b}) ~= {}",c!=0));}
                8=>code.push(format!("r{b} = {{}}")),
                32=>code.push(format!("r{b} = {}",k(c)?)),
                41|169=>{},
                53=>code.push(format!("r{c} = {}",b!=0)),
                65=>{code.push(format!("r{} = r{b}",a+1));code.push(format!("r{a} = r{b}[{}]",rk(c)?));}
                107=>code.push(format!("r{a} = r{c}[{}]",rk(b)?)),
                158=>code.push(format!("r{c} = r{a}")),
                213=>{
                    let key=k(a)?;
                    let expr=if key=="\"__volt_predicate_262dee66401d0dac\""{"isFunctionType".into()}else{format!("environment[{key}]")};
                    code.push(format!("r{c} = {expr}"));
                }
                244=>code.push(format!("r{b}[{}] = {}",rk(c)?,rk(a)?)),
                247=>code.push(format!("r{b} = {}",upvalues.get(c as usize).ok_or_else(||format!("Missing upvalue {name}:{c}"))?)),
                186=>{
                    if b==0{code.push(format!("do local list = table.pack({}); for i = 1, list.n do r{c}[{} + i] = list[i] end end",variable_values(c+1)?,a-1));}
                    else{for i in 1..=b{code.push(format!("r{c}[{}] = r{}",a-1+i,c+i));}}
                }
                89=>code.push(format!("r{b} = {}",(a..=c).map(|i|format!("r{i}")).collect::<Vec<_>>().join(" .. "))),
                72=>{
                    let args=if a==0{variable_values(b+1)?}else{(b+1..b+a).map(|i|format!("r{i}")).collect::<Vec<_>>().join(", ")};
                    let call=format!("r{b}({args})");
                    if c==0{
                        code.push(format!("returned = table.pack({call})"));
                        for register in b..registers{let index=register-b+1;code.push(format!("if returned.n >= {index} then r{register} = returned[{index}] end"));}
                    }
                    else if c==1{code.push(call);}
                    else{code.push(format!("{} = {call}",(b..b+c-1).map(|i|format!("r{i}")).collect::<Vec<_>>().join(", ")));}
                }
                97=>{
                    if b==0{code.push(format!("return {}",variable_values(c)?));}
                    else{code.push(format!("return {}",(c..c+b-1).map(|i|format!("r{i}")).collect::<Vec<_>>().join(", ")));}
                }
                183=>condition=Some(format!("({} == {}) == {}",rk(c)?,rk(a)?,b!=0)),
                228|112|113|125|149|161=>{},
                160=>{
                    let child_literal=string(&row["child"])?;
                    let child=child_literal.trim_matches('"');
                    let mut captured=Vec::new();
                    code.push("do".into());
                    for (i,capture) in sequence(&row["captures"]).iter().enumerate(){
                        let value=if let Some(n)=capture["register"].as_i64(){format!("r{n}")}else{upvalues.get(num(&capture["upvalue"])? as usize).ok_or("Missing parent upvalue")?.clone()};
                        let local=format!("capture_{}_{}",pc,i);
                        code.push(format!("    local {local} = {value}"));captured.push(local);
                    }
                    let function=self.function(child,&captured)?;
                    code.push(format!("    r{b} = {}",function.replace('\n',"\n    ")));
                    code.push("end".into());
                }
                163=>{code.push(format!("{}({})",upvalues.first().ok_or("Missing callback upvalue")?,k(t(2,1)?)?));code.push("return".into());}
                81=>{
                    let tuples:Vec<i64>=(2..=7).flat_map(|g|sequence(&row["tuples"][g.to_string()])).map(|v|num(&v)).collect::<Result<_,_>>()?;
                    let mut all=vec![a];all.extend(tuples);
                    if all.len()!=23{return Err(format!("Invalid fused quest record at {name}:{pc}"));}
                    let values=all.iter().map(|t|k(*t)).collect::<Result<Vec<_>,_>>()?;
                    code.push(format!("r2, r3, r4, r5 = {}, {}, {}, {}",values[0],values[1],values[2],values[3]));
                    code.push(format!("r1[1], r1[2], r1[3], r1[4] = {}, {}, {}, {}",values[0],values[1],values[2],values[3]));
                    code.push(format!("r0[{}] = r1",values[4]));
                    for group in 0..3{
                        let i=5+group*5;
                        code.push(format!("r1 = {{{}, {}, {}, {}}}",values[i],values[i+1],values[i+2],values[i+3]));
                        code.push(format!("r2, r3, r4, r5 = {}, {}, {}, {}",values[i],values[i+1],values[i+2],values[i+3]));
                        code.push(format!("r0[{}] = r1",values[i+4]));
                    }
                    code.push("r1 = {}".into());
                    code.push(format!("r2, r3, r4 = {}, {}, {}",values[20],values[21],values[22]));
                }
                180=>{
                    code.push("r13(r14, r15, r16)".into());code.push("r14 = r9".into());
                    code.push(format!("r13 = r9[{}]",k(t(2,1)?)?));code.push(format!("r15 = {}",k(t(2,2)?)?));
                }
                25|119=>{
                    let predicate=if op==25{k(a)?}else{k(c)?};
                    if predicate!="\"__volt_predicate_262dee66401d0dac\""||k(t(2,3)?)?!="1"{return Err(format!("Unrecognized predicate at {name}:{pc}"));}
                    let test=format!("environment[{}](environment[{}]) == \"function\"",k(t(2,1)?)?,k(t(2,2)?)?);
                    condition=Some(test);
                }
                90|110=>{
                    let (function,url,member,args)=if op==90 {
                        (t(2,1)?,t(2,2)?,t(2,3)?,vec![t(2,4)?,t(3,1)?,t(3,2)?,t(3,3)?,t(3,4)?,t(4,1)?])
                    }else{(b,t(2,1)?,t(2,2)?,vec![t(2,3)?,t(2,4)?,t(3,1)?,t(3,2)?,t(3,3)?,t(3,4)?])};
                    code.push(format!("environment[{}]({})",k(function)?,k(url)?));
                    let ui=upvalues.first().ok_or("Missing UI capture")?;
                    code.push(format!("{ui}[{}]({ui}, {})",k(member)?,args.into_iter().map(k).collect::<Result<Vec<_>,_>>()?.join(", ")));
                }
                100|128=>code.push(format!("environment[{}]({}, r0, r2)",k(if op==100 {a}else{b})?,k(t(2,1)?)?)),
                203=>{
                    code.push("r4, r5 = r1(r2, r3)".into());
                    code.push("if r4 ~= nil then r3 = r4 end".into());
                    condition=Some("r4 ~= nil".into());
                }
                14=>{
                    code.push("r6, r7 = r6(r7)".into());condition=Some("r6".into());
                }
                159=>{
                    code.push("branchResult, r2 = r1(r2)".into());condition=Some("not branchResult".into());
                }
                253|171=>{
                    code.push(format!("environment[{}]({}, r5[{}], r5[{}], r7)",k(c)?,k(t(2,1)?)?,k(t(2,2)?)?,k(t(2,3)?)?));
                    code.push(format!("r11, r13 = r5[{}], r7",k(t(2,2)?)?));
                }
                157=>{
                    code.push(format!("r12 = environment[{}]",k(c)?));code.push(format!("r9 = r12[{}]",k(t(2,1)?)?));code.push(format!("r10 = {}",k(t(2,2)?)?));
                    code.push("r9(r10)".into());code.push("r4, r5 = r1(r2, r3)".into());code.push("if r4 ~= nil then r3 = r4 end".into());condition=Some("r4 ~= nil".into());
                }
                236=>code.push(format!("if type(r{a}) == \"table\" then local mt = getmetatable(r{a}); if type(mt) == \"table\" and mt.__iter then r{a} = mt.__iter(r{a}) else r{a}, r{}, r{} = next, r{a}, nil end end",a+1,a+2)),
                _=>return Err(format!("Unmapped opcode {op} at {name}:{pc}")),
            }
            let successors = sequence(&row["successors"])
                .iter()
                .map(num)
                .collect::<Result<Vec<_>, _>>()?;
            nodes.insert(
                pc,
                Node {
                    code,
                    condition,
                    successors,
                },
            );
        }
        let body = structured(&nodes)?;
        for line in body.lines() {
            out.push_str("    ");
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("end");
        Ok(out)
    }
}

fn reachable(
    nodes: &BTreeMap<i64, Node>,
    start: i64,
    stop: Option<i64>,
    loop_headers: &[i64],
) -> HashSet<i64> {
    let mut seen = HashSet::new();
    let mut queue = vec![start];
    while let Some(pc) = queue.pop() {
        if Some(pc) == stop || loop_headers.contains(&pc) || !seen.insert(pc) {
            continue;
        }
        if let Some(node) = nodes.get(&pc) {
            queue.extend(&node.successors);
        }
    }
    seen
}
pub(crate) fn structured(nodes: &BTreeMap<i64, Node>) -> Result<String, String> {
    let mut predecessors: HashMap<i64, Vec<i64>> = HashMap::new();
    for (pc, node) in nodes {
        for target in &node.successors {
            predecessors.entry(*target).or_default().push(*pc);
        }
    }
    let heads: BTreeSet<_> = nodes
        .keys()
        .copied()
        .filter(|pc| {
            if *pc == 1 {
                return true;
            }
            let incoming = predecessors.get(pc).map(Vec::as_slice).unwrap_or(&[]);
            incoming.len() != 1 || nodes[&incoming[0]].successors.len() != 1
        })
        .collect();
    let mut blocks = BTreeMap::new();
    for head in &heads {
        let mut pc = *head;
        let mut code = Vec::new();
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(pc) {
                return Err(format!("Unbounded basic block at {pc}"));
            }
            let node = nodes
                .get(&pc)
                .ok_or_else(|| format!("Missing CFG node {pc}"))?;
            code.extend(node.code.clone());
            if let [next] = node.successors.as_slice() {
                if !heads.contains(next) {
                    pc = *next;
                    continue;
                }
            }
            blocks.insert(
                *head,
                Node {
                    code,
                    condition: node.condition.clone(),
                    successors: node.successors.clone(),
                },
            );
            break;
        }
    }
    let nodes = &blocks;
    let mut dominators: HashMap<i64, BTreeSet<i64>> = nodes
        .keys()
        .map(|pc| (*pc, nodes.keys().copied().collect()))
        .collect();
    dominators.insert(1, [1].into());
    for _ in 0..nodes.len() {
        let mut changed = false;
        for &pc in nodes.keys().filter(|pc| **pc != 1) {
            let preds: Vec<_> = nodes
                .iter()
                .filter(|(_, node)| node.successors.contains(&pc))
                .map(|(p, _)| *p)
                .collect();
            let mut set = preds
                .first()
                .map(|p| dominators[p].clone())
                .unwrap_or_default();
            for p in preds.iter().skip(1) {
                set = set.intersection(&dominators[p]).copied().collect();
            }
            set.insert(pc);
            if set != dominators[&pc] {
                dominators.insert(pc, set);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut loops: HashMap<i64, HashSet<i64>> = HashMap::new();
    for (&pc, node) in nodes {
        for &target in &node.successors {
            if dominators.get(&pc).is_some_and(|d| d.contains(&target)) {
                let body = loops
                    .entry(target)
                    .or_insert_with(|| HashSet::from([target]));
                body.insert(pc);
                let mut pending = vec![pc];
                while let Some(n) = pending.pop() {
                    if n == target {
                        continue;
                    }
                    for (&pred, pnode) in nodes {
                        if pnode.successors.contains(&n) && body.insert(pred) {
                            pending.push(pred);
                        }
                    }
                }
            }
        }
    }
    struct Walker<'a> {
        nodes: &'a BTreeMap<i64, Node>,
        loops: HashMap<i64, HashSet<i64>>,
        active: Vec<i64>,
        multi_exit: HashSet<i64>,
        budget: usize,
    }
    impl Walker<'_> {
        fn walk(
            &mut self,
            mut pc: i64,
            stop: Option<i64>,
            indent: usize,
            mut enter_loop: bool,
        ) -> Result<String, String> {
            let mut out = String::new();
            let pad = "    ".repeat(indent);
            let mut local = HashSet::new();
            loop {
                self.budget = self
                    .budget
                    .checked_sub(1)
                    .ok_or("CFG structuring budget exceeded")?;
                if Some(pc) == stop {
                    return Ok(out);
                }
                if let Some(&header) = self.active.last() {
                    if pc == header && !enter_loop {
                        out.push_str(&format!("{pad}continue\n"));
                        return Ok(out);
                    }
                    if !self.loops[&header].contains(&pc) {
                        if self.multi_exit.contains(&header) {
                            out.push_str(&format!("{pad}loopExit{header} = {pc}\n"));
                        }
                        out.push_str(&format!("{pad}break\n"));
                        return Ok(out);
                    }
                }
                enter_loop = false;
                if !local.insert(pc) {
                    return Err(format!(
                        "Unstructured cycle at {pc}; stop={stop:?}; active loops={:?}",
                        self.active
                    ));
                }
                if let Some(body) = self.loops.get(&pc).cloned() {
                    if !self.active.contains(&pc) {
                        let exits: BTreeSet<_> = body
                            .iter()
                            .flat_map(|p| self.nodes[p].successors.iter())
                            .filter(|p| !body.contains(p))
                            .copied()
                            .collect();
                        if exits.len() > 1 {
                            self.multi_exit.insert(pc);
                            out.push_str(&format!("{pad}local loopExit{pc}\n"));
                        }
                        out.push_str(&format!("{pad}while true do\n"));
                        self.active.push(pc);
                        out.push_str(&self.walk(pc, None, indent + 1, true)?);
                        self.active.pop();
                        out.push_str(&format!("{pad}end\n"));
                        if exits.len() > 1 {
                            let paths: Vec<_> = exits
                                .iter()
                                .map(|exit| reachable(self.nodes, *exit, Some(pc), &self.active))
                                .collect();
                            let mut common = paths[0].clone();
                            for path in paths.iter().skip(1) {
                                common.retain(|node| path.contains(node));
                            }
                            // The common post-loop region is emitted once after the exit branches.
                            let join = common
                                .into_iter()
                                .filter(|node| !body.contains(node))
                                .min()
                                .or(stop);
                            for (index, exit) in exits.iter().enumerate() {
                                if index == 0 {
                                    out.push_str(&format!("{pad}if loopExit{pc} == {exit} then\n"));
                                } else if index + 1 == exits.len() {
                                    out.push_str(&format!("{pad}else\n"));
                                } else {
                                    out.push_str(&format!(
                                        "{pad}elseif loopExit{pc} == {exit} then\n"
                                    ));
                                }
                                out.push_str(&self.walk(*exit, join, indent + 1, false)?);
                            }
                            out.push_str(&format!("{pad}end\n"));
                            if let Some(join) = join {
                                pc = join;
                                continue;
                            }
                            return Ok(out);
                        }
                        if let Some(exit) = exits.first() {
                            pc = *exit;
                            continue;
                        }
                        return Ok(out);
                    }
                }
                let Some(node) = self.nodes.get(&pc) else {
                    return Err(format!("Missing CFG node {pc}"));
                };
                for line in &node.code {
                    for line in line.lines() {
                        out.push_str(&pad);
                        out.push_str(line);
                        out.push('\n');
                    }
                }
                match node.successors.as_slice() {
                    [] => return Ok(out),
                    [next] => {
                        pc = *next;
                    }
                    [yes, no] => {
                        let cond = node
                            .condition
                            .as_ref()
                            .ok_or_else(|| format!("Missing branch condition at {pc}"))?
                            .clone();
                        let yes = *yes;
                        let no = *no;
                        let y = reachable(self.nodes, yes, Some(pc), &self.active);
                        let n = reachable(self.nodes, no, Some(pc), &self.active);
                        let mut common: Vec<_> = y
                            .intersection(&n)
                            .copied()
                            .filter(|p| Some(*p) != self.active.last().copied())
                            .collect();
                        let distances = |start: i64| {
                            let mut q = VecDeque::from([(start, 0)]);
                            let mut found = HashMap::new();
                            while let Some((p, d)) = q.pop_front() {
                                if p == pc || self.active.contains(&p) || found.contains_key(&p) {
                                    continue;
                                }
                                found.insert(p, d);
                                if let Some(n) = self.nodes.get(&p) {
                                    for &s in &n.successors {
                                        q.push_back((s, d + 1));
                                    }
                                }
                            }
                            found
                        };
                        let yes_distances = distances(yes);
                        let no_distances = distances(no);
                        common.sort_by_key(|p| (yes_distances[p] + no_distances[p], *p));
                        let join = common.first().copied().or(stop);
                        out.push_str(&format!("{pad}if {cond} then\n"));
                        out.push_str(&self.walk(yes, join, indent + 1, false)?);
                        out.push_str(&format!("{pad}else\n"));
                        out.push_str(&self.walk(no, join, indent + 1, false)?);
                        out.push_str(&format!("{pad}end\n"));
                        if let Some(join) = join {
                            pc = join;
                        } else {
                            return Ok(out);
                        }
                    }
                    _ => return Err("More than two successors".into()),
                }
            }
        }
    }
    Walker {
        nodes,
        loops,
        active: Vec::new(),
        multi_exit: HashSet::new(),
        budget: 10000,
    }
    .walk(1, None, 0, false)
}

pub fn emit(ir: &Value) -> Result<String, String> {
    let mut emitter = Emitter { ir };
    let function = emitter.function("root", &[])?;
    Ok(format!(
        "-- Recovered from chess.luau; generated from decoded instructions.\n-- The custom VM is removed. Register names are generated, not original names.\n-- External modules are referenced as in the supplied program.\nlocal environment = getfenv()\nlocal function isFunctionType(value) return value == \"function\" end\nreturn ({function})(...)\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loops_preserve_two_distinct_exit_paths() {
        let node = |code: &str, condition: Option<&str>, successors: Vec<i64>| Node {
            code: if code.is_empty() {
                vec![]
            } else {
                vec![code.into()]
            },
            condition: condition.map(str::to_string),
            successors,
        };
        let nodes = BTreeMap::from([
            (1, node("", Some("i < limit"), vec![2, 5])),
            (2, node("i += 1", Some("i == 3"), vec![4, 1])),
            (4, node("result = 'early'", None, vec![6])),
            (5, node("result = 'normal'", None, vec![6])),
            (6, node("return result, i", None, vec![])),
        ]);
        let body = structured(&nodes).unwrap();
        for (limit, expected, count) in [(2, "normal", 2), (5, "early", 3)] {
            let lua = crate::vm::restricted_lua().unwrap();
            let source = format!("local limit = ...; local i = 0; local result\n{body}");
            let (result, iterations): (String, i32) = lua.load(source).call(limit).unwrap();
            assert_eq!((result.as_str(), iterations), (expected, count));
        }
    }

    #[test]
    fn nested_loop_joins_do_not_cross_iteration_headers() {
        let node = |code: &str, condition: Option<&str>, successors: Vec<i64>| Node {
            code: if code.is_empty() {
                vec![]
            } else {
                vec![code.into()]
            },
            condition: condition.map(str::to_string),
            successors,
        };
        let nodes = BTreeMap::from([
            (1, node("", Some("i < 2"), vec![2, 10])),
            (2, node("j = 0", None, vec![3])),
            (3, node("", Some("choice"), vec![4, 5])),
            (4, node("j += 1; result ..= 'a'", None, vec![6])),
            (5, node("j += 1; result ..= 'b'", None, vec![6])),
            (6, node("", Some("j == 2"), vec![8, 7])),
            (7, node("", None, vec![3])),
            (8, node("i += 1", None, vec![1])),
            (10, node("return result, i, j", None, vec![])),
        ]);
        let body = structured(&nodes).unwrap();
        for (choice, expected) in [(true, "aaaa"), (false, "bbbb")] {
            let lua = crate::vm::restricted_lua().unwrap();
            let source =
                format!("local choice = ...; local i, j = 0, 0; local result = ''\n{body}");
            let (result, i, j): (String, i32, i32) = lua.load(source).call(choice).unwrap();
            assert_eq!((result.as_str(), i, j), (expected, 2, 2));
        }
    }
}
