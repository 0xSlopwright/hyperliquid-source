//! Input-only normal W/G test proxies and observable recording.
//! No expected trace/parent phase labels, native layout or value-format claim.
use node94_field_request_protocol::{try_field_protocol, ContextKind, FieldCells, ValueContext, WriterWords};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Write;

pub type WriterProxy<'a> = dyn FnMut(u64, u64, &[u8], Option<&Cell<u8>>) -> u8 + 'a;

enum Action {
    Error(u8), Present(u8), Formatter(usize), Newline(u8),
    Destination(usize, u64), Table(usize, u64), Flags(usize, u64),
    Method(u64, u64), Descriptor(u64, u64),
}

struct WriterStep { result: u8, actions: Vec<Action> }
enum Operation { Change(Action), Request(Vec<u8>) }
struct ValuePlan { result: Option<u8>, operations: Vec<Operation> }
struct Call { name: Vec<u8>, data: u64, descriptor: u64 }
struct Case {
    id: String, error: u8, present: u8, formatter: usize,
    words: [[u64; 3]; 3], methods: BTreeMap<u64, u64>, descriptors: BTreeMap<u64, u64>,
    calls: Vec<Call>, writer_steps: Vec<WriterStep>, writer_default: WriterStep,
    value_plans: Vec<ValuePlan>, value_default: ValuePlan,
}

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "complete hex bytes");
    text.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("hex byte")
    }).collect()
}

fn encoded(bytes: &[u8]) -> String {
    let mut result = String::new();
    for byte in bytes { write!(result, "{byte:02x}").unwrap(); }
    result
}

fn word(text: &str) -> u64 { text.parse().expect("unsigned word") }
fn byte(text: &str) -> u8 { text.parse().expect("raw byte") }
fn formatter(text: &str) -> usize {
    let index: usize = text.parse().expect("formatter ID");
    assert!(index < 3, "three logical formatter objects"); index
}
fn map(text: &str) -> BTreeMap<u64, u64> {
    if text.is_empty() { return BTreeMap::new(); }
    text.split(',').map(|item| {
        let (key, value) = item.split_once(':').expect("key:method"); (word(key), word(value))
    }).collect()
}
fn action(text: &str) -> Action {
    let (kind, value) = text.split_at(1);
    match kind {
        "E" => Action::Error(byte(value)), "H" => Action::Present(byte(value)),
        "F" => Action::Formatter(formatter(value)), "N" => Action::Newline(byte(value)),
        "D" | "T" | "U" => {
            let (id, value) = value.split_once('=').expect("formatter=word");
            let id = formatter(id); let value = word(value);
            match kind { "D" => Action::Destination(id, value), "T" => Action::Table(id, value), _ => Action::Flags(id, value) }
        }
        "M" | "V" => {
            let (key, value) = value.split_once('=').expect("key=method");
            if kind == "M" { Action::Method(word(key), word(value)) } else { Action::Descriptor(word(key), word(value)) }
        }
        _ => panic!("unknown normal-proxy action"),
    }
}
fn writer_step(text: &str) -> WriterStep {
    let (result, actions) = text.split_once('/').expect("AL/actions");
    WriterStep { result: byte(result), actions: if actions.is_empty() { Vec::new() } else { actions.split(',').map(action).collect() } }
}
fn value_plan(text: &str) -> ValuePlan {
    let (result, operations) = text.split_once('/').expect("return/ops");
    ValuePlan { result: if result == "l" { None } else { Some(byte(result)) },
        operations: if operations.is_empty() { Vec::new() } else { operations.split('!').map(|op| {
            if let Some(value) = op.strip_prefix('Q') { Operation::Request(hex(value)) }
            else { Operation::Change(action(op)) }
        }).collect() } }
}
fn case(text: &str) -> Case {
    let fields: Vec<_> = text.split('|').collect(); assert_eq!(fields.len(), 10, "ten input-only fields");
    assert!(!fields[0].is_empty() && fields[0].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    let initial: Vec<_> = fields[1].split(':').collect(); assert_eq!(initial.len(), 3);
    let pool: Vec<_> = fields[2].split(',').map(|row| {
        let row: Vec<_> = row.split(':').map(word).collect(); assert_eq!(row.len(), 3); [row[0], row[1], row[2]]
    }).collect(); assert_eq!(pool.len(), 3);
    assert!(!fields[5].is_empty(), "at least one invocation per stimulus");
    let calls = fields[5].split(';').map(|call| {
        let row: Vec<_> = call.split(':').collect(); assert_eq!(row.len(), 3);
        Call { name: hex(row[0]), data: word(row[1]), descriptor: word(row[2]) }
    }).collect();
    Case { id: fields[0].into(), error: byte(initial[0]), present: byte(initial[1]), formatter: formatter(initial[2]),
        words: [pool[0], pool[1], pool[2]], methods: map(fields[3]), descriptors: map(fields[4]), calls,
        writer_steps: if fields[6].is_empty() { Vec::new() } else { fields[6].split(';').map(writer_step).collect() },
        writer_default: writer_step(fields[7]),
        value_plans: if fields[8].is_empty() { Vec::new() } else { fields[8].split(';').map(value_plan).collect() },
        value_default: value_plan(fields[9]) }
}

struct Environment<'s, 'f> {
    state: &'s FieldCells<'f>, pool: &'f [WriterWords; 3],
    methods: RefCell<BTreeMap<u64, u64>>, descriptors: RefCell<BTreeMap<u64, u64>>,
    events: RefCell<Vec<String>>, writer_index: Cell<usize>, value_index: Cell<usize>,
}
impl<'s, 'f> Environment<'s, 'f> {
    fn id(&self, words: &WriterWords) -> String {
        self.pool.iter().position(|candidate| std::ptr::eq(candidate, words)).map(|id| id.to_string()).unwrap_or_else(|| "x".into())
    }
    fn state(&self) -> String {
        format!("{}:{}:{}", self.state.error.get(), self.state.present.get(), self.id(self.state.formatter.get()))
    }
    fn apply(&self, change: &Action, newline: Option<&Cell<u8>>) {
        match change {
            Action::Error(value) => self.state.error.set(*value),
            Action::Present(value) => self.state.present.set(*value),
            Action::Formatter(id) => self.state.formatter.set(&self.pool[*id]),
            Action::Newline(value) => { if let Some(flag) = newline { flag.set(*value); } },
            Action::Destination(id, value) => self.pool[*id].destination.set(*value),
            Action::Table(id, value) => self.pool[*id].table.set(*value),
            Action::Flags(id, value) => self.pool[*id].flags.set(*value),
            Action::Method(key, value) => { self.methods.borrow_mut().insert(*key, *value); },
            Action::Descriptor(key, value) => { self.descriptors.borrow_mut().insert(*key, *value); },
        }
    }
    fn context<W: ?Sized>(&self, context: &ValueContext<'_, W>) -> String
    where W: FnMut(u64, u64, &[u8], Option<&Cell<u8>>) -> u8 {
        let kind = match context.kind() { ContextKind::Flat => 'f', ContextKind::Pretty => 'p' };
        let id = context.flat_writer().map(|words| self.id(words)).unwrap_or_else(|| "-".into());
        let (destination, table) = context.writer_words();
        format!("{kind}:{id}:{destination}:{table}:{}:{}:{}", context.raw_flags_word(), optional(context.newline_flag().map(Cell::get)), self.state())
    }
}
fn optional(value: Option<u8>) -> String { value.map(|v| v.to_string()).unwrap_or_else(|| "-".into()) }
fn map_string(map: &BTreeMap<u64, u64>) -> String { map.iter().map(|(key, value)| format!("{key}:{value}")).collect::<Vec<_>>().join(",") }

/// Execute only the given normal test proxies against the actual production
/// API. Stimuli contain no expected trace or parent/writer phase labels.
pub fn transcript(line: &str) -> String {
    let case = case(line);
    let pool = case.words.map(|[destination, table, flags]| WriterWords::new(destination, table, flags));
    let state = FieldCells::new(&pool[case.formatter], case.error, case.present);
    let environment = Environment { state: &state, pool: &pool, methods: RefCell::new(case.methods), descriptors: RefCell::new(case.descriptors),
        events: RefCell::new(Vec::new()), writer_index: Cell::new(0), value_index: Cell::new(0) };
    let mut writer = |destination: u64, table: u64, bytes: &[u8], newline: Option<&Cell<u8>>| {
        let index = environment.writer_index.get(); environment.writer_index.set(index+1);
        let method = environment.methods.borrow().get(&table).copied().unwrap_or(0);
        let before = environment.state(); let n_before = optional(newline.map(Cell::get));
        let step = case.writer_steps.get(index).unwrap_or(&case.writer_default);
        for change in &step.actions { environment.apply(change, newline); }
        environment.events.borrow_mut().push(format!("w:{index}:{destination}:{table}:{method}:{}:{n_before}:{}:{}:{before}:{}",
            encoded(bytes), step.result, optional(newline.map(Cell::get)), environment.state()));
        step.result
    };
    let proxy: &mut WriterProxy<'_> = &mut writer;
    let mut value = |data: u64, descriptor: u64, context: &mut ValueContext<'_, WriterProxy<'_>>| {
        let index = environment.value_index.get(); environment.value_index.set(index+1);
        let method = environment.descriptors.borrow().get(&descriptor).copied().unwrap_or(0);
        environment.events.borrow_mut().push(format!("g:{index}:{data}:{descriptor}:{method}:{}", environment.context(context)));
        let plan = case.value_plans.get(index).unwrap_or(&case.value_default);
        let mut last = 0; let mut request_index = 0;
        for operation in &plan.operations {
            match operation {
                Operation::Change(change) => environment.apply(change, context.newline_flag()),
                Operation::Request(bytes) => {
                    last = context.request(bytes);
                    environment.events.borrow_mut().push(format!("q:{index}:{request_index}:{}:{last}:{}", encoded(bytes), environment.context(context)));
                    request_index += 1;
                }
            }
        }
        let result = plan.result.unwrap_or(last);
        environment.events.borrow_mut().push(format!("v:{index}:{result}:{}", environment.context(context)));
        result
    };
    for (index, call) in case.calls.iter().enumerate() {
        let result = try_field_protocol(&state, &call.name, call.data, call.descriptor, &mut *proxy, &mut value);
        let identity = match result { None => 0, Some(actual) if std::ptr::eq(actual, &state) => 1, Some(_) => 2 };
        environment.events.borrow_mut().push(format!("r:{index}:{identity}:{}", environment.state()));
    }
    let words = pool.iter().map(|words| format!("{}:{}:{}", words.destination.get(), words.table.get(), words.flags.get())).collect::<Vec<_>>().join(",");
    format!("{};S={};F={words};M={};V={};X={}", case.id, environment.state(), map_string(&environment.methods.borrow()),
        map_string(&environment.descriptors.borrow()), environment.events.borrow().join(","))
}
