use std::borrow::Cow;

pub mod parser;

#[derive(Debug)]
pub struct Line {
    pid: libc::pid_t,
    timestamp: jiff::Timestamp,
    event: Event,
}

#[derive(Debug)]
enum Event {
    Syscall {
        name: String,
        args: Fields,
        result: SyscallResult,
        duration: std::time::Duration,
    },
    Signal {
        signal: Value,
        siginfo: Fields,
    },
    Exited {
        code: Value,
    },
    KilledBy {
        signal: Value,
    },
}

#[derive(Debug)]
enum Value {
    String(bstr::BString),
    TruncatedString(bstr::BString),
    Expression(String),
    FunctionCall {
        function: String,
        args: Vec<Value>,
    },
    Struct(Fields),
    SparseArray(Vec<(Value, Value)>),
    Array(Vec<Value>),
    NotBitSet(Vec<Value>),
    Annotated {
        value: Box<Value>,
        annotation: bstr::BString,
        deleted: bool,
    },
    Commented {
        value: Box<Value>,
        comment: String,
    },
    Changed {
        from: Box<Value>,
        to: Box<Value>,
    },
    Alternative {
        left: Box<Value>,
        right: Box<Value>,
    },
    Truncated,
}

#[derive(Debug)]
struct Fields {
    entries: Vec<(Option<String>, Value)>,
    truncated: bool,
}

#[derive(Debug)]
struct SyscallResult {
    value: Option<Value>,
    message: String,
}
