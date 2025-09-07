use std::borrow::Cow;

pub mod emitter;
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

impl Value {
    fn to_bstring(&self) -> Option<Cow<'_, bstr::BStr>> {
        match self {
            Self::String(bstring) => Some(Cow::Borrowed(bstr::BStr::new(bstring))),
            Self::TruncatedString(bstring) => {
                let mut bstring = bstring.clone();
                bstring.extend_from_slice(b"...");
                Some(Cow::Owned(bstring))
            }
            Self::Expression(_) => None,
            Self::FunctionCall { .. } => None,
            Self::Struct(..) => None,
            Self::SparseArray(..) => None,
            Self::Array(..) => None,
            Self::NotBitSet(..) => None,
            Self::Annotated {
                value,
                annotation,
                deleted: _,
            } => {
                let bstring = value
                    .to_bstring()
                    .unwrap_or(Cow::Borrowed(bstr::BStr::new(annotation)));
                Some(bstring)
            }
            Self::Commented { value, comment: _ } => value.to_bstring(),
            Self::Changed { from, to: _ } => from.to_bstring(),
            Self::Alternative { left, right: _ } => left.to_bstring(),
            Self::Truncated => None,
        }
    }

    fn as_array(&self) -> Option<&[Value]> {
        if let Self::Array(values) = self {
            Some(values)
        } else {
            None
        }
    }

    fn as_i32(&self) -> Option<i32> {
        if let Self::Expression(expr) = self {
            expr.parse().ok()
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct Fields {
    entries: Vec<(Option<String>, Value)>,
    truncated: bool,
}

impl Fields {
    fn value_at_index(&self, index: usize) -> Option<&Value> {
        if let Some((_, value)) = self.entries.get(index) {
            return Some(value);
        }

        if self.truncated {
            None
        } else {
            panic!(
                "field index {index} is out of bounds (number of fields: {})",
                self.entries.len()
            );
        }
    }
}

#[derive(Debug)]
struct SyscallResult {
    value: Option<Value>,
    message: String,
}
