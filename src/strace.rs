use std::borrow::Cow;

use blame_on::Blame;

use crate::Pid;

// pub mod emitter;
pub mod parser;

#[derive(Debug)]
pub struct Line<'a> {
    pub pid: Pid,
    pub timestamp: jiff::Timestamp,
    pub event: Event<'a>,
}

#[derive(Debug)]
pub enum Event<'a> {
    Syscall(SyscallEvent<'a>),
    Signal { signal: &'a str },
    Exited { code: &'a str },
    KilledBy { signal: &'a str },
}

#[derive(Debug)]
pub struct SyscallEvent<'a> {
    pub name: &'a str,
    pub args_string: Blame<&'a str>,
    pub result_string: Blame<&'a str>,
    pub duration: std::time::Duration,
}

#[derive(Debug, PartialEq, Eq)]
enum Value<'a> {
    String(Cow<'a, bstr::BStr>),
    TruncatedString(Cow<'a, bstr::BStr>),
    Expression(&'a str),
    FunctionCall {
        function: &'a str,
        args: Vec<Field<'a>>,
    },
    Struct(Vec<Field<'a>>),
    SparseArray(Vec<(Value<'a>, Value<'a>)>),
    Array(Vec<Value<'a>>),
    NotBitset(Vec<Value<'a>>),
    Annotated {
        value: Box<Value<'a>>,
        annotation: Cow<'a, bstr::BStr>,
        deleted: bool,
    },
    Commented {
        value: Box<Value<'a>>,
        comment: &'a str,
    },
    Changed {
        from: Box<Value<'a>>,
        to: Box<Value<'a>>,
    },
    Alternative {
        left: Box<Value<'a>>,
        right: Box<Value<'a>>,
    },
    BinaryOperations {
        first: Box<Value<'a>>,
        operators_and_operands: Vec<(BinaryOperator, Value<'a>)>,
    },
    Truncated,
}

impl Value<'_> {
    fn to_bstring(&self) -> Option<Cow<'_, bstr::BStr>> {
        match self {
            Self::String(bstr) => Some(Cow::Borrowed(&**bstr)),
            Self::TruncatedString(bstring) => {
                let mut bstring = bstring.clone().into_owned();
                bstring.extend_from_slice(b"...");
                Some(Cow::Owned(bstring))
            }
            Self::Expression(_) => None,
            Self::FunctionCall { .. } => None,
            Self::Struct(..) => None,
            Self::SparseArray(..) => None,
            Self::Array(..) => None,
            Self::NotBitset(..) => None,
            Self::Annotated {
                value,
                annotation,
                deleted: _,
            } => {
                let bstring = value
                    .to_bstring()
                    .unwrap_or(Cow::Borrowed(bstr::BStr::new(&**annotation)));
                Some(bstring)
            }
            Self::Commented { value, comment: _ } => value.to_bstring(),
            Self::Changed { from, to: _ } => from.to_bstring(),
            Self::Alternative { left, right: _ } => left.to_bstring(),
            Self::BinaryOperations { .. } | Self::Truncated => None,
        }
    }

    fn as_array(&'_ self) -> Option<&'_ [Value<'_>]> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOperator {
    And,
    Or,
    Equal,
    NotEqual,
}

#[derive(Debug)]
struct LazyFields<'a> {
    string: Blame<&'a str>,
}

struct Fields<'a> {
    values: Vec<Field<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Field<'a> {
    pub name: Option<&'a str>,
    pub value: Value<'a>,
}
