use chumsky::prelude::*;

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

type ParserError<'a> = extra::Err<Rich<'a, char>>;

pub fn line_parser<'a>() -> impl chumsky::Parser<'a, &'a str, Line, ParserError<'a>> {
    let pid = text::int(10).try_map(|pid: &str, span| {
        pid.parse::<libc::pid_t>()
            .map_err(|e| Rich::custom(span, e))
    });

    let signed_duration = one_of("+-")
        .or_not()
        .then(text::int(10))
        .to_slice()
        .then(
            just(".")
                .then(one_of("0123456789").repeated().at_least(1))
                .to_slice()
                .or_not(),
        )
        .try_map(|(seconds, fraction): (&str, Option<&str>), span| {
            let seconds = seconds.parse::<i64>().map_err(|e| Rich::custom(span, e))?;

            let nanoseconds = if let Some(fraction) = fraction {
                let fraction = fraction.parse::<f64>().map_err(|e| Rich::custom(span, e))?;
                let nanoseconds = (fraction * 1_000_000_000.0).round() as i32;
                nanoseconds.clamp(0, 999_999_999)
            } else {
                0
            };

            Ok(jiff::SignedDuration::new(seconds, nanoseconds))
        });
    let duration = signed_duration.try_map(|duration, span| {
        std::time::Duration::try_from(duration).map_err(|e| Rich::custom(span, e))
    });
    let timestamp = signed_duration.try_map(|duration, span| {
        jiff::Timestamp::from_duration(duration).map_err(|e| Rich::custom(span, e))
    });

    let string_escape = just('\\').ignore_then(choice((
        just('\\').to(b'\\'),
        just('a').to(0x07),
        just('b').to(0x08),
        just('e').to(0x1B),
        just('f').to(0x0C),
        just('n').to(b'\n'),
        just('r').to(b'\r'),
        just('t').to(b'\t'),
        just('v').to(0x0B),
        just('\'').to(b'\''),
        just('"').to(b'\"'),
        just('?').to(b'?'),
        just('x')
            .ignore_then(
                one_of("0123456789ABCDEFabcdef")
                    .repeated()
                    .exactly(2)
                    .to_slice(),
            )
            .try_map(|hex: &str, span| {
                let byte = u8::from_str_radix(hex, 16).map_err(|e| Rich::custom(span, e))?;
                Ok(byte)
            }),
        one_of("01234567")
            .repeated()
            .at_least(1)
            .at_most(3)
            .to_slice()
            .try_map(|octal: &str, span| {
                let byte = u8::from_str_radix(octal, 8).map_err(|e| Rich::custom(span, e))?;
                Ok(byte)
            }),
    )));

    let string = none_of("\\\"")
        .try_map(|c: char, span| u8::try_from(c).map_err(|e| Rich::custom(span, e)))
        .or(string_escape)
        .repeated()
        .collect::<Vec<u8>>()
        .map(bstr::BString::new)
        .delimited_by(just("\""), just("\""));

    let text_annotation = recursive(|text_annotation| {
        none_of("\\\"<>")
            .try_map(|c: char, span| u8::try_from(c).map_err(|e| Rich::custom(span, e)))
            .or(string_escape)
            .repeated()
            .collect::<Vec<u8>>()
            .map(bstr::BString::new)
            .then(text_annotation.to_slice().or_not())
            .map(|(mut left, right): (_, Option<&str>)| {
                if let Some(right) = right {
                    left.extend_from_slice(right.as_bytes());
                }

                left
            })
            .delimited_by(just("<"), just(">"))
    })
    .then(just("(deleted)").ignored().or_not())
    .map(|(annotation, deleted)| (annotation, deleted.is_some()));
    let label_annotation = choice((
        one_of('a'..'z'),
        one_of('A'..'Z'),
        one_of('0'..'9'),
        one_of("-_"),
    ))
    .repeated()
    .then(just(':'))
    .then(just("->").ignored().or(none_of("<>").ignored()).repeated())
    .to_slice()
    .map(bstr::BString::from)
    .delimited_by(just("<"), just(">").and_is(just("->").not()))
    .map(|annotation| (annotation, false));
    let annotation = label_annotation.or(text_annotation);

    let comment = just::<_, &str, ParserError>("/*")
        .ignore_then(
            any()
                .and_is(just("*/").not())
                .repeated()
                .to_slice()
                .padded(),
        )
        .then_ignore(just("*/"));

    let basic_expression = one_of::<_, &str, ParserError>(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-*/^&|",
    )
    .repeated()
    .at_least(1)
    .to_slice()
    .map(String::from);

    let value = recursive(|value| {
        choice((
            string
                .then(just("...").ignored().or_not())
                .map(|(string, ellipses)| {
                    if ellipses.is_some() {
                        Value::TruncatedString(string)
                    } else {
                        Value::String(string)
                    }
                }),
            text::ident()
                .then(
                    value
                        .clone()
                        .separated_by(just(",").padded())
                        .collect::<Vec<_>>()
                        .delimited_by(just("("), just(")")),
                )
                .map(|(function, args): (&str, _)| Value::FunctionCall {
                    function: function.into(),
                    args,
                }),
            value
                .clone()
                .delimited_by(just("["), just("]"))
                .then_ignore(just("="))
                .then(value.clone())
                .separated_by(just(",").padded())
                .collect::<Vec<_>>()
                .delimited_by(just("["), just("]"))
                .map(Value::SparseArray),
            just("~")
                .ignored()
                .or_not()
                .then(
                    value
                        .clone()
                        .separated_by(
                            just(",")
                                .padded()
                                .ignored()
                                .or(text::whitespace().at_least(1)),
                        )
                        .collect::<Vec<_>>()
                        .delimited_by(just("["), just("]")),
                )
                .map(|(not, values)| {
                    if not.is_some() {
                        Value::NotBitSet(values)
                    } else {
                        Value::Array(values)
                    }
                }),
            text::ident()
                .then_ignore(just("=").padded())
                .or_not()
                .then(value.clone())
                .map(|(name, value)| (name.map(String::from), value))
                .separated_by(just(",").padded())
                .collect::<Vec<_>>()
                .then(just(",").padded().then(just("...")).ignored().or_not())
                .delimited_by(just("{"), just("}"))
                .map(|(entries, truncated)| {
                    Value::Struct(Fields {
                        entries,
                        truncated: truncated.is_some(),
                    })
                }),
            basic_expression.map(Value::Expression),
            value
                .clone()
                .separated_by(choice((just("&&"), just("||"), just("=="))).padded())
                .at_least(2)
                .delimited_by(just("{"), just("}"))
                .to_slice()
                .map(|expr: &str| Value::Expression(expr.into())),
        ))
        .then(annotation.or_not())
        .map(|(value, annotation)| {
            if let Some((annotation, deleted)) = annotation {
                Value::Annotated {
                    value: value.into(),
                    annotation,
                    deleted,
                }
            } else {
                value
            }
        })
        .then(comment.padded().or_not())
        .map(|(value, comment)| {
            if let Some(comment) = comment {
                Value::Commented {
                    value: value.into(),
                    comment: comment.into(),
                }
            } else {
                value
            }
        })
        .then(just(" or ").ignore_then(value.clone()).or_not())
        .map(|(left, right)| {
            if let Some(right) = right {
                Value::Alternative {
                    left: left.into(),
                    right: right.into(),
                }
            } else {
                left
            }
        })
        .then(just("=>").padded().ignore_then(value.clone()).or_not())
        .map(|(from, to)| {
            if let Some(to) = to {
                Value::Changed {
                    from: from.into(),
                    to: to.into(),
                }
            } else {
                from
            }
        })
    });

    let syscall_duration = duration.delimited_by(just("<"), just(">"));

    let syscall_result = value
        .clone()
        .map(Some)
        .or(just("?").map(|_| None))
        .padded()
        .then(
            any()
                .and_is(syscall_duration.then(end()).not())
                .repeated()
                .to_slice()
                .map(String::from),
        )
        .map(|(value, message)| SyscallResult { value, message });

    let syscall = group((
        text::ident().map(String::from),
        text::ident()
            .then_ignore(just("="))
            .or_not()
            .then(value.clone())
            .map(|(key, value)| (key.map(String::from), value))
            .separated_by(just(",").padded())
            .collect::<Vec<_>>()
            .delimited_by(just("("), just(")")),
        just("=").padded().ignore_then(syscall_result),
        syscall_duration,
    ))
    .map(|(name, args, result, duration)| Event::Syscall {
        name,
        args: Fields {
            entries: args,
            truncated: false,
        },
        result,
        duration,
    });

    let exited = just("+++ exited with")
        .ignore_then(value.clone().and_is(just("+++").not()).padded())
        .then_ignore(just("+++"))
        .map(|code| Event::Exited { code });
    let killed_by = just("+++ killed by")
        .ignore_then(value.clone().and_is(just("+++").not()).padded())
        .then_ignore(just("+++"))
        .map(|signal| Event::KilledBy { signal });
    let signal = just("--- ")
        .ignore_then(value.clone())
        .then_ignore(text::whitespace().at_least(1))
        .then(value.and_is(just("---").not()).padded())
        .then_ignore(just("---"))
        .try_map(|(signal, siginfo), span| {
            let Value::Struct(siginfo) = siginfo else {
                return Err(Rich::custom(span, "Expected siginfo value to be a struct"));
            };

            Ok(Event::Signal { signal, siginfo })
        });

    let event = choice((syscall, exited, killed_by, signal));

    pid.then_ignore(text::whitespace().at_least(1))
        .then(timestamp)
        .then_ignore(text::whitespace().at_least(1))
        .then(event)
        .map(|((pid, timestamp), event)| Line {
            pid,
            timestamp,
            event,
        })
}
