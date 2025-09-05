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
        args: Vec<Value>,
        result: SyscallResult,
        duration: std::time::Duration,
    },
    Signal {
        signal: Value,
        siginfo: Struct,
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
    Struct(Struct),
    Annotated {
        value: Box<Value>,
        annotation: bstr::BString,
    },
    Commented {
        value: Box<Value>,
        comment: bstr::BString,
    },
    Truncated,
}

#[derive(Debug)]
struct Struct {
    entries: Vec<(bstr::BString, Value)>,
}

#[derive(Debug)]
struct SyscallResult {
    value: Value,
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
            .ignore_then(text::int(16).repeated().exactly(2).to_slice())
            .try_map(|hex: &str, span| {
                let byte = u8::from_str_radix(hex, 16).map_err(|e| Rich::custom(span, e))?;
                Ok(byte)
            }),
        text::int(8)
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

    let annotation = none_of("\\\"<>")
        .try_map(|c: char, span| u8::try_from(c).map_err(|e| Rich::custom(span, e)))
        .or(string_escape)
        .repeated()
        .collect::<Vec<u8>>()
        .map(bstr::BString::new)
        .delimited_by(just("<"), just(">"));

    let comment = just::<_, &str, ParserError>("/*")
        .ignore_then(any().and_is(just("*/").not()).repeated())
        .then_ignore(just("*/"));

    let expression = one_of::<_, &str, ParserError>(
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
            expression.map(Value::Expression),
        ))
    });

    let syscall_duration = duration.delimited_by(just("<"), just(">"));

    let syscall_result = value
        .clone()
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
        value
            .padded()
            .separated_by(just(","))
            .collect::<Vec<_>>()
            .delimited_by(just("("), just(")")),
        just("=").padded().ignore_then(syscall_result),
        syscall_duration,
    ))
    .map(|(name, args, result, duration)| Event::Syscall {
        name,
        args,
        result,
        duration,
    });

    let event = choice((syscall,));

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
