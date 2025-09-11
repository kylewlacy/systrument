use std::borrow::Cow;

use blame_on::{Blame, Span};
use bstr::ByteVec as _;
use chumsky::prelude::*;

use crate::Pid;

use super::{Event, Field, Fields, Line, SyscallEvent, Value};

pub fn parse_line<'line, 'loc>(line: &'line str) -> Result<Line<'line>, StraceParseError> {
    let input = Blame::new_str(line);

    let (pid, input) = input
        .split_once(" ")
        .map_err(|blame| StraceParseError::new(blame.span, "expected pid"))?;
    let pid = pid
        .parse::<Pid>()
        .map_err(|blame| StraceParseError::new(blame.span, "invalid pid"))?;

    let (timestamp, input) = input
        .split_once(" ")
        .map_err(|blame| StraceParseError::new(blame.span, "expected timestamp"))?;
    let timestamp = timestamp
        .try_map(|timestamp| {
            let duration = parse_duration(timestamp)?;
            let timestamp = jiff::Timestamp::from_duration(duration).map_err(|_| ())?;
            Result::<_, ()>::Ok(timestamp)
        })
        .map_err(|blame| StraceParseError::new(blame.span, "invalid timestamp"))?;

    let event = if let Ok(input) = input.strip_prefix("+++ ") {
        let (event, input) = input
            .rsplit_once(" +++")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse exit event"))?;
        input
            .empty()
            .map_err(|blame| StraceParseError::new(blame.span, "expected end of input"))?;

        if let Ok(code) = event.strip_prefix("exited with ") {
            Event::Exited { code: code.value }
        } else if let Ok(signal) = event.strip_prefix("killed by ") {
            Event::KilledBy {
                signal: signal.value,
            }
        } else {
            return Err(StraceParseError::new(
                event.span,
                "could not parse exit event",
            ));
        }
    } else if let Ok(input) = input.strip_prefix("--- ") {
        let signal = input
            .strip_suffix(" ---")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse signal event"))?;
        Event::Signal {
            signal: signal.value,
        }
    } else {
        let (syscall_name, input) = input
            .split_once("(")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse event"))?;

        let (input, duration) = input
            .strip_suffix(">")
            .and_then(|input| input.rsplit_once(" <"))
            .map_err(|blame| {
                StraceParseError::new(blame.span, "expected duration at end of syscall")
            })?;
        let duration = duration
            .try_map(|duration| {
                let duration = parse_duration(duration)?;
                let duration = std::time::Duration::try_from(duration).map_err(|_| ())?;
                Result::<_, ()>::Ok(duration)
            })
            .map_err(|blame| StraceParseError::new(blame.span, "invalid duration"))?;
        let (input, result) = input
            .rsplit_once(" = ")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse syscall result"))?;
        let args = input
            .trim_ascii_end()
            .strip_suffix(")")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse syscall args"))?;

        Event::Syscall(SyscallEvent {
            name: syscall_name.value,
            args,
            result: result.value.trim(),
            duration: duration.value,
        })
    };

    Ok(Line {
        pid: pid.value,
        timestamp: timestamp.value,
        event,
    })
}

fn parse_duration(s: &str) -> Result<jiff::SignedDuration, ()> {
    let (seconds, subsecond) = if let Some(decimal_index) = s.find('.') {
        let (seconds, subsecond) = s.split_at(decimal_index);
        (seconds, Some(subsecond))
    } else {
        (s, None)
    };

    let seconds: i64 = seconds.parse().map_err(|_| ())?;
    let nanoseconds = if let Some(subsecond) = subsecond {
        let subsecond: f64 = subsecond.parse().map_err(|_| ())?;
        let nanoseconds = (subsecond * 1_000_000_000.0).round() as i32;
        nanoseconds.clamp(0, 999_999_999)
    } else {
        0
    };

    Ok(jiff::SignedDuration::new(seconds, nanoseconds))
}

fn parse_value<'a, 'src>(
    input: Blame<&'a str>,
) -> Result<(Value<'a>, Blame<&'a str>), StraceParseError> {
    if let Ok(string) = input.strip_prefix("\"") {
        let literal_string_end = string
            .map(|string| string.find(&['"', '\\']))
            .into_result()
            .map_err(|blame| StraceParseError::new(blame.span, "invalid string value"))?;
        let (literal_string, mut rest) = string.split_at(literal_string_end.value);
        let mut string = Cow::Borrowed(bstr::BStr::new(literal_string.value.as_bytes()));

        while let Ok(escape) = rest.strip_prefix("\\") {
            let escape_byte =
                escape.as_bytes().value.get(0).copied().ok_or_else(|| {
                    StraceParseError::new(escape.span, "unexpected end of string")
                })?;
            let (append, consumed) = match escape_byte {
                b'\\' => (b'\\', 1),
                b'a' => (0x07, 1),
                b'b' => (0x08, 1),
                b'e' => (0x1B, 1),
                b'f' => (0x0C, 1),
                b'n' => (b'\n', 1),
                b'r' => (b'\r', 1),
                b't' => (b'\t', 1),
                b'v' => (0x0B, 1),
                b'\'' => (b'\'', 1),
                b'"' => (b'"', 1),
                b'?' => (b'?', 1),
                b'x' => {
                    let hex = escape.value.get(1..3).ok_or_else(|| {
                        StraceParseError::new(escape.span, "unexpected end of string")
                    })?;
                    let byte = u8::from_str_radix(hex, 16).map_err(|e| {
                        StraceParseError::new(escape.span, "invalid hex escape in string")
                    })?;
                    (byte, 3)
                }
                b'0'..b'7' => {
                    let escaped_bytes = &escape.value.as_bytes()[0..];
                    let num_octal_bytes = escaped_bytes
                        .iter()
                        .take(3)
                        .take_while(|b| (b'0'..=b'7').contains(b))
                        .count();
                    let octal_bytes = &escaped_bytes[0..num_octal_bytes];
                    let octal = std::str::from_utf8(octal_bytes).unwrap();
                    let byte = u8::from_str_radix(octal, 8).map_err(|e| {
                        StraceParseError::new(escape.span, "invalid octal escape in string")
                    })?;
                    (byte, num_octal_bytes)
                }
                _ => {
                    return Err(StraceParseError::new(escape.span, "invalid string escape"));
                }
            };

            string.to_mut().push_byte(append);
            (_, rest) = escape.split_at(consumed);

            let literal_string_end = rest
                .map(|string| string.find(&['"', '\\']))
                .into_result()
                .map_err(|blame| StraceParseError::new(blame.span, "unexpected string end"))?;

            let literal_string;
            (literal_string, rest) = rest.split_at(literal_string_end.value);

            string
                .to_mut()
                .extend_from_slice(literal_string.value.as_bytes());
        }

        let rest = rest.strip_prefix("\"").map_err(|blame| {
            StraceParseError::new(blame.span, "expected closing quote for string")
        })?;

        if let Ok(rest) = rest.strip_prefix("...") {
            Ok((Value::TruncatedString(string), rest))
        } else {
            Ok((Value::String(string), rest))
        }
    } else if let Ok((ident, rest)) = parse_ident(input)
        && let Ok(mut rest) = rest.strip_prefix("(")
    {
        let mut fields = vec![];
        let mut needs_comma = false;
        loop {
            if let Ok(rest) = rest.strip_prefix(")") {
                break Ok((
                    Value::FunctionCall {
                        function: ident.value,
                        args: fields,
                    },
                    rest,
                ));
            }

            if rest.value.is_empty() {
                return Err(StraceParseError::new(
                    rest.span,
                    "unexpected end of function argument list",
                ));
            }

            if needs_comma {
                rest = rest.strip_prefix(", ").map_err(|blame| {
                    StraceParseError::new(
                        blame.span,
                        "expected ', ' or ')' after function argument",
                    )
                })?;
            }

            let next_field;
            (next_field, rest) = parse_field(rest.trim_start())?;
            needs_comma = true;

            fields.push(next_field);
        }
    } else if let Ok(mut rest) = input.strip_prefix("[") {
        let mut items = vec![];
        let mut is_first = true;
        let mut needs_comma = None;
        loop {
            if let Ok(rest) = rest.strip_prefix("]") {
                break Ok((Value::Array(items), rest));
            }

            if rest.value.is_empty() {
                return Err(StraceParseError::new(rest.span, "unexpected end of array"));
            }

            if is_first {
                is_first = false;
            } else if let Some(true) = needs_comma {
                rest = rest.strip_prefix(", ").map_err(|blame| {
                    StraceParseError::new(blame.span, "expected ', ' or ']' after array item")
                })?;
            } else if let Some(false) = needs_comma {
                rest = rest.strip_prefix(" ").map_err(|blame| {
                    StraceParseError::new(blame.span, "expected ' ' after bitset element")
                })?;
            } else if let Ok(after_comma) = rest.strip_prefix(", ") {
                needs_comma = Some(true);
                rest = after_comma;
            } else if let Ok(after_space) = rest.strip_prefix(" ") {
                needs_comma = Some(false);
                rest = after_space;
            } else {
                return Err(StraceParseError::new(
                    rest.span,
                    "expected ' ' or ', ' or ']' after first array item",
                ));
            }

            let next_item;
            (next_item, rest) = parse_value(rest)?;

            items.push(next_item);
        }
    } else if let Ok(mut rest) = input.strip_prefix("~[") {
        let mut items = vec![];
        let mut is_first = true;
        loop {
            if let Ok(rest) = rest.strip_prefix("]") {
                break Ok((Value::NotBitset(items), rest));
            }

            if rest.value.is_empty() {
                return Err(StraceParseError::new(rest.span, "unexpected end of bitset"));
            }

            if !is_first {
                rest = rest.strip_prefix(" ").map_err(|blame| {
                    StraceParseError::new(blame.span, "expected ' ' or ']' after bitset element")
                })?;
            }
            is_first = false;

            let next_item;
            (next_item, rest) = parse_value(rest)?;

            items.push(next_item);
        }
    } else if let Ok(mut rest) = input.trim_start().strip_prefix("{") {
        let mut fields = vec![];
        let mut is_first = true;
        loop {
            rest = rest.trim_start();

            if let Ok(rest) = rest.strip_prefix("}") {
                break Ok((Value::Struct(fields), rest));
            }

            if rest.value.is_empty() {
                return Err(StraceParseError::new(rest.span, "unexpected end of struct"));
            }

            if !is_first {
                rest = rest.strip_prefix(",").map_err(|blame| {
                    StraceParseError::new(blame.span, "expected ',' or '}' after struct field")
                })?;
            }
            is_first = false;

            let next_field;
            (next_field, rest) = parse_field(rest)?;

            fields.push(next_field);
        }
    } else if input.value.starts_with(|c| is_basic_expression_char(c)) {
        let end_basic_expr = input
            .value
            .find(|c| !is_basic_expression_char(c))
            .unwrap_or(input.value.len());
        let (basic_expr, rest) = input.split_at(end_basic_expr);

        Ok((Value::Expression(basic_expr.value), rest))
    } else {
        Err(StraceParseError::new(input.span, "unrecognized expression"))
    }
}

fn parse_field<'a>(input: Blame<&'a str>) -> Result<(Field<'a>, Blame<&'a str>), StraceParseError> {
    let name_and_rest = input.split_once("=").ok().and_then(|(name, rest)| {
        let name = name.trim().non_empty().ok()?;
        let rest = rest.trim_start().non_empty().ok()?;

        Some((name, rest)).filter(|(name, _)| is_ident(name.value))
    });
    if let Some((name, rest)) = name_and_rest {
        let (value, rest) = parse_value(rest)?;
        Ok((
            Field {
                name: Some(name.value),
                value,
            },
            rest,
        ))
    } else {
        let (value, rest) = parse_value(input)?;
        Ok((Field { name: None, value }, rest))
    }
}

fn parse_ident<'a>(
    input: Blame<&'a str>,
) -> Result<(Blame<&'a str>, Blame<&'a str>), Blame<&'a str>> {
    let ident_end_index = input
        .value
        .char_indices()
        .take_while(|(i, c)| {
            if *i == 0 {
                matches!(c, 'a'..='z' | 'A'..='Z' | '_')
            } else {
                matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
            }
        })
        .map(|(i, _)| i)
        .last()
        .ok_or(input)?;

    let (ident, rest) = input.split_at(ident_end_index + 1);
    Ok((ident, rest))
}

fn is_ident(value: &str) -> bool {
    let Ok((ident, rest)) = parse_ident(Blame::new_str(value)) else {
        return false;
    };

    rest.value.is_empty()
}

fn is_basic_expression_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '+' | '-' | '*' | '.' | '/' | '^' | '&' | '|')
}

// fn line_parser<'a>() -> impl chumsky::Parser<'a, &'a str, Line<'a>, ParserError<'a>> {
//     let pid = text::int(10)
//         .try_map(|pid: &str, span| pid.parse::<Pid>().map_err(|e| Rich::custom(span, e)));

//     let signed_duration = one_of("+-")
//         .or_not()
//         .then(text::int(10))
//         .to_slice()
//         .then(
//             just(".")
//                 .then(one_of('0'..='9').repeated().at_least(1))
//                 .to_slice()
//                 .or_not(),
//         )
//         .try_map(|(seconds, fraction): (&str, Option<&str>), span| {
//             let seconds = seconds.parse::<i64>().map_err(|e| Rich::custom(span, e))?;

//             let nanoseconds = if let Some(fraction) = fraction {
//                 let fraction = fraction.parse::<f64>().map_err(|e| Rich::custom(span, e))?;
//                 let nanoseconds = (fraction * 1_000_000_000.0).round() as i32;
//                 nanoseconds.clamp(0, 999_999_999)
//             } else {
//                 0
//             };

//             Ok(jiff::SignedDuration::new(seconds, nanoseconds))
//         });
//     let duration = signed_duration.clone().try_map(|duration, span| {
//         std::time::Duration::try_from(duration).map_err(|e| Rich::custom(span, e))
//     });
//     let timestamp = signed_duration.try_map(|duration, span| {
//         jiff::Timestamp::from_duration(duration).map_err(|e| Rich::custom(span, e))
//     });

//     let syscall_duration = duration.delimited_by(just("<"), just(">"));

//     // let syscall_result = one_of('a'..'z')
//     //     .or(one_of('A'..'Z'))
//     //     .or(one_of('0'..'9'))
//     //     .or(one_of("_+-?"))
//     //     .repeated()
//     //     .clone()
//     //     .map(Some)
//     //     .or(just("?").map(|_| None))
//     //     .padded()
//     //     .then(
//     //         any()
//     //             .and_is(syscall_duration.clone().then(end()).not())
//     //             .repeated()
//     //             .to_slice()
//     //             .map(String::from),
//     //     )
//     //     .map(|(value, message)| SyscallResult { value, message });

//     let syscall = group((
//         text::ident(),
//         any()
//             .repeated()
//             .to_slice()
//             .delimited_by(just("("), just(") = ")),
//         any().repeated().to_slice(),
//         just(" ").ignore_then(syscall_duration),
//     ))
//     .map(|(name, args, result, duration)| {
//         Event::Syscall(SyscallEvent {
//             name,
//             args,
//             result,
//             duration,
//         })
//     });
//     let exited = any()
//         .repeated()
//         .to_slice()
//         .delimited_by(just("+++ exited with "), just(" +++"))
//         .map(|code| Event::Exited { code });
//     let killed_by = any()
//         .repeated()
//         .to_slice()
//         .delimited_by(just("+++ killed by "), just(" +++"))
//         .map(|signal| Event::KilledBy { signal });
//     let signal = any()
//         .repeated()
//         .to_slice()
//         .delimited_by(just("--- "), just(" ---"))
//         .map(|signal| Event::Signal { signal });

//     let event = choice((syscall, exited, killed_by, signal));

//     group((
//         pid.then_ignore(just(" ")),
//         timestamp.then_ignore(just(" ")),
//         event.then_ignore(end()),
//     ))
//     .map(|(pid, timestamp, event)| Line {
//         pid,
//         timestamp,
//         event,
//     })
// }

#[derive(Debug, thiserror::Error)]
#[error("failed to parse strace line")]
pub struct StraceParseError {
    span: miette::LabeledSpan,
}

impl StraceParseError {
    fn new(span: blame_on::Span, message: impl Into<String>) -> Self {
        Self {
            span: miette::LabeledSpan::at(span, message),
        }
    }
}

impl miette::Diagnostic for StraceParseError {
    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Warning)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(self.span.clone())))
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::strace::{Field, Value};

    fn parse_value(s: &str) -> miette::Result<Value<'_>> {
        let (value, rest) = super::parse_value(s.into())
            .map_err(|err| miette::Report::new(err).with_source_code(s.to_string()))?;
        rest.empty().map_err(|blame| {
            miette::Report::new(crate::strace::parser::StraceParseError::new(
                blame.span,
                "parse_value did not consume whole input",
            ))
        })?;

        Ok(value)
    }

    fn string(s: impl AsRef<[u8]>) -> Value<'static> {
        Value::String(Cow::Owned(bstr::BString::new(s.as_ref().to_vec())))
    }

    fn truncated_string(s: impl AsRef<[u8]>) -> Value<'static> {
        Value::TruncatedString(Cow::Owned(bstr::BString::new(s.as_ref().to_vec())))
    }

    fn expr(expr: &'_ str) -> Value<'_> {
        Value::Expression(expr)
    }

    fn fn_call<'a>(function: &'a str, args: impl IntoIterator<Item = Field<'a>>) -> Value<'a> {
        Value::FunctionCall {
            function,
            args: args.into_iter().collect(),
        }
    }

    fn array<'a>(items: impl IntoIterator<Item = Value<'a>>) -> Value<'a> {
        Value::Array(items.into_iter().collect())
    }

    fn struct_value<'a>(fields: impl IntoIterator<Item = Field<'a>>) -> Value<'a> {
        Value::Struct(fields.into_iter().collect())
    }

    fn not_bitset<'a>(items: impl IntoIterator<Item = Value<'a>>) -> Value<'a> {
        Value::NotBitset(items.into_iter().collect())
    }

    fn unnamed(value: Value) -> Field {
        Field { name: None, value }
    }

    fn named<'a>(name: &'a str, value: Value<'a>) -> Field<'a> {
        Field {
            name: Some(name),
            value,
        }
    }

    #[test]
    fn test_parse_string() {
        assert_eq!(parse_value(r#""""#).unwrap(), string(""));
        assert_eq!(parse_value(r#""foo""#).unwrap(), string("foo"));
        assert_eq!(
            parse_value(r#""foo\"bar\"""#).unwrap(),
            string(r#"foo"bar""#)
        );
        assert_eq!(parse_value(r#""foo\nbar""#).unwrap(), string("foo\nbar"));
        assert_eq!(
            parse_value(r#""foo 🦀 bar""#).unwrap(),
            string("foo 🦀 bar")
        );
        assert_eq!(
            parse_value(r#""foo \xFf bar""#).unwrap(),
            string(b"foo \xff bar")
        );
        assert_eq!(
            parse_value(r#""foo \0 bar""#).unwrap(),
            string(b"foo \x00 bar")
        );
        assert_eq!(
            parse_value(r#""foo \10 bar""#).unwrap(),
            string(b"foo \x08 bar")
        );
        assert_eq!(
            parse_value(r#""foo \177 bar""#).unwrap(),
            string(b"foo \x7F bar")
        );
        assert_eq!(
            parse_value(r#""foo \178 bar""#).unwrap(),
            string(b"foo \x0F8 bar")
        );
        assert_eq!(parse_value(r#""foo \377""#).unwrap(), string(b"foo \xFF"));
        assert_eq!(parse_value(r#""foo \37""#).unwrap(), string(b"foo \x1F"));
        assert_eq!(parse_value(r#""foo \3""#).unwrap(), string(b"foo \x03"));
    }

    #[test]
    fn test_parse_truncated_string() {
        assert_eq!(parse_value(r#"""..."#).unwrap(), truncated_string(""));
        assert_eq!(parse_value(r#""foo"..."#).unwrap(), truncated_string("foo"));
        assert_eq!(
            parse_value(r#""foo\"bar\""..."#).unwrap(),
            truncated_string(r#"foo"bar""#)
        );
        assert_eq!(
            parse_value(r#""foo\nbar"..."#).unwrap(),
            truncated_string("foo\nbar")
        );
        assert_eq!(
            parse_value(r#""foo 🦀 bar"..."#).unwrap(),
            truncated_string("foo 🦀 bar")
        );
        assert_eq!(
            parse_value(r#""foo \xFf bar"..."#).unwrap(),
            truncated_string(b"foo \xff bar")
        );
        assert_eq!(
            parse_value(r#""foo \0 bar"..."#).unwrap(),
            truncated_string(b"foo \x00 bar")
        );
        assert_eq!(
            parse_value(r#""foo \10 bar"..."#).unwrap(),
            truncated_string(b"foo \x08 bar")
        );
        assert_eq!(
            parse_value(r#""foo \177 bar"..."#).unwrap(),
            truncated_string(b"foo \x7F bar")
        );
        assert_eq!(
            parse_value(r#""foo \178 bar"..."#).unwrap(),
            truncated_string(b"foo \x0F8 bar")
        );
        assert_eq!(
            parse_value(r#""foo \377"..."#).unwrap(),
            truncated_string(b"foo \xFF")
        );
        assert_eq!(
            parse_value(r#""foo \37"..."#).unwrap(),
            truncated_string(b"foo \x1F")
        );
        assert_eq!(
            parse_value(r#""foo \3"..."#).unwrap(),
            truncated_string(b"foo \x03")
        );
    }

    #[test]
    fn test_parse_basic_expr() {
        assert_eq!(parse_value("500").unwrap(), expr("500"));
        assert_eq!(parse_value("+0.5").unwrap(), expr("+0.5"));
        assert_eq!(parse_value("0x5*02/4").unwrap(), expr("0x5*02/4"));
        assert_eq!(
            parse_value("BLAH_BLAH_BLAH5").unwrap(),
            expr("BLAH_BLAH_BLAH5")
        );
    }

    #[test]
    fn test_parse_function_call() {
        assert_eq!(parse_value("foo()").unwrap(), fn_call("foo", []));
        assert_eq!(
            parse_value("foo(1)").unwrap(),
            fn_call("foo", [unnamed(expr("1"))])
        );
        assert_eq!(
            parse_value("foo(1, 2)").unwrap(),
            fn_call("foo", [unnamed(expr("1")), unnamed(expr("2"))])
        );
        assert_eq!(
            parse_value("foo(1, 2, 3)").unwrap(),
            fn_call(
                "foo",
                [unnamed(expr("1")), unnamed(expr("2")), unnamed(expr("3"))]
            )
        );
        assert_eq!(
            parse_value("foo(param1 = 1, param2 = 2)").unwrap(),
            fn_call(
                "foo",
                [named("param1", expr("1")), named("param2", expr("2"))]
            )
        );
        assert_eq!(
            parse_value("foo(fizz(), buzz = buzz(a = 1, b = 2), bar(baz, qux = qux()))").unwrap(),
            fn_call(
                "foo",
                [
                    unnamed(fn_call("fizz", [])),
                    named(
                        "buzz",
                        fn_call("buzz", [named("a", expr("1")), named("b", expr("2"))])
                    ),
                    unnamed(fn_call(
                        "bar",
                        [unnamed(expr("baz")), named("qux", fn_call("qux", []))]
                    ))
                ]
            )
        );
    }

    #[test]
    fn test_parse_array() {
        assert_eq!(parse_value("[]").unwrap(), array([]));
        assert_eq!(parse_value("[1]").unwrap(), array([expr("1")]));
        assert_eq!(
            parse_value("[1, 2]").unwrap(),
            array([expr("1"), expr("2")])
        );
        assert_eq!(
            parse_value("[1, 2, BUCKLE_MY_SHOE]").unwrap(),
            array([expr("1"), expr("2"), expr("BUCKLE_MY_SHOE")])
        );
        assert_eq!(
            parse_value("[1, 2, [a, b, c], [d e f]]").unwrap(),
            array([
                expr("1"),
                expr("2"),
                array([expr("a"), expr("b"), expr("c")]),
                array([expr("d"), expr("e"), expr("f")])
            ])
        );
    }

    #[test]
    fn test_parse_bitset_as_array() {
        assert_eq!(parse_value("[]").unwrap(), array([]));
        assert_eq!(parse_value("[1]").unwrap(), array([expr("1")]));
        assert_eq!(parse_value("[1 2]").unwrap(), array([expr("1"), expr("2")]));
        assert_eq!(
            parse_value("[1 2 BUCKLE_MY_SHOE]").unwrap(),
            array([expr("1"), expr("2"), expr("BUCKLE_MY_SHOE")])
        );
        assert_eq!(
            parse_value("[1 2 [a b c] [d, e, f]]").unwrap(),
            array([
                expr("1"),
                expr("2"),
                array([expr("a"), expr("b"), expr("c")]),
                array([expr("d"), expr("e"), expr("f")])
            ])
        );
    }

    #[test]
    fn test_parse_not_bitset() {
        assert_eq!(parse_value("~[]").unwrap(), not_bitset([]));
        assert_eq!(parse_value("~[1]").unwrap(), not_bitset([expr("1")]));
        assert_eq!(
            parse_value("~[1 2]").unwrap(),
            not_bitset([expr("1"), expr("2")])
        );
        assert_eq!(
            parse_value("~[1 2 BUCKLE_MY_SHOE]").unwrap(),
            not_bitset([expr("1"), expr("2"), expr("BUCKLE_MY_SHOE")])
        );
        assert_eq!(
            parse_value("~[1 2 3*4*5]").unwrap(),
            not_bitset([expr("1"), expr("2"), expr("3*4*5")])
        );
    }

    #[test]
    fn test_parse_struct() {
        assert_eq!(parse_value("{}").unwrap(), struct_value([]));
        assert_eq!(
            parse_value("{1}").unwrap(),
            struct_value([unnamed(expr("1"))])
        );
        assert_eq!(
            parse_value("{ 1 }").unwrap(),
            struct_value([unnamed(expr("1"))])
        );
        assert_eq!(
            parse_value("{ a = 1 }").unwrap(),
            struct_value([named("a", expr("1"))])
        );
        assert_eq!(
            parse_value("{ a = 1, b = 2}").unwrap(),
            struct_value([named("a", expr("1")), named("b", expr("2"))])
        );
        assert_eq!(
            parse_value("{ a = 1, b = 2, { 3 }, {_4 = 4 }, inner = {AAAA}}").unwrap(),
            struct_value([
                named("a", expr("1")),
                named("b", expr("2")),
                unnamed(struct_value([unnamed(expr("3"))])),
                unnamed(struct_value([named("_4", expr("4"))])),
                named("inner", struct_value([unnamed(expr("AAAA"))]))
            ])
        );
    }
}
