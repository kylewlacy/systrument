use std::borrow::Cow;

use blame_on::Blame;
use bstr::ByteVec as _;

use crate::{
    Pid,
    strace::{BinaryOperator, ExitedEvent},
};

use super::{Event, Field, Fields, Line, SyscallEvent, Value};

pub fn parse_line<'a>(line: &'a str) -> Result<Line<'a>, StraceParseError> {
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

        if let Ok(code_string) = event.strip_prefix("exited with ") {
            Event::Exited(ExitedEvent { code_string })
        } else if let Ok(signal_string) = event.strip_prefix("killed by ") {
            Event::KilledBy { signal_string }
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
        let (input, result_string) = input
            .rsplit_once(" = ")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse syscall result"))?;
        let args_string = input
            .trim_ascii_end()
            .strip_suffix(")")
            .map_err(|blame| StraceParseError::new(blame.span, "failed to parse syscall args"))?;

        Event::Syscall(SyscallEvent {
            name: syscall_name.value,
            args_string,
            result_string: result_string.trim(),
            duration: duration.value,
        })
    };

    Ok(Line {
        pid: pid.value,
        timestamp: timestamp.value,
        event,
    })
}

pub(crate) fn parse_args<'a>(mut input: Blame<&'a str>) -> Result<Fields<'a>, StraceParseError> {
    let mut args = vec![];
    let mut needs_comma = false;

    loop {
        input = input.trim_start();

        if let Ok(_) = input.empty() {
            break;
        }

        if needs_comma {
            input = input
                .strip_prefix(",")
                .map_err(|blame| StraceParseError::new(blame.span, "expected ',' or end of args"))?
                .trim_start();
        }

        needs_comma = true;

        let field;
        (field, input) = parse_field(input)?;
        args.push(field);
    }

    Ok(Fields { values: args })
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

fn parse_value_basic<'a>(
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
            let byte;
            (byte, rest) = parse_string_escape_sequence(escape)?;

            string.to_mut().push_byte(byte);

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
        if let Ok(rest) = rest.trim_start().strip_prefix("[")
            && let Ok((first_index, rest)) = parse_value(rest)
            && let Ok(mut rest) = rest
                .trim_start()
                .strip_prefix("]")
                .and_then(|rest| rest.trim_start().strip_prefix("="))
        {
            // Sparse array (e.g. `[ [100] = some_value ]`)

            let first_item;
            (first_item, rest) = parse_value(rest.trim_start())?;

            let mut items = vec![(first_index, first_item)];
            loop {
                rest = rest.trim_start();
                if let Ok(rest) = rest.strip_prefix("]") {
                    break Ok((Value::SparseArray(items), rest));
                };

                if rest.value.is_empty() {
                    return Err(StraceParseError::new(
                        rest.span,
                        "unexpected end of sparse array",
                    ));
                }

                rest = rest.strip_prefix(", [").map_err(|blame| {
                    StraceParseError::new(
                        blame.span,
                        "expected ', [' or ']' after sparse array item",
                    )
                })?;

                let index;
                (index, rest) = parse_value(rest.trim_start())?;

                rest = rest
                    .trim_start()
                    .strip_prefix("]")
                    .and_then(|rest| rest.trim_start().strip_prefix("="))
                    .map(|rest| rest.trim_start())
                    .map_err(|blame| {
                        StraceParseError::new(
                            blame.span,
                            "expected '] = ' after sparse array index",
                        )
                    })?;

                let item;
                (item, rest) = parse_value(rest)?;

                items.push((index, item));
            }
        } else {
            // Array (`[1, 2, 3]`) or bitset (`[1 2 3]`)

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
                rest = rest
                    .strip_prefix(",")
                    .map_err(|blame| {
                        StraceParseError::new(blame.span, "expected ',' or '}' after struct field")
                    })?
                    .trim_start();
            }
            is_first = false;

            let next_field;
            (next_field, rest) = parse_field(rest)?;

            fields.push(next_field);
        }
    } else if let Ok(rest) = input.strip_prefix("...") {
        Ok((Value::Truncated, rest))
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

pub(crate) fn parse_value<'a>(
    input: Blame<&'a str>,
) -> Result<(Value<'a>, Blame<&'a str>), StraceParseError> {
    let (mut value, mut rest) = parse_value_basic(input)?;
    if let Ok(after_annotation_start) = rest.strip_prefix("<") {
        rest = after_annotation_start;

        let mut depth: u32 = 0;
        let mut annotation = Cow::Borrowed(bstr::BStr::new(&[]));

        loop {
            let c;
            (c, rest) = split_char(rest).map_err(|blame| {
                StraceParseError::new(blame.span, "unterminated annotation, expected '>'")
            })?;

            match c {
                '>' if annotation.last() == Some(&b'-') => {
                    // Treat `->` as part of the annotation, even if we're
                    // looking for `>` as the closing delimiter

                    // Append the character by either slicing more borrowed data
                    // from the original string or by appending the char
                    match &mut annotation {
                        Cow::Borrowed(_) => {
                            annotation = Cow::Borrowed(bstr::BStr::new(
                                &after_annotation_start.value[0..(annotation.len() + c.len_utf8())],
                            ))
                        }
                        Cow::Owned(annotation) => {
                            annotation.push_char(c);
                        }
                    }
                }
                '>' => {
                    if depth == 0 {
                        // Reached the final closing delimiter, so we're done
                        // parsing the annotation
                        break;
                    };

                    depth -= 1;

                    // Append the character by either slicing more borrowed data
                    // from the original string or by appending the char
                    match &mut annotation {
                        Cow::Borrowed(_) => {
                            annotation = Cow::Borrowed(bstr::BStr::new(
                                &after_annotation_start.value[0..(annotation.len() + c.len_utf8())],
                            ))
                        }
                        Cow::Owned(annotation) => {
                            annotation.push_char(c);
                        }
                    }
                }
                '\\' => {
                    // String escape sequence. Parse then append as a byte
                    // to the annotation
                    let byte;
                    (byte, rest) = parse_string_escape_sequence(rest)?;
                    annotation.to_mut().push_byte(byte);
                }
                c => {
                    // Any other character should be appended like normal

                    // Append the character by either slicing more borrowed data
                    // from the original string or by appending the char
                    match &mut annotation {
                        Cow::Borrowed(_) => {
                            annotation = Cow::Borrowed(bstr::BStr::new(
                                &after_annotation_start.value[0..(annotation.len() + c.len_utf8())],
                            ))
                        }
                        Cow::Owned(annotation) => {
                            annotation.push_char(c);
                        }
                    }

                    // If the character is an unescaped opening delimiter,
                    // increase the depth so we keep the depth balanced
                    if c == '<' {
                        depth += 1;
                    }
                }
            }
        }

        if let Ok(after_deleted) = rest.strip_prefix("(deleted)") {
            rest = after_deleted;
            value = Value::Annotated {
                value: Box::new(value),
                annotation,
                deleted: true,
            };
        } else {
            value = Value::Annotated {
                value: Box::new(value),
                annotation,
                deleted: false,
            };
        }
    }

    let mut operators_and_operands = vec![];
    loop {
        let Ok((op, after_op)) = parse_binary_op(rest) else {
            break;
        };
        rest = after_op;

        let next_value;
        (next_value, rest) = parse_value_basic(rest)?;

        operators_and_operands.push((op, next_value));
    }

    if !operators_and_operands.is_empty() {
        value = Value::BinaryOperations {
            first: Box::new(value),
            operators_and_operands,
        };
    }

    if let Ok(after_alternative) = rest.strip_prefix(" or ") {
        rest = after_alternative.trim_start();

        let right_value;
        (right_value, rest) = parse_value(rest)?;
        value = Value::Alternative {
            left: Box::new(value),
            right: Box::new(right_value),
        };
    }

    if let Ok(after_comment_start) = rest.trim_start().strip_prefix("/*") {
        rest = after_comment_start;

        let comment;
        (comment, rest) = rest.split_once("*/").map_err(|blame| {
            StraceParseError::new(blame.span, "unterminated comment, expected '*/'")
        })?;

        value = Value::Commented {
            value: Box::new(value),
            comment: comment.value.trim(),
        };
    }

    if let Ok(after_changed) = rest.trim_start().strip_prefix("=>") {
        rest = after_changed.trim_start();

        let to_value;
        (to_value, rest) = parse_value(rest)?;
        value = Value::Changed {
            from: Box::new(value),
            to: Box::new(to_value),
        };
    }

    Ok((value, rest))
}

pub(crate) fn parse_whole_value(s: Blame<&str>) -> Result<Value<'_>, StraceParseError> {
    let (value, rest) = parse_value(s.into())?;
    rest.empty().map_err(|blame| {
        crate::strace::parser::StraceParseError::new(
            blame.span,
            "expected end of input after value",
        )
    })?;

    Ok(value)
}

fn split_char<'a>(input: Blame<&'a str>) -> Result<(char, Blame<&'a str>), Blame<&'a str>> {
    let c = input.value.chars().next().ok_or(input)?;
    let (_, rest) = input.split_at(c.len_utf8());
    Ok((c, rest))
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

fn parse_string_escape_sequence<'a>(
    escape: Blame<&'a str>,
) -> Result<(u8, Blame<&'a str>), StraceParseError> {
    let escape_byte = escape
        .as_bytes()
        .value
        .get(0)
        .copied()
        .ok_or_else(|| StraceParseError::new(escape.span, "unexpected end of string"))?;
    let (byte, consumed) = match escape_byte {
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
            let hex = escape
                .value
                .get(1..3)
                .ok_or_else(|| StraceParseError::new(escape.span, "unexpected end of string"))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| StraceParseError::new(escape.span, "invalid hex escape in string"))?;
            (byte, 3)
        }
        b'0'..=b'7' => {
            let escaped_bytes = &escape.value.as_bytes()[0..];
            let num_octal_bytes = escaped_bytes
                .iter()
                .take(3)
                .take_while(|b| (b'0'..=b'7').contains(b))
                .count();
            let octal_bytes = &escaped_bytes[0..num_octal_bytes];
            let octal = std::str::from_utf8(octal_bytes).unwrap();
            let byte = u8::from_str_radix(octal, 8).map_err(|_| {
                StraceParseError::new(escape.span, "invalid octal escape in string")
            })?;
            (byte, num_octal_bytes)
        }
        _ => {
            return Err(StraceParseError::new(escape.span, "invalid string escape"));
        }
    };

    let (_, rest) = escape.split_at(consumed);
    Ok((byte, rest))
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
    let Ok((_, rest)) = parse_ident(Blame::new_str(value)) else {
        return false;
    };

    rest.value.is_empty()
}

fn is_basic_expression_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '+' | '-' | '*' | '.' | '/' | '^' | '&' | '|')
}

fn parse_binary_op<'a>(
    input: Blame<&'a str>,
) -> Result<(BinaryOperator, Blame<&'a str>), Blame<&'a str>> {
    if let Ok(rest) = input.trim_start().strip_prefix("&&") {
        Ok((BinaryOperator::And, rest.trim_start()))
    } else if let Ok(rest) = input.trim_start().strip_prefix("||") {
        Ok((BinaryOperator::Or, rest.trim_start()))
    } else if let Ok(rest) = input.trim_start().strip_prefix("==") {
        Ok((BinaryOperator::Equal, rest.trim_start()))
    } else if let Ok(rest) = input.trim_start().strip_prefix("!=") {
        Ok((BinaryOperator::NotEqual, rest.trim_start()))
    } else {
        Err(input)
    }
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

    use crate::strace::{BinaryOperator, Field, Value};

    fn parse_value(s: &str) -> miette::Result<Value<'_>> {
        super::parse_whole_value(s.into())
            .map_err(|err| miette::Report::new(err).with_source_code(s.to_string()))
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

    fn binary_ops<'a>(
        first: Value<'a>,
        rest: impl IntoIterator<Item = (BinaryOperator, Value<'a>)>,
    ) -> Value<'a> {
        Value::BinaryOperations {
            first: Box::new(first),
            operators_and_operands: rest.into_iter().collect(),
        }
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

    fn sparse_array<'a>(items: impl IntoIterator<Item = (Value<'a>, Value<'a>)>) -> Value<'a> {
        Value::SparseArray(items.into_iter().collect())
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

    fn annotated(value: Value<'_>, annotation: impl AsRef<[u8]>) -> Value<'_> {
        Value::Annotated {
            value: Box::new(value),
            annotation: Cow::Owned(bstr::BString::new(annotation.as_ref().to_vec())),
            deleted: false,
        }
    }

    fn annotated_deleted(value: Value<'_>, annotation: impl AsRef<[u8]>) -> Value<'_> {
        Value::Annotated {
            value: Box::new(value),
            annotation: Cow::Owned(bstr::BString::new(annotation.as_ref().to_vec())),
            deleted: true,
        }
    }

    fn commented<'a>(value: Value<'a>, comment: &'a str) -> Value<'a> {
        Value::Commented {
            value: Box::new(value),
            comment,
        }
    }

    fn changed<'a>(from: Value<'a>, to: Value<'a>) -> Value<'a> {
        Value::Changed {
            from: Box::new(from),
            to: Box::new(to),
        }
    }

    fn alternative<'a>(left: Value<'a>, right: Value<'a>) -> Value<'a> {
        Value::Alternative {
            left: Box::new(left),
            right: Box::new(right),
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
    fn test_parse_expr_with_operators() {
        assert_eq!(
            parse_value("[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]").unwrap(),
            array([struct_value([unnamed(binary_ops(
                fn_call("WIFEXITED", [unnamed(expr("s"))]),
                [
                    (
                        BinaryOperator::And,
                        fn_call("WEXITSTATUS", [unnamed(expr("s"))])
                    ),
                    (BinaryOperator::Equal, expr("0"))
                ]
            ))])]),
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
    fn test_parse_function_call_truncated() {
        assert_eq!(
            parse_value("foo(...)").unwrap(),
            fn_call("foo", [unnamed(Value::Truncated)])
        );
        assert_eq!(
            parse_value("foo(1, 2, 3, ...)").unwrap(),
            fn_call(
                "foo",
                [
                    unnamed(expr("1")),
                    unnamed(expr("2")),
                    unnamed(expr("3")),
                    unnamed(Value::Truncated)
                ]
            )
        );
        assert_eq!(
            parse_value("foo(param1 = 1, param2 = 2, ...)").unwrap(),
            fn_call(
                "foo",
                [
                    named("param1", expr("1")),
                    named("param2", expr("2")),
                    unnamed(Value::Truncated)
                ]
            )
        );
        assert_eq!(
            parse_value(
                "foo(fizz(...), buzz = buzz(a = 1, b = 2, ...), bar(baz, qux = qux(...), ...), ...)"
            )
            .unwrap(),
            fn_call(
                "foo",
                [
                    unnamed(fn_call("fizz", [unnamed(Value::Truncated)])),
                    named(
                        "buzz",
                        fn_call(
                            "buzz",
                            [
                                named("a", expr("1")),
                                named("b", expr("2")),
                                unnamed(Value::Truncated)
                            ]
                        )
                    ),
                    unnamed(fn_call(
                        "bar",
                        [
                            unnamed(expr("baz")),
                            named("qux", fn_call("qux", [unnamed(Value::Truncated)])),
                            unnamed(Value::Truncated)
                        ]
                    )),
                    unnamed(Value::Truncated)
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
    fn test_parse_array_truncated() {
        assert_eq!(parse_value("[...]").unwrap(), array([Value::Truncated]));
        assert_eq!(parse_value("[1]").unwrap(), array([expr("1")]));
        assert_eq!(
            parse_value("[1, 2, ...]").unwrap(),
            array([expr("1"), expr("2"), Value::Truncated])
        );
        assert_eq!(
            parse_value("[1, 2, BUCKLE_MY_SHOE]").unwrap(),
            array([expr("1"), expr("2"), expr("BUCKLE_MY_SHOE")])
        );
        assert_eq!(
            parse_value("[1, 2, [a, b, c, ...], [d e f], ...]").unwrap(),
            array([
                expr("1"),
                expr("2"),
                array([expr("a"), expr("b"), expr("c"), Value::Truncated]),
                array([expr("d"), expr("e"), expr("f")]),
                Value::Truncated
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

    #[test]
    fn test_parse_struct_truncated() {
        assert_eq!(
            parse_value("{ifa_family=AF_UNSPEC, ...}").unwrap(),
            struct_value([
                named("ifa_family", expr("AF_UNSPEC")),
                unnamed(Value::Truncated)
            ])
        )
    }

    #[test]
    fn test_parse_sparse_array() {
        assert_eq!(
            parse_value("[ [1] = 100 ]").unwrap(),
            sparse_array([(expr("1"), expr("100"))])
        );
        assert_eq!(
            parse_value("[ [1] = 100, [ 2 ] = 200 ]").unwrap(),
            sparse_array([(expr("1"), expr("100")), (expr("2"), expr("200"))])
        );
        assert_eq!(
            parse_value("[ [FIZZ] = 100, [FIZZ|BUZZ] = [[1] = [1]] ]").unwrap(),
            sparse_array([
                (expr("FIZZ"), expr("100")),
                (
                    expr("FIZZ|BUZZ"),
                    sparse_array([(expr("1"), array([expr("1")]))])
                )
            ])
        );
        assert_eq!(
            parse_value("{c_iflag=ICRNL|IXON|IUTF8, c_oflag=NL0|CR0|TAB0|BS0|VT0|FF0|OPOST|ONLCR, c_cflag=B38400|CS8|CREAD, c_lflag=ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN|ECHOCTL|ECHOKE, c_line=N_TTY, c_cc=[[VINTR]=0x3, [VQUIT]=0x1c, [VERASE]=0x7f, [VKILL]=0x15, [VEOF]=0x4, [VTIME]=0, [VMIN]=0x1, [VSWTC]=0, [VSTART]=0x11, [VSTOP]=0x13, [VSUSP]=0x1a, [VEOL]=0, [VREPRINT]=0x12, [VDISCARD]=0xf, [VWERASE]=0x17, [VLNEXT]=0x16, [VEOL2]=0, [17]=0, [18]=0]}").unwrap(),
            struct_value([
                named("c_iflag", expr("ICRNL|IXON|IUTF8")),
                named("c_oflag", expr("NL0|CR0|TAB0|BS0|VT0|FF0|OPOST|ONLCR")),
                named("c_cflag", expr("B38400|CS8|CREAD")),
                named("c_lflag", expr("ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN|ECHOCTL|ECHOKE")),
                named("c_line", expr("N_TTY")),
                named(
                    "c_cc",
                    sparse_array([
                        (expr("VINTR"), expr("0x3")),
                        (expr("VQUIT"), expr("0x1c")),
                        (expr("VERASE"), expr("0x7f")),
                        (expr("VKILL"), expr("0x15")),
                        (expr("VEOF"), expr("0x4")),
                        (expr("VTIME"), expr("0")),
                        (expr("VMIN"), expr("0x1")),
                        (expr("VSWTC"), expr("0")),
                        (expr("VSTART"), expr("0x11")),
                        (expr("VSTOP"), expr("0x13")),
                        (expr("VSUSP"), expr("0x1a")),
                        (expr("VEOL"), expr("0")),
                        (expr("VREPRINT"), expr("0x12")),
                        (expr("VDISCARD"), expr("0xf")),
                        (expr("VWERASE"), expr("0x17")),
                        (expr("VLNEXT"), expr("0x16")),
                        (expr("VEOL2"), expr("0")),
                        (expr("17"), expr("0")),
                        (expr("18"), expr("0")),
                    ])
                )
            ])
        );
    }

    #[test]
    fn test_parse_annotated() {
        assert_eq!(
            parse_value("6</foo/bar/baz>").unwrap(),
            annotated(expr("6"), "/foo/bar/baz")
        );
        assert_eq!(
            parse_value("AT_FDCWD<hello>").unwrap(),
            annotated(expr("AT_FDCWD"), "hello")
        );
        assert_eq!(
            parse_value("openat(AT_FDCWD</home/user>)").unwrap(),
            fn_call(
                "openat",
                [unnamed(annotated(expr("AT_FDCWD"), "/home/user"))]
            )
        );
        assert_eq!(
            parse_value("16<NETLINK:[ROUTE:2386219]>").unwrap(),
            annotated(expr("16"), "NETLINK:[ROUTE:2386219]")
        );
        assert_eq!(
            parse_value("16<UNIX-STREAM:[167063691->167059833]>").unwrap(),
            annotated(expr("16"), "UNIX-STREAM:[167063691->167059833]")
        );
        assert_eq!(
            parse_value(
                "16<UDPv6:[[2001:db8:1000:1000:1000:100:100:1000]:41629->[2001:db8:1000::1000:1000]:0]>"
            ).unwrap(),
            annotated(
                expr("16"),
                "UDPv6:[[2001:db8:1000:1000:1000:100:100:1000]:41629->[2001:db8:1000::1000:1000]:0]"
            )
        );
        assert_eq!(
            parse_value(r#"3</var/home/kyle/Development/scratch/-\"\76\74][\"\\a.txt>"#).unwrap(),
            annotated(
                expr("3"),
                r#"/var/home/kyle/Development/scratch/-"><]["\a.txt"#
            )
        );
        assert_eq!(
            parse_value("6</foo/bar/baz>(deleted)").unwrap(),
            annotated_deleted(expr("6"), "/foo/bar/baz")
        );
    }

    #[test]
    fn test_parse_commented() {
        assert_eq!(
            parse_value("100 /* hello! */").unwrap(),
            commented(expr("100"), "hello!")
        );
        assert_eq!(
            parse_value("{st_atime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */}").unwrap(),
            struct_value([named(
                "st_atime",
                commented(expr("1755889791"), "2025-08-22T12:09:51.972352920-0700")
            )])
        );
    }

    #[test]
    fn test_parse_changed() {
        assert_eq!(
            parse_value("FOO => BAR").unwrap(),
            changed(expr("FOO"), expr("BAR")),
        );
        assert_eq!(
            parse_value("{a=foo /* abc */ => bar /* def */}").unwrap(),
            struct_value([named(
                "a",
                changed(commented(expr("foo"), "abc"), commented(expr("bar"), "def"))
            )]),
        );
    }

    #[test]
    fn test_parse_alternative() {
        assert_eq!(
            parse_value("FOO or BAR").unwrap(),
            alternative(expr("FOO"), expr("BAR")),
        );
        assert_eq!(
            parse_value("FOO or BAR or BAZ").unwrap(),
            alternative(expr("FOO"), alternative(expr("BAR"), expr("BAZ"))),
        );
    }
}
