use chumsky::prelude::*;

use crate::{Pid, strace::SyscallEvent};

use super::{Event, Fields, Line, SyscallResult, Value};

pub fn parse_line<'line, 'loc>(
    line: &'line str,
    location: &super::LineSourceLocation,
) -> Result<Line<'line>, ParseLineError> {
    line_parser()
        .parse(line)
        .into_result()
        .map_err(|errors| ParseLineError::from_parser_errors(line, location, errors))
}

fn line_parser<'a>() -> impl chumsky::Parser<'a, &'a str, Line<'a>, ParserError<'a>> {
    let pid = text::int(10)
        .try_map(|pid: &str, span| pid.parse::<Pid>().map_err(|e| Rich::custom(span, e)));

    let signed_duration = one_of("+-")
        .or_not()
        .then(text::int(10))
        .to_slice()
        .then(
            just(".")
                .then(one_of('0'..='9').repeated().at_least(1))
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
    let duration = signed_duration.clone().try_map(|duration, span| {
        std::time::Duration::try_from(duration).map_err(|e| Rich::custom(span, e))
    });
    let timestamp = signed_duration.try_map(|duration, span| {
        jiff::Timestamp::from_duration(duration).map_err(|e| Rich::custom(span, e))
    });

    let syscall_duration = duration.delimited_by(just("<"), just(">"));

    // let syscall_result = one_of('a'..'z')
    //     .or(one_of('A'..'Z'))
    //     .or(one_of('0'..'9'))
    //     .or(one_of("_+-?"))
    //     .repeated()
    //     .clone()
    //     .map(Some)
    //     .or(just("?").map(|_| None))
    //     .padded()
    //     .then(
    //         any()
    //             .and_is(syscall_duration.clone().then(end()).not())
    //             .repeated()
    //             .to_slice()
    //             .map(String::from),
    //     )
    //     .map(|(value, message)| SyscallResult { value, message });

    let syscall = group((
        text::ident(),
        any()
            .repeated()
            .to_slice()
            .delimited_by(just("("), just(") = ")),
        any().repeated().to_slice(),
        just(" ").ignore_then(syscall_duration),
    ))
    .map(|(name, args, result, duration)| {
        Event::Syscall(SyscallEvent {
            name,
            args,
            result,
            duration,
        })
    });
    let exited = any()
        .repeated()
        .to_slice()
        .delimited_by(just("+++ exited with "), just(" +++"))
        .map(|code| Event::Exited { code });
    let killed_by = any()
        .repeated()
        .to_slice()
        .delimited_by(just("+++ killed by "), just(" +++"))
        .map(|signal| Event::KilledBy { signal });
    let signal = any()
        .repeated()
        .to_slice()
        .delimited_by(just("--- "), just(" ---"))
        .map(|signal| Event::Signal { signal });

    let event = choice((syscall, exited, killed_by, signal));

    group((
        pid.then_ignore(just(" ")),
        timestamp.then_ignore(just(" ")),
        event.then_ignore(end()),
    ))
    .map(|(pid, timestamp, event)| Line {
        pid,
        timestamp,
        event,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("failed to parse strace line")]
pub struct ParseLineError {
    src: StraceSource,
    spans: Vec<miette::LabeledSpan>,
}

impl ParseLineError {
    fn from_parser_errors(
        source: &str,
        location: &super::LineSourceLocation,
        errors: Vec<Rich<'_, char>>,
    ) -> Self {
        let spans = errors
            .into_iter()
            .map(|error| {
                let span = error.span();
                miette::LabeledSpan::at(span.into_range(), error.into_reason().to_string())
            })
            .collect();

        Self {
            src: StraceSource {
                source: source.to_string(),
                filename: location.filename.to_string(),
                line_index: location.line_index,
            },
            spans,
        }
    }
}

impl miette::Diagnostic for ParseLineError {
    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Warning)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.src)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        Some(Box::new(self.spans.iter().cloned()))
    }
}

#[derive(Debug)]
struct StraceSource {
    filename: String,
    line_index: usize,
    source: String,
}

impl miette::SourceCode for StraceSource {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        let contents = self
            .source
            .read_span(span, context_lines_before, context_lines_after)?;
        let contents = miette::MietteSpanContents::new_named(
            self.filename.to_string(),
            contents.data(),
            *contents.span(),
            self.line_index + contents.line(),
            contents.column(),
            contents.line_count(),
        );
        Ok(Box::new(contents))
    }
}

type ParserError<'a> = extra::Err<Rich<'a, char>>;
