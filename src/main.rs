use std::io::BufRead as _;

use chumsky::Parser as _;

mod strace;

fn main() {
    let stdin = std::io::stdin().lock();
    for (n, line) in stdin.lines().enumerate() {
        let line = line.unwrap();

        let (_strace, errors) = strace::parser::line_parser()
            .parse(&line)
            .into_output_errors();

        let filename = "<stdin>";

        for e in &errors {
            ariadne::Report::build(
                ariadne::ReportKind::Error,
                (filename, e.span().into_range()),
            )
            .with_config(ariadne::Config::new().with_index_type(ariadne::IndexType::Byte))
            .with_message(e.to_string())
            .with_label(
                ariadne::Label::new((filename, e.span().into_range()))
                    .with_message(e.reason().to_string())
                    .with_color(ariadne::Color::Red),
            )
            .finish()
            .print((
                filename,
                ariadne::Source::from(&line).with_display_line_offset(n),
            ))
            .unwrap()
        }
    }
}
