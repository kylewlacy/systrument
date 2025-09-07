use std::io::BufRead as _;

use chumsky::Parser as _;

mod event;
mod perfetto;
mod strace;

fn main() {
    let mut emitter = strace::emitter::EventEmitter::default();
    let output_path = std::env::args()
        .skip(1)
        .next()
        .expect("usage: <output-path>");

    let stdin = std::io::stdin().lock();
    let mut perfetto_writer =
        perfetto::PerfettoOutput::new(std::fs::File::create(output_path).unwrap());

    for (n, line) in stdin.lines().enumerate() {
        let line = line.unwrap();

        let (strace, errors) = strace::parser::line_parser()
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
            .eprint((
                filename,
                ariadne::Source::from(&line).with_display_line_offset(n),
            ))
            .unwrap()
        }

        if let Some(strace) = strace {
            emitter.push_line(strace);
        }

        while let Some(event) = emitter.pop_event() {
            perfetto_writer
                .output_event(event)
                .expect("error writing perfetto event");
        }
    }
}
