use std::io::BufRead as _;

use chumsky::Parser as _;

mod event;
mod strace;

fn main() {
    let mut emitter = strace::emitter::EventEmitter::default();

    let stdin = std::io::stdin().lock();
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
            .print((
                filename,
                ariadne::Source::from(&line).with_display_line_offset(n),
            ))
            .unwrap()
        }

        if let Some(strace) = strace {
            emitter.push_line(strace);
        }

        while let Some(event) = emitter.pop_event() {
            let pid = event.pid;
            match event.kind {
                event::EventKind::StartProcess(event) => {
                    println!(
                        "[{pid}] start: {}",
                        event.command_name().unwrap_or_default()
                    );
                }
                event::EventKind::StopProcess(event) => {
                    println!("[{pid}] stop: {event:?}");
                }
            }
        }
    }
}
