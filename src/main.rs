use std::io::BufRead as _;

fn main() -> miette::Result<()> {
    // let mut emitter = strace::emitter::EventEmitter::default();
    let output_path = std::env::args()
        .skip(1)
        .next()
        .expect("usage: <output-path>");

    let stdin = std::io::stdin().lock();
    let mut perfetto_writer =
        systrument::perfetto::PerfettoOutput::new(std::fs::File::create(output_path).unwrap());

    for (line_index, line) in stdin.lines().enumerate() {
        let line = line.unwrap();

        let strace = systrument::strace::parser::parse_line(&line);
        let strace = match strace {
            Ok(strace) => strace,
            Err(error) => {
                let report = miette::Report::new(error).with_source_code(
                    systrument::utils::OffsetSource::new_named("<stdin>", line)
                        .with_line_offset(line_index),
                );
                println!("{report:?}");
                continue;
            }
        };

        // println!("{strace:#?}");

        // emitter.push_line(strace);

        // while let Some(event) = emitter.pop_event() {
        //     perfetto_writer
        //         .output_event(event)
        //         .expect("error writing perfetto event");
        // }
    }

    Ok(())
}
