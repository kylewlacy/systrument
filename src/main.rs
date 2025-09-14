use std::io::BufRead as _;

use clap::Parser;
use miette::{Context as _, IntoDiagnostic as _};

#[derive(Debug, Clone, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum Command {
    #[command(name = "strace2perfetto")]
    StraceToPerfetto(StraceToPerfettoArgs),
}

#[derive(Debug, Clone, Parser)]
struct StraceToPerfettoArgs {
    #[arg(default_value_t)]
    input: patharg::InputArg,

    #[arg(short, long)]
    output: patharg::OutputArg,
}

fn main() -> miette::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::StraceToPerfetto(args) => {
            strace_to_perfetto(args)?;
        }
    }

    Ok(())
}

fn strace_to_perfetto(args: StraceToPerfettoArgs) -> miette::Result<()> {
    let mut emitter = systrument::strace::emitter::EventEmitter::default();

    let input = args
        .input
        .open()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open input path {}", args.input))?;
    let output = args
        .output
        .create()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open output path {}", args.input))?;
    let mut perfetto_writer = systrument::perfetto::PerfettoOutput::new(output);

    let input_name = if args.input.is_stdin() {
        "<stdin>".to_string()
    } else {
        args.input.to_string()
    };

    for (line_index, line) in input.lines().enumerate() {
        let line = line.unwrap();

        let strace = systrument::strace::parser::parse_line(&line);
        let strace = match strace {
            Ok(strace) => strace,
            Err(error) => {
                let report = miette::Report::new(error).with_source_code(
                    systrument::utils::OffsetSource::new_named(&input_name, line)
                        .with_line_offset(line_index),
                );
                println!("{report:?}");
                continue;
            }
        };

        if let Err(error) = emitter.push_line(strace, line.clone()) {
            let report = miette::Report::new(error).with_source_code(
                systrument::utils::OffsetSource::new_named(&input_name, line)
                    .with_line_offset(line_index),
            );
            println!("{report:?}");
            continue;
        }

        while let Some(event) = emitter.pop_event() {
            perfetto_writer
                .output_event(event)
                .expect("error writing Perfetto event");
        }
    }

    Ok(())
}
