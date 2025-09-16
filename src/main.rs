use std::io::BufRead as _;

use clap::Parser;
use miette::{Context as _, IntoDiagnostic as _};
use opentelemetry::trace::TracerProvider as _;

#[derive(Debug, Clone, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum Command {
    #[command(name = "strace2perfetto")]
    StraceToPerfetto(StraceToPerfettoArgs),

    #[command(name = "strace2otel")]
    StraceToOtel(StraceToOtelArgs),
}

#[derive(Debug, Clone, Parser)]
struct StraceToPerfettoArgs {
    #[arg(default_value_t)]
    input: patharg::InputArg,

    #[arg(short, long)]
    output: patharg::OutputArg,

    #[arg(short, long)]
    logs: bool,
}

#[derive(Debug, Clone, Parser)]
struct StraceToOtelArgs {
    #[arg(default_value_t)]
    input: patharg::InputArg,

    #[arg(short, long)]
    logs: bool,

    #[arg(long)]
    relative_to_now: bool,
}

fn main() -> miette::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::StraceToPerfetto(args) => {
            strace_to_perfetto(args)?;
        }
        Command::StraceToOtel(args) => {
            strace_to_otel(args)?;
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
    let mut perfetto_writer = systrument::perfetto::PerfettoOutput::new(
        output,
        systrument::perfetto::PerfettoOutputOptions { logs: args.logs },
    );

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

fn strace_to_otel(args: StraceToOtelArgs) -> miette::Result<()> {
    let otel_span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .into_diagnostic()
        .wrap_err("failed to build OTLP span exporter")?;
    let otel_trace_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(otel_span_exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_attribute(opentelemetry::KeyValue::new("service.name", "systrument"))
                .build(),
        )
        .build();
    let otel_tracer = otel_trace_provider.tracer("systrument");

    let mut emitter = systrument::strace::emitter::EventEmitter::default();

    let input = args
        .input
        .open()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open input path {}", args.input))?;

    let relative_to = if args.relative_to_now {
        Some(jiff::Timestamp::now())
    } else {
        None
    };
    let mut otel_writer = systrument::otel::OtelOutput::new(
        otel_tracer,
        systrument::otel::OtelOutputOptions { relative_to },
    );

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
            otel_writer
                .output_event(event)
                .expect("error writing OTel event");
        }
    }

    drop(otel_writer);

    otel_trace_provider
        .shutdown()
        .into_diagnostic()
        .wrap_err("failed to shutdown OTel trace provider")?;

    Ok(())
}
