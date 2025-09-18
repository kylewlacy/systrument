use std::{collections::BTreeMap, io::BufRead as _};

use clap::Parser;
use miette::{Context as _, IntoDiagnostic as _};
use opentelemetry::{logs::LoggerProvider, trace::TracerProvider as _};

/// The number of strace lines to look at before emitting them. This helps
/// if strace lines are included out-of-order.
const WINDOW_SIZE: usize = 100;

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
    let mut emitter = systrument::strace::analyzer::Analyzer::default();

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

    // Keep a queue of lines as we encounter them (we use a BTreeMap to order
    // lines by timestamp)
    let mut queued_lines = BTreeMap::new();

    for (line_index, line) in input.lines().enumerate() {
        let line = line.unwrap();

        // Parse the line
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

        // Add it to the queue, ordered by timestamp
        queued_lines.insert(strace.timestamp, (line_index, line));

        // Emit any lines beyond the window size
        while queued_lines.len() > WINDOW_SIZE {
            let (line_index, line) = queued_lines.first_entry().unwrap().remove();
            let strace = systrument::strace::parser::parse_line(&line).unwrap();

            let event = match emitter.analyze(strace) {
                Ok(event) => event,
                Err(error) => {
                    let report = miette::Report::new(error).with_source_code(
                        systrument::utils::OffsetSource::new_named(&input_name, line)
                            .with_line_offset(line_index),
                    );
                    println!("{report:?}");
                    continue;
                }
            };

            perfetto_writer
                .output_event(event)
                .expect("error writing Perfetto event");
        }
    }

    // Handle remaining queued lines
    for (line_index, line) in queued_lines.into_values() {
        let strace = systrument::strace::parser::parse_line(&line).unwrap();

        let event = match emitter.analyze(strace) {
            Ok(event) => event,
            Err(error) => {
                let report = miette::Report::new(error).with_source_code(
                    systrument::utils::OffsetSource::new_named(&input_name, line)
                        .with_line_offset(line_index),
                );
                println!("{report:?}");
                continue;
            }
        };

        perfetto_writer
            .output_event(event)
            .expect("error writing Perfetto event");
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

    let (otel_logger, otel_log_provider) = if args.logs {
        let otel_log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .build()
            .into_diagnostic()
            .wrap_err("failed to build OTLP log exporter")?;
        let otel_log_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_batch_exporter(otel_log_exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_attribute(opentelemetry::KeyValue::new("service.name", "systrument"))
                    .build(),
            )
            .build();
        let otel_logger = otel_log_provider.logger("systrument");
        (Some(otel_logger), Some(otel_log_provider))
    } else {
        (None, None)
    };

    let mut emitter = systrument::strace::analyzer::Analyzer::default();

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
        otel_logger,
        systrument::otel::OtelOutputOptions { relative_to },
    );

    let input_name = if args.input.is_stdin() {
        "<stdin>".to_string()
    } else {
        args.input.to_string()
    };

    // Keep a queue of lines as we encounter them (we use a BTreeMap to order
    // lines by timestamp)
    let mut queued_lines = BTreeMap::new();

    for (line_index, line) in input.lines().enumerate() {
        let line = line.unwrap();

        // Parse the line
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

        // Add it to the queue, ordered by timestamp
        queued_lines.insert(strace.timestamp, (line_index, line));

        // Emit any lines beyond the window size
        while queued_lines.len() > WINDOW_SIZE {
            let (line_index, line) = queued_lines.first_entry().unwrap().remove();
            let strace = systrument::strace::parser::parse_line(&line).unwrap();

            let event = match emitter.analyze(strace) {
                Ok(event) => event,
                Err(error) => {
                    let report = miette::Report::new(error).with_source_code(
                        systrument::utils::OffsetSource::new_named(&input_name, line)
                            .with_line_offset(line_index),
                    );
                    println!("{report:?}");
                    continue;
                }
            };

            otel_writer
                .output_event(event)
                .expect("error writing OTel event");
        }
    }

    // Handle remaining queued lines
    for (line_index, line) in queued_lines.into_values() {
        let strace = systrument::strace::parser::parse_line(&line).unwrap();

        let event = match emitter.analyze(strace) {
            Ok(event) => event,
            Err(error) => {
                let report = miette::Report::new(error).with_source_code(
                    systrument::utils::OffsetSource::new_named(&input_name, line)
                        .with_line_offset(line_index),
                );
                println!("{report:?}");
                continue;
            }
        };

        otel_writer
            .output_event(event)
            .expect("error writing OTel event");
    }

    // Shut down the writer
    drop(otel_writer);

    // Shut down the OpenTelemetry tracer and logger
    otel_trace_provider
        .shutdown()
        .into_diagnostic()
        .wrap_err("failed to shutdown OTel trace provider")?;
    if let Some(otel_log_provider) = otel_log_provider {
        otel_log_provider
            .shutdown()
            .into_diagnostic()
            .wrap_err("failed to shutdown OTel log provider")?;
    }

    Ok(())
}
