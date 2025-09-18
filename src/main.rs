use std::{
    collections::BTreeMap,
    io::{BufRead as _, Write as _},
    path::PathBuf,
    process::ExitCode,
};

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

    Record(RecordArgs),
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

#[derive(Debug, Clone, Parser)]
struct RecordArgs {
    #[arg(long)]
    full: bool,

    #[arg(long)]
    otel: bool,

    #[arg(short, long)]
    output_strace: Option<PathBuf>,

    #[arg(long)]
    output_perfetto: Option<PathBuf>,

    #[arg(last = true)]
    command: Vec<std::ffi::OsString>,
}

fn main() -> miette::Result<ExitCode> {
    let args = Args::parse();

    let exit_code = match args.command {
        Command::StraceToPerfetto(args) => {
            strace_to_perfetto(args)?;
            ExitCode::SUCCESS
        }
        Command::StraceToOtel(args) => {
            strace_to_otel(args)?;
            ExitCode::SUCCESS
        }
        Command::Record(args) => record(args)?,
    };

    Ok(exit_code)
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

fn record(args: RecordArgs) -> miette::Result<ExitCode> {
    let mut command = std::process::Command::new("strace");
    command
        .arg("-f")
        .arg("--status=!unfinished")
        .arg("--string-limit=4096")
        .arg("--absolute-timestamps=unix,us")
        .arg("--syscall-times")
        .arg("--decode-fds=all")
        .arg("--always-show-pid")
        .arg("--no-abbrev");

    if !args.full {
        command.arg("--seccomp-bpf").arg("--trace=file,process");
    }

    let mut strace_pipe = None;
    if !args.otel && args.output_perfetto.is_none() {
        let Some(output) = &args.output_strace else {
            miette::bail!("one of --otel, --output-perfetto, or --output-strace must be specified");
        };

        command.arg("--output").arg(output);
    } else {
        let pipe = create_pipe()?;
        command.arg("--output").arg(&pipe.path);

        strace_pipe = Some(pipe);
    }

    command.arg("--");
    command.args(args.command);

    let mut perfetto_writer = args
        .output_perfetto
        .map(|path| {
            let output = std::fs::File::create(&path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create Perfetto output at path {}",
                        path.display()
                    )
                })?;
            let writer = systrument::perfetto::PerfettoOutput::new(
                output,
                systrument::perfetto::PerfettoOutputOptions { logs: true },
            );
            Ok::<_, miette::Report>(writer)
        })
        .transpose()?;

    let mut otel_trace_provider = None;
    let mut otel_log_provider = None;
    let mut otel_writer = if args.otel {
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .into_diagnostic()
            .wrap_err("failed to build OTLP span exporter")?;
        let trace_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_attribute(opentelemetry::KeyValue::new("service.name", "systrument"))
                    .build(),
            )
            .build();
        let tracer = trace_provider.tracer("systrument");

        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .build()
            .into_diagnostic()
            .wrap_err("failed to build OTLP log exporter")?;
        let log_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_attribute(opentelemetry::KeyValue::new("service.name", "systrument"))
                    .build(),
            )
            .build();
        let logger = log_provider.logger("systrument");

        otel_trace_provider = Some(trace_provider);
        otel_log_provider = Some(log_provider);

        Some(systrument::otel::OtelOutput::new(
            tracer,
            Some(logger),
            systrument::otel::OtelOutputOptions { relative_to: None },
        ))
    } else {
        None
    };
    let mut strace_writer = if strace_pipe.is_some()
        && let Some(path) = &args.output_strace
    {
        let output = std::fs::File::create(path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create Perfetto output at path {}",
                    path.display()
                )
            })?;
        Some(output)
    } else {
        None
    };

    let command_thread = std::thread::spawn(move || command.status());

    if let Some(strace_pipe) = strace_pipe {
        let strace_pipe = std::fs::File::open(&strace_pipe.path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to open FIFO at path {}", strace_pipe.path.display())
            })?;
        let mut emitter = systrument::strace::analyzer::Analyzer::default();

        // Keep a queue of lines as we encounter them (we use a BTreeMap to order
        // lines by timestamp)
        let mut queued_lines = BTreeMap::new();

        let strace_pipe = std::io::BufReader::new(strace_pipe);
        for (line_index, line) in strace_pipe.lines().enumerate() {
            let line = line.unwrap();

            // Write the line verbatim
            if let Some(strace_writer) = &mut strace_writer {
                writeln!(strace_writer, "{line}").unwrap();
            }

            // Parse the line
            let strace = systrument::strace::parser::parse_line(&line);
            let strace = match strace {
                Ok(strace) => strace,
                Err(error) => {
                    let report = miette::Report::new(error).with_source_code(
                        systrument::utils::OffsetSource::new_named("<strace>", line)
                            .with_line_offset(line_index),
                    );
                    eprintln!("{report:?}");
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
                            systrument::utils::OffsetSource::new_named("<strace>", line)
                                .with_line_offset(line_index),
                        );
                        println!("{report:?}");
                        continue;
                    }
                };

                if let Some(perfetto_writer) = &mut perfetto_writer {
                    perfetto_writer
                        .output_event(event.clone())
                        .expect("error writing Perfetto event");
                }
                if let Some(otel_writer) = &mut otel_writer {
                    otel_writer
                        .output_event(event)
                        .expect("error writing OTel event");
                }
            }
        }

        // Handle remaining queued lines
        for (line_index, line) in queued_lines.into_values() {
            let strace = systrument::strace::parser::parse_line(&line).unwrap();

            let event = match emitter.analyze(strace) {
                Ok(event) => event,
                Err(error) => {
                    let report = miette::Report::new(error).with_source_code(
                        systrument::utils::OffsetSource::new_named("<strace>", line)
                            .with_line_offset(line_index),
                    );
                    println!("{report:?}");
                    continue;
                }
            };

            if let Some(perfetto_writer) = &mut perfetto_writer {
                perfetto_writer
                    .output_event(event.clone())
                    .expect("error writing Perfetto event");
            }
            if let Some(otel_writer) = &mut otel_writer {
                otel_writer
                    .output_event(event)
                    .expect("error writing OTel event");
            }
        }
    }

    // Shut down the OTel writer
    drop(otel_writer);

    // Shut down the OpenTelemetry tracer and logger
    if let Some(otel_trace_provider) = otel_trace_provider {
        otel_trace_provider
            .shutdown()
            .into_diagnostic()
            .wrap_err("failed to shutdown OTel trace provider")?;
    }
    if let Some(otel_log_provider) = otel_log_provider {
        otel_log_provider
            .shutdown()
            .into_diagnostic()
            .wrap_err("failed to shutdown OTel log provider")?;
    }

    let exit_status = command_thread.join().unwrap().into_diagnostic()?;
    if exit_status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        let exit_code = exit_status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from);
        Ok(exit_code)
    }
}

#[cfg(unix)]
fn create_pipe() -> miette::Result<TempPipe> {
    let id = uuid::Uuid::new_v4();
    let path = std::env::temp_dir().join(format!("strace-{id}.pipe"));

    interprocess::os::unix::fifo_file::create_fifo(&path, 0o777)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create FIFO with path {}", path.display()))?;

    Ok(TempPipe { path })
}

#[cfg(not(unix))]
fn create_pipe() -> miette::Result<TempPipe> {
    miette::bail!("platform not supported: only --output-strace can be used");
}

struct TempPipe {
    path: PathBuf,
}

impl Drop for TempPipe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
