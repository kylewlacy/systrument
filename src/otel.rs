use std::{cell::OnceCell, collections::HashMap};

use bstr::ByteSlice as _;
use opentelemetry::{
    logs::LogRecord as _,
    trace::{Span as _, TraceContextExt},
};

use crate::event::Event;

const ROOT_SPAN_NAME: &str = "processes";

#[derive(Debug, Default)]
pub struct OtelOutputOptions {
    pub relative_to: Option<jiff::Timestamp>,
}

pub struct OtelOutput<T, L>
where
    T: opentelemetry::trace::Tracer<Span = opentelemetry_sdk::trace::Span>,
    L: opentelemetry::logs::Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord>,
{
    options: OtelOutputOptions,
    tracer: T,
    logger: Option<L>,
    root_span: std::cell::OnceCell<opentelemetry_sdk::trace::Span>,
    process_spans: HashMap<crate::Pid, opentelemetry_sdk::trace::Span>,
    first_event_timestamp: Option<jiff::Timestamp>,
    last_event_timestamp: Option<jiff::Timestamp>,
}

impl<T, L> OtelOutput<T, L>
where
    T: opentelemetry::trace::Tracer<Span = opentelemetry_sdk::trace::Span>,
    L: opentelemetry::logs::Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord>,
{
    pub fn new(tracer: T, logger: Option<L>, options: OtelOutputOptions) -> Self {
        Self {
            options,
            logger,
            tracer,
            process_spans: HashMap::new(),
            root_span: OnceCell::new(),
            first_event_timestamp: None,
            last_event_timestamp: None,
        }
    }

    pub fn output_event(&mut self, event: Event) -> Result<(), Box<dyn std::error::Error>> {
        self.first_event_timestamp = Some(self.first_event_timestamp.unwrap_or(event.timestamp));
        self.last_event_timestamp = Some(event.timestamp);

        let adjusted_timestamp = self.adjust_timestamp(event.timestamp);

        match event.kind {
            crate::event::EventKind::ExecProcess(exec_process_event) => {
                let command_name = exec_process_event.exec.command_name().map_or_else(
                    || format!("process {}", event.pid),
                    |command_name| command_name.to_str_lossy().into_owned(),
                );
                let parent_span_context = event
                    .owner_pid
                    .and_then(|owner_pid| {
                        let span = self.process_spans.get(&owner_pid)?;
                        Some(span.span_context().clone())
                    })
                    .unwrap_or_else(|| self.root_span(event.timestamp).span_context().clone());
                let cx =
                    opentelemetry::Context::new().with_remote_span_context(parent_span_context);
                let attributes =
                    std::iter::once(opentelemetry::KeyValue::new("pid", i64::from(event.pid)))
                        .chain(event.parent_pid.map(|parent_pid| {
                            opentelemetry::KeyValue::new("parent_pid", i64::from(parent_pid))
                        }))
                        .chain(event.owner_pid.map(|owner_pid| {
                            opentelemetry::KeyValue::new("owner_pid", i64::from(owner_pid))
                        }))
                        .chain(exec_process_event.exec.command_name().into_iter().map(
                            |command_name| {
                                opentelemetry::KeyValue::new(
                                    "command_name",
                                    command_name.to_str_lossy().into_owned(),
                                )
                            },
                        ))
                        .chain(exec_process_event.exec.command.iter().map(|command| {
                            opentelemetry::KeyValue::new(
                                "command",
                                command.to_str_lossy().into_owned(),
                            )
                        }))
                        .chain(exec_process_event.exec.args.iter().map(|args| {
                            opentelemetry::KeyValue::new(
                                "args",
                                opentelemetry::Value::Array(opentelemetry::Array::String(
                                    args.iter()
                                        .map(|arg| arg.to_str_lossy().into_owned().into())
                                        .collect(),
                                )),
                            )
                        }))
                        .chain(exec_process_event.exec.env.iter().flatten().map(
                            |(name, value)| {
                                opentelemetry::KeyValue::new(
                                    format!("env.{name}"),
                                    opentelemetry::Value::String(
                                        value.to_str_lossy().into_owned().into(),
                                    ),
                                )
                            },
                        ));
                let span = self
                    .tracer
                    .span_builder(command_name)
                    .with_start_time(adjusted_timestamp)
                    .with_attributes(attributes)
                    .start_with_context(&self.tracer, &cx);
                let prev_span = self.process_spans.insert(event.pid, span);

                if let Some(mut prev_span) = prev_span {
                    prev_span.set_attribute(opentelemetry::KeyValue::new("re_exec", true));
                    prev_span.end_with_timestamp(adjusted_timestamp.into());
                }
            }
            crate::event::EventKind::StopProcess(stop_process_event) => {
                if let Some(mut span) = self.process_spans.remove(&event.pid) {
                    match stop_process_event.stopped {
                        crate::event::ProcessStoppedReason::Exited { code } => {
                            if let Some(code) = code {
                                span.set_attributes([
                                    opentelemetry::KeyValue::new("exit_code", i64::from(code)),
                                    opentelemetry::KeyValue::new("exit_ok", code == 0),
                                ]);
                            }
                        }
                        crate::event::ProcessStoppedReason::Killed { signal } => {
                            span.set_attributes(
                                std::iter::once(opentelemetry::KeyValue::new("exit_ok", false))
                                    .chain(signal.map(|signal| {
                                        opentelemetry::KeyValue::new("exit_signal", signal)
                                    })),
                            );
                        }
                    }

                    span.end_with_timestamp(adjusted_timestamp.into());
                }
            }
            crate::event::EventKind::ForkProcess(_) | crate::event::EventKind::Log => {}
        };

        if self.logger.is_some() {
            let span_context = self
                .process_spans
                .get(&event.pid)
                .or_else(|| self.process_spans.get(&event.owner_pid?))
                .map(|span| span.span_context().clone())
                .unwrap_or_else(|| self.root_span(event.timestamp).span_context().clone());
            let logger = self.logger.as_ref().unwrap();

            let mut log = logger.create_log_record();
            log.set_timestamp(adjusted_timestamp.into());
            log.set_trace_context(span_context.trace_id(), span_context.span_id(), None);

            log.add_attribute("pid", event.pid);
            if let Some(parent_pid) = event.parent_pid {
                log.add_attribute("parent_pid", parent_pid);
            }
            if let Some(owner_pid) = event.owner_pid {
                log.add_attribute("owner_pid", owner_pid);
            }

            match event.strace.event {
                crate::strace::Event::Syscall(syscall) => {
                    log.set_body(
                        format!(
                            "{}({}) = {}",
                            syscall.name, syscall.args_string.value, syscall.result_string.value
                        )
                        .into(),
                    );
                    log.add_attribute("syscall", syscall.name.to_string());
                    log.add_attribute("args", syscall.args_string.value.to_string());
                    log.add_attribute("result", syscall.result_string.value.to_string());
                }
                crate::strace::Event::Signal { signal } => {
                    log.set_body(format!("--- {signal} ---").into());
                    log.add_attribute("signal", signal.to_string());
                }
                crate::strace::Event::Exited(exited_event) => {
                    log.set_body(
                        format!("+++ exited with {} +++", exited_event.code_string.value).into(),
                    );

                    let exit_code = exited_event.code().ok().and_then(|code| code.as_i32());
                    if let Some(exit_code) = exit_code {
                        log.add_attribute("exit_code", exit_code);
                    }
                }
                crate::strace::Event::KilledBy { signal_string } => {
                    log.set_body(format!("+++ killed by {} +++", signal_string.value).into());
                    log.add_attribute("signal", signal_string.value.to_string());
                }
            }

            logger.emit(log);
        }

        Ok(())
    }

    fn adjust_timestamp(&self, event_timestamp: jiff::Timestamp) -> jiff::Timestamp {
        let Some(relative_to) = self.options.relative_to else {
            return event_timestamp;
        };

        let Some(first_event_timestamp) = self.first_event_timestamp else {
            return event_timestamp;
        };

        let duration = event_timestamp - first_event_timestamp;
        relative_to + duration
    }

    fn root_span(&mut self, event_timestamp: jiff::Timestamp) -> &opentelemetry_sdk::trace::Span {
        let first_event_timestamp = self.first_event_timestamp.unwrap_or(event_timestamp);
        self.first_event_timestamp = Some(first_event_timestamp);

        let adjusted_timestamp = self.adjust_timestamp(first_event_timestamp);

        self.root_span.get_or_init(|| {
            self.tracer
                .span_builder(ROOT_SPAN_NAME)
                .with_start_time(adjusted_timestamp)
                .start(&self.tracer)
        })
    }
}

impl<T, L> Drop for OtelOutput<T, L>
where
    T: opentelemetry::trace::Tracer<Span = opentelemetry_sdk::trace::Span>,
    L: opentelemetry::logs::Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord>,
{
    fn drop(&mut self) {
        if let Some(mut root_span) = self.root_span.take() {
            if let Some(last_event_timestamp) = self.last_event_timestamp {
                let adjusted_timestamp = self.adjust_timestamp(last_event_timestamp);
                root_span.end_with_timestamp(adjusted_timestamp.into());
            } else {
                root_span.end();
            }
        }
    }
}
