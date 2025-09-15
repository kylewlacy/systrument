use std::{cell::OnceCell, collections::HashMap};

use bstr::ByteSlice as _;
use opentelemetry::trace::{Span as _, TraceContextExt};

use crate::event::Event;

const ROOT_SPAN_NAME: &str = "processes";

#[derive(Debug, Default)]
pub struct OtelOutputOptions {
    pub trace_id: Option<opentelemetry::TraceId>,
    pub parent_span_id: Option<opentelemetry::SpanId>,
    pub relative_to: Option<jiff::Timestamp>,
}

pub struct OtelOutput<T>
where
    T: opentelemetry::trace::Tracer<Span = opentelemetry_sdk::trace::Span>,
{
    options: OtelOutputOptions,
    tracer: T,
    trace_id: opentelemetry::TraceId,
    root_span: std::cell::OnceCell<opentelemetry_sdk::trace::Span>,
    process_spans: HashMap<crate::Pid, opentelemetry_sdk::trace::Span>,
    first_event_timestamp: Option<jiff::Timestamp>,
    last_event_timestamp: Option<jiff::Timestamp>,
}

impl<T> OtelOutput<T>
where
    T: opentelemetry::trace::Tracer<Span = opentelemetry_sdk::trace::Span>,
{
    pub fn new(tracer: T, options: OtelOutputOptions) -> Self {
        let trace_id = options
            .trace_id
            .unwrap_or_else(|| opentelemetry::TraceId::from(rand::random::<u128>()));

        Self {
            options,
            tracer,
            process_spans: HashMap::new(),
            root_span: OnceCell::new(),
            trace_id,
            first_event_timestamp: None,
            last_event_timestamp: None,
        }
    }

    pub fn output_event(&mut self, event: Event) -> Result<(), Box<dyn std::error::Error>> {
        self.first_event_timestamp = Some(self.first_event_timestamp.unwrap_or(event.timestamp));
        self.last_event_timestamp = Some(event.timestamp);

        let adjusted_timestamp = self.adjust_timestamp(event.timestamp);

        let root_span = self.root_span.get_or_init(|| {
            let mut cx = opentelemetry::Context::new();
            if let Some(parent_span_id) = self.options.parent_span_id {
                cx = cx.with_remote_span_context(opentelemetry::trace::SpanContext::new(
                    self.trace_id,
                    parent_span_id,
                    Default::default(),
                    false,
                    Default::default(),
                ));
            }
            self.tracer
                .span_builder(ROOT_SPAN_NAME)
                .with_start_time(adjusted_timestamp)
                .start_with_context(&self.tracer, &cx)
        });

        match event.kind {
            crate::event::EventKind::StartProcess(start_process) => {
                let command_name = start_process.command_name().map_or_else(
                    || format!("process {}", event.pid),
                    |command_name| command_name.to_str_lossy().into_owned(),
                );
                let parent_span = start_process
                    .owner_pid
                    .and_then(|owner_pid| self.process_spans.get(&owner_pid))
                    .unwrap_or(root_span);
                let cx = opentelemetry::Context::new()
                    .with_remote_span_context(parent_span.span_context().clone());
                let attributes =
                    std::iter::once(opentelemetry::KeyValue::new("pid", event.pid.to_string()))
                        .chain(
                            start_process
                                .command_name()
                                .into_iter()
                                .map(|command_name| {
                                    opentelemetry::KeyValue::new(
                                        "command_name",
                                        command_name.to_str_lossy().into_owned(),
                                    )
                                }),
                        )
                        .chain(start_process.command.iter().map(|command| {
                            opentelemetry::KeyValue::new(
                                "command",
                                command.to_str_lossy().into_owned(),
                            )
                        }))
                        .chain(start_process.args.iter().map(|args| {
                            opentelemetry::KeyValue::new(
                                "args",
                                opentelemetry::Value::Array(opentelemetry::Array::String(
                                    args.iter()
                                        .map(|arg| arg.to_str_lossy().into_owned().into())
                                        .collect(),
                                )),
                            )
                        }));
                let span = self
                    .tracer
                    .span_builder(command_name)
                    .with_start_time(adjusted_timestamp)
                    .with_attributes(attributes)
                    .start_with_context(&self.tracer, &cx);
                self.process_spans.insert(event.pid, span);
            }
            crate::event::EventKind::StopProcess(_) => {
                if let Some(mut span) = self.process_spans.remove(&event.pid) {
                    span.end_with_timestamp(adjusted_timestamp.into());
                }
            }
            crate::event::EventKind::Log => {}
        };

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
}

impl<T> Drop for OtelOutput<T>
where
    T: opentelemetry::trace::Tracer<Span = opentelemetry_sdk::trace::Span>,
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
