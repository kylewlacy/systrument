use std::collections::HashMap;

use bstr::ByteVec as _;
use perfetto_protos::{
    debug_annotation::{DebugAnnotation, debug_annotation},
    interned_data::InternedData,
    log_message::{LogMessage, LogMessageBody},
    process_descriptor::ProcessDescriptor,
    thread_descriptor::ThreadDescriptor,
    trace::Trace,
    trace_packet::{TracePacket, trace_packet},
    track_descriptor::{TrackDescriptor, track_descriptor},
    track_event::{TrackEvent, track_event},
};
use protobuf::{EnumOrUnknown, Message as _, MessageField};

use crate::{Pid, event::Event};

const TRACK_NAME: &str = "Processes";

#[derive(Debug, Default)]
pub struct PerfettoOutputOptions {
    pub logs: bool,
}

pub struct PerfettoOutput<W: std::io::Write> {
    writer: W,
    options: PerfettoOutputOptions,
    trusted_packet_sequence_id: trace_packet::Optional_trusted_packet_sequence_id,
    track_uuids_by_pid: HashMap<Pid, u64>,
    log_body_iid: u64,
    packets: Vec<TracePacket>,
    root_track_uuid: Option<u64>,
}

impl<W: std::io::Write> PerfettoOutput<W> {
    pub fn new(writer: W, options: PerfettoOutputOptions) -> Self {
        let trusted_packet_sequence_id =
            trace_packet::Optional_trusted_packet_sequence_id::TrustedPacketSequenceId(
                rand::random(),
            );
        let mut packets = vec![];

        let root_track_uuid = if options.logs {
            let root_track_uuid = rand::random();
            packets.push(TracePacket {
                optional_trusted_packet_sequence_id: Some(trusted_packet_sequence_id.clone()),
                sequence_flags: Some(1),
                data: Some(trace_packet::Data::TrackDescriptor(TrackDescriptor {
                    uuid: Some(root_track_uuid),
                    static_or_dynamic_name: Some(track_descriptor::Static_or_dynamic_name::Name(
                        "Root".into(),
                    )),
                    process: MessageField::some(ProcessDescriptor {
                        pid: Some(0),
                        ..Default::default()
                    }),
                    thread: MessageField::some(ThreadDescriptor {
                        pid: Some(0),
                        tid: Some(0),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                ..Default::default()
            });
            Some(root_track_uuid)
        } else {
            None
        };

        Self {
            writer,
            options,
            trusted_packet_sequence_id: trusted_packet_sequence_id,
            track_uuids_by_pid: HashMap::new(),
            log_body_iid: 1,
            packets,
            root_track_uuid,
        }
    }

    pub fn output_event(&mut self, event: Event) -> Result<(), Box<dyn std::error::Error>> {
        let pid = event.pid;
        let mut track_uuid = *self
            .track_uuids_by_pid
            .entry(pid)
            .or_insert_with(|| rand::random());
        let timestamp = event
            .timestamp
            .as_nanosecond()
            .try_into()
            .expect("timestamp out of range");

        let log_packet = if self.options.logs {
            let log_body_iid = self.log_body_iid;
            self.log_body_iid += 1;

            Some(TracePacket {
                timestamp: Some(timestamp),
                optional_trusted_packet_sequence_id: Some(self.trusted_packet_sequence_id.clone()),
                interned_data: MessageField::some(InternedData {
                    log_message_body: vec![LogMessageBody {
                        iid: Some(log_body_iid),
                        body: Some(format!("{}\n", event.strace.line)),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                data: Some(trace_packet::Data::TrackEvent(TrackEvent {
                    track_uuid: self.root_track_uuid,
                    name_field: Some(track_event::Name_field::Name("Log".into())),
                    type_: Some(EnumOrUnknown::new(track_event::Type::TYPE_INSTANT)),
                    log_message: MessageField::some(LogMessage {
                        body_iid: Some(log_body_iid),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                ..Default::default()
            })
        } else {
            None
        };

        match event.kind {
            crate::event::EventKind::ExecProcess(exec_process_event) => {
                if exec_process_event.re_exec {
                    // If the `exec` happened on an existing track, end the
                    // current track first

                    self.packets.push(TracePacket {
                        timestamp: Some(timestamp),
                        optional_trusted_packet_sequence_id: Some(
                            self.trusted_packet_sequence_id.clone(),
                        ),
                        data: Some(trace_packet::Data::TrackEvent(TrackEvent {
                            track_uuid: Some(track_uuid),
                            type_: Some(EnumOrUnknown::new(track_event::Type::TYPE_SLICE_END)),
                            ..Default::default()
                        })),
                        ..Default::default()
                    });

                    // Generate a new UUID for the new exec track
                    track_uuid = rand::random();
                    self.track_uuids_by_pid.insert(pid, track_uuid);
                }

                let command_name = exec_process_event
                    .exec
                    .command_name()
                    .map(|command_name| command_name.to_owned());
                let debug_annotations = exec_process_event
                    .exec
                    .command
                    .into_iter()
                    .map(|command| DebugAnnotation {
                        name_field: Some(debug_annotation::Name_field::Name("command".to_string())),
                        value: Some(debug_annotation::Value::StringValue(
                            Vec::from(command).into_string_lossy(),
                        )),
                        ..Default::default()
                    })
                    .chain(exec_process_event.exec.args.into_iter().map(|args| {
                        DebugAnnotation {
                            name_field: Some(debug_annotation::Name_field::Name(
                                "args".to_string(),
                            )),
                            array_values: args
                                .into_iter()
                                .map(|arg| DebugAnnotation {
                                    value: Some(debug_annotation::Value::StringValue(
                                        Vec::from(arg).into_string_lossy(),
                                    )),
                                    ..Default::default()
                                })
                                .collect(),
                            ..Default::default()
                        }
                    }))
                    .chain(exec_process_event.exec.env.into_iter().map(|env| {
                        DebugAnnotation {
                            name_field: Some(debug_annotation::Name_field::Name("env".to_string())),
                            dict_entries: env
                                .into_iter()
                                .map(|(name, value)| DebugAnnotation {
                                    name_field: Some(debug_annotation::Name_field::Name(
                                        Vec::from(name).into_string_lossy(),
                                    )),
                                    value: Some(debug_annotation::Value::StringValue(
                                        Vec::from(value).into_string_lossy(),
                                    )),
                                    ..Default::default()
                                })
                                .collect(),
                            ..Default::default()
                        }
                    }))
                    .collect();

                self.packets.extend([
                    TracePacket {
                        timestamp: Some(timestamp),
                        optional_trusted_packet_sequence_id: Some(
                            self.trusted_packet_sequence_id.clone(),
                        ),
                        sequence_flags: Some(1),
                        data: Some(trace_packet::Data::TrackDescriptor(TrackDescriptor {
                            uuid: Some(track_uuid),
                            parent_uuid: self.root_track_uuid,
                            static_or_dynamic_name: Some(
                                track_descriptor::Static_or_dynamic_name::Name(TRACK_NAME.into()),
                            ),
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                    TracePacket {
                        timestamp: Some(timestamp),
                        optional_trusted_packet_sequence_id: Some(
                            self.trusted_packet_sequence_id.clone(),
                        ),
                        data: Some(trace_packet::Data::TrackEvent(TrackEvent {
                            track_uuid: Some(track_uuid),
                            type_: Some(EnumOrUnknown::new(track_event::Type::TYPE_SLICE_BEGIN)),
                            name_field: command_name
                                .map(|name| track_event::Name_field::Name(name.to_string())),
                            debug_annotations,
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                ]);
                self.packets.extend(log_packet);
            }
            crate::event::EventKind::StopProcess(_) => {
                self.track_uuids_by_pid.remove(&pid);
                self.packets.extend(log_packet);
                self.packets.push(TracePacket {
                    timestamp: Some(timestamp),
                    optional_trusted_packet_sequence_id: Some(
                        self.trusted_packet_sequence_id.clone(),
                    ),
                    data: Some(trace_packet::Data::TrackEvent(TrackEvent {
                        track_uuid: Some(track_uuid),
                        type_: Some(EnumOrUnknown::new(track_event::Type::TYPE_SLICE_END)),
                        ..Default::default()
                    })),
                    ..Default::default()
                });
            }
            crate::event::EventKind::ForkProcess(_) | crate::event::EventKind::Log => {
                self.packets.extend(log_packet);
            }
        };

        let perfetto_message = Trace {
            packet: std::mem::take(&mut self.packets),
            ..Default::default()
        };
        perfetto_message.write_to_writer(&mut self.writer)?;

        Ok(())
    }
}
