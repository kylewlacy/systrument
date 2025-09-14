use std::collections::HashMap;

use perfetto_protos::{
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

pub struct PerfettoOutput<W: std::io::Write> {
    writer: W,
    trusted_packet_sequence_id: trace_packet::Optional_trusted_packet_sequence_id,
    track_uuids_by_pid: HashMap<Pid, u64>,
    log_body_iid: u64,
    packets: Vec<TracePacket>,
    root_track_uuid: u64,
}

impl<W: std::io::Write> PerfettoOutput<W> {
    pub fn new(writer: W) -> Self {
        let trusted_packet_sequence_id =
            trace_packet::Optional_trusted_packet_sequence_id::TrustedPacketSequenceId(
                rand::random(),
            );
        let root_track_uuid = rand::random();
        let root_track_packet = TracePacket {
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
        };

        Self {
            writer,
            trusted_packet_sequence_id: trusted_packet_sequence_id,
            track_uuids_by_pid: HashMap::new(),
            log_body_iid: 1,
            packets: vec![root_track_packet],
            root_track_uuid,
        }
    }

    pub fn output_event(&mut self, event: Event) -> Result<(), Box<dyn std::error::Error>> {
        let pid = event.pid;
        let track_uuid = *self
            .track_uuids_by_pid
            .entry(pid)
            .or_insert_with(|| rand::random());
        let timestamp = event
            .timestamp
            .as_nanosecond()
            .try_into()
            .expect("timestamp out of range");

        let log_body_iid = self.log_body_iid;
        self.log_body_iid += 1;

        let log_packet = TracePacket {
            timestamp: Some(timestamp),
            optional_trusted_packet_sequence_id: Some(self.trusted_packet_sequence_id.clone()),
            interned_data: MessageField::some(InternedData {
                log_message_body: vec![LogMessageBody {
                    iid: Some(log_body_iid),
                    body: Some(format!("{}\n", event.log)),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            data: Some(trace_packet::Data::TrackEvent(TrackEvent {
                track_uuid: Some(self.root_track_uuid),
                name_field: Some(track_event::Name_field::Name("Log".into())),
                type_: Some(EnumOrUnknown::new(track_event::Type::TYPE_INSTANT)),
                log_message: MessageField::some(LogMessage {
                    body_iid: Some(log_body_iid),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        match event.kind {
            crate::event::EventKind::StartProcess(start_process) => {
                self.packets.extend([
                    TracePacket {
                        timestamp: Some(timestamp),
                        optional_trusted_packet_sequence_id: Some(
                            self.trusted_packet_sequence_id.clone(),
                        ),
                        sequence_flags: Some(1),
                        data: Some(trace_packet::Data::TrackDescriptor(TrackDescriptor {
                            uuid: Some(track_uuid),
                            parent_uuid: Some(self.root_track_uuid),
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
                            name_field: start_process
                                .command_name()
                                .map(|name| track_event::Name_field::Name(name.to_string())),
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                    log_packet,
                ]);
            }
            crate::event::EventKind::StopProcess(_) => {
                self.track_uuids_by_pid.remove(&pid);
                self.packets.extend([
                    log_packet,
                    TracePacket {
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
                    },
                ]);
            }
            crate::event::EventKind::Log => {
                self.packets.push(log_packet);
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
