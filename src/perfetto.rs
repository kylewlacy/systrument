use std::collections::HashMap;

use perfetto_protos::{
    trace::Trace,
    trace_packet::{TracePacket, trace_packet},
    track_descriptor::{TrackDescriptor, track_descriptor},
    track_event::{TrackEvent, track_event},
};
use protobuf::{EnumOrUnknown, Message as _};

use crate::event::Event;

const TRACK_NAME: &str = "Processes";

pub struct PerfettoOutput<W: std::io::Write> {
    writer: W,
    trusted_packet_sequence_id: trace_packet::Optional_trusted_packet_sequence_id,
    track_uuids_by_pid: HashMap<libc::pid_t, u64>,
}

impl<W: std::io::Write> PerfettoOutput<W> {
    pub fn new(writer: W) -> Self {
        let trusted_packet_sequence_id =
            trace_packet::Optional_trusted_packet_sequence_id::TrustedPacketSequenceId(
                rand::random(),
            );

        Self {
            writer,
            trusted_packet_sequence_id,
            track_uuids_by_pid: HashMap::new(),
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

        let packets = match event.kind {
            crate::event::EventKind::StartProcess(event) => {
                vec![
                    TracePacket {
                        timestamp: Some(timestamp),
                        optional_trusted_packet_sequence_id: Some(
                            self.trusted_packet_sequence_id.clone(),
                        ),
                        data: Some(trace_packet::Data::TrackDescriptor(TrackDescriptor {
                            uuid: Some(track_uuid),
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
                            name_field: event
                                .command_name()
                                .map(|name| track_event::Name_field::Name(name.to_string())),
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                ]
            }
            crate::event::EventKind::StopProcess(_) => {
                self.track_uuids_by_pid.remove(&pid);
                vec![TracePacket {
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
                }]
            }
        };

        let perfetto_message = Trace {
            packet: packets,
            ..Default::default()
        };
        perfetto_message.write_to_writer(&mut self.writer)?;

        Ok(())
    }
}
