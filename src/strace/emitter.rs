use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
};

use bstr::ByteSlice;

use crate::{
    Pid,
    event::{Event, EventKind, StartProcessEvent, StopProcessEvent},
};

#[derive(Default)]
pub struct EventEmitter {
    alive_processes: HashMap<Pid, ProcessState>,
    events: VecDeque<Event>,
}

impl EventEmitter {
    pub fn push_line(
        &mut self,
        line: super::Line,
    ) -> Result<(), crate::strace::parser::StraceParseError> {
        let timestamp = line.timestamp;
        let pid = line.pid;

        let process_state = self.alive_processes.entry(pid).or_default();

        match line.event {
            super::Event::Syscall(event) => match event.name {
                "fork" | "vfork" | "clone" | "clone3" => {
                    let result = event.result()?;

                    let child_pid = result.returned.and_then(|value| value.as_i32());
                    if let Some(child_pid) = child_pid {
                        self.alive_processes
                            .entry(child_pid)
                            .or_insert_with(|| ProcessState {
                                parent_pid: Some(pid),
                                ..Default::default()
                            });
                    }
                }
                "execve" => {
                    let args = event.args()?;

                    let command = args
                        .value_at_index(0)
                        .and_then(super::Value::to_bstring)
                        .map(Cow::into_owned);
                    let exec_args =
                        args.value_at_index(1)
                            .and_then(super::Value::as_array)
                            .map(|args| {
                                args.iter()
                                    .map(|arg| {
                                        arg.to_bstring()
                                            .unwrap_or(Cow::Borrowed(bstr::BStr::new(
                                                b"<unknown arg>",
                                            )))
                                            .into_owned()
                                    })
                                    .collect()
                            });
                    let env = args
                        .value_at_index(2)
                        .and_then(super::Value::as_array)
                        .map(|env| {
                            env.iter()
                                .filter_map(|env| {
                                    let env = env.to_bstring()?;
                                    let (key, value) = env.split_once_str(b"=")?;
                                    Some((bstr::BString::from(key), bstr::BString::from(value)))
                                })
                                .collect()
                        });

                    if process_state.did_exec {
                        self.events.push_back(Event {
                            timestamp,
                            pid,
                            kind: EventKind::StopProcess(StopProcessEvent::ReExeced),
                        });
                    }
                    process_state.did_exec = true;

                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::StartProcess(StartProcessEvent {
                            parent_pid: process_state.parent_pid,
                            command,
                            args: exec_args,
                            env,
                        }),
                    });
                }
                "execveat" => {
                    let args = event.args()?;

                    let dir = args
                        .value_at_index(0)
                        .and_then(super::Value::to_bstring)
                        .map(Cow::into_owned);
                    let command = args
                        .value_at_index(1)
                        .and_then(super::Value::to_bstring)
                        .map(Cow::into_owned);
                    let command = match (dir, command) {
                        (Some(mut dir), Some(command)) => {
                            if !command.is_empty() {
                                dir.push(b'/');
                                dir.extend_from_slice(&command);
                            }
                            Some(dir)
                        }
                        (Some(path), None) | (None, Some(path)) => Some(path),
                        (None, None) => None,
                    };

                    let exec_args =
                        args.value_at_index(2)
                            .and_then(super::Value::as_array)
                            .map(|args| {
                                args.iter()
                                    .map(|arg| {
                                        arg.to_bstring()
                                            .unwrap_or(Cow::Borrowed(bstr::BStr::new(
                                                b"<unknown arg>",
                                            )))
                                            .into_owned()
                                    })
                                    .collect()
                            });
                    let env = args
                        .value_at_index(3)
                        .and_then(super::Value::as_array)
                        .map(|env| {
                            env.iter()
                                .filter_map(|env| {
                                    let env = env.to_bstring()?;
                                    let (key, value) = env.split_once_str(b"=")?;
                                    Some((bstr::BString::from(key), bstr::BString::from(value)))
                                })
                                .collect()
                        });

                    if process_state.did_exec {
                        self.events.push_back(Event {
                            timestamp,
                            pid,
                            kind: EventKind::StopProcess(StopProcessEvent::ReExeced),
                        });
                    }
                    process_state.did_exec = true;

                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::StartProcess(StartProcessEvent {
                            parent_pid: process_state.parent_pid,
                            command,
                            args: exec_args,
                            env,
                        }),
                    });
                }
                _ => {}
            },
            super::Event::Signal { .. } => {}
            super::Event::Exited(event) => {
                let code = event.code()?;
                let did_stop_process = self
                    .alive_processes
                    .remove(&pid)
                    .is_some_and(|state| state.did_exec);
                if did_stop_process {
                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::StopProcess(StopProcessEvent::Exited {
                            code: code.as_i32(),
                        }),
                    });
                }
            }
            super::Event::KilledBy { signal_string } => {
                let signal = signal_string.split(" ").next().unwrap();
                let did_stop_process = self
                    .alive_processes
                    .remove(&pid)
                    .is_some_and(|state| state.did_exec);
                if did_stop_process {
                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::StopProcess(StopProcessEvent::Killed {
                            signal: Some(signal.value.to_string()),
                        }),
                    });
                }
            }
        }

        Ok(())
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
}

#[derive(Default)]
struct ProcessState {
    parent_pid: Option<Pid>,
    did_exec: bool,
}
