use std::{
    borrow::Cow,
    collections::{HashSet, VecDeque},
};

use bstr::ByteSlice;

use crate::event::{Event, EventKind, ProcessExec, StopProcessEvent};

#[derive(Default)]
pub struct EventEmitter {
    alive_processes: HashSet<libc::pid_t>,
    events: VecDeque<Event>,
}

impl EventEmitter {
    pub fn push_line(&mut self, line: super::Line) {
        let timestamp = line.timestamp;
        let pid = line.pid;

        let is_new_process = self.alive_processes.insert(line.pid);
        if is_new_process {
            self.events.push_back(Event {
                timestamp,
                pid,
                kind: EventKind::StartProcess,
            });
        }

        match line.event {
            super::Event::Syscall {
                name,
                args,
                result: _,
                duration: _,
            } => match name.as_str() {
                "execve" => {
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

                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::ExecProcess(ProcessExec {
                            command,
                            args: exec_args,
                            env,
                        }),
                    });
                }
                "execveat" => {
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

                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::ExecProcess(ProcessExec {
                            command,
                            args: exec_args,
                            env,
                        }),
                    });
                }
                _ => {}
            },
            super::Event::Signal { .. } => {}
            super::Event::Exited { code } => {
                let did_remove = self.alive_processes.remove(&pid);
                if did_remove {
                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::StopProcess(StopProcessEvent::Exited {
                            code: code.as_i32(),
                        }),
                    });
                }
            }
            super::Event::KilledBy { signal } => {
                let did_remove = self.alive_processes.remove(&pid);
                if did_remove {
                    let signal = if let super::Value::Expression(signal) = signal {
                        Some(signal)
                    } else {
                        None
                    };

                    self.events.push_back(Event {
                        timestamp,
                        pid,
                        kind: EventKind::StopProcess(StopProcessEvent::Killed { signal }),
                    });
                }
            }
        }
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
}
