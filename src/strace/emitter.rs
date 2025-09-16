use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
};

use bstr::ByteSlice;

use crate::{
    Pid,
    event::{Event, EventKind, StartProcessEvent, StopProcessEvent},
    strace::parser::StraceParseError,
};

#[derive(Default)]
pub struct EventEmitter {
    processes: HashMap<Pid, ProcessState>,
    events: VecDeque<Event>,
}

impl EventEmitter {
    pub fn push_line(&mut self, line: super::Line, log: String) -> Result<(), StraceParseError> {
        let ctx = EventContext {
            log,
            pid: line.pid,
            timestamp: line.timestamp,
        };

        match line.event {
            super::Event::Syscall(event) => match event.name {
                "fork" | "vfork" | "clone" | "clone3" => {
                    let result = event.result()?;

                    let child_pid = result.returned.and_then(|value| value.as_i32());
                    self.handle_fork(ctx, child_pid);
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

                    self.handle_exec(
                        ctx,
                        ProcessExec {
                            command,
                            args: exec_args,
                            env,
                        },
                    );
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

                    self.handle_exec(
                        ctx,
                        ProcessExec {
                            command,
                            args: exec_args,
                            env,
                        },
                    );
                }
                _ => {
                    self.handle_log(ctx);
                }
            },
            super::Event::Signal { .. } => {
                self.handle_log(ctx);
            }
            super::Event::Exited(event) => {
                let code = event.code()?;
                let stopped = StopProcessEvent::Exited {
                    code: code.as_i32(),
                };
                self.handle_stopped(ctx, stopped);
            }
            super::Event::KilledBy { signal_string } => {
                let signal = signal_string.split(" ").next().unwrap();
                let stopped = StopProcessEvent::Killed {
                    signal: Some(signal.value.to_string()),
                };
                self.handle_stopped(ctx, stopped);
            }
        }

        Ok(())
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn handle_fork(&mut self, ctx: EventContext, child_pid: Option<i32>) {
        if let Some(child_pid) = child_pid {
            let owner_pid = self.find_owner_pid(ctx.pid);

            self.processes
                .entry(child_pid)
                .or_insert_with(|| ProcessState {
                    parent_pid: Some(ctx.pid),
                    owner_pid,
                    status: ProcessStatus::Forked,
                });
        }

        self.handle_log(ctx);
    }

    fn handle_exec(&mut self, ctx: EventContext, exec: ProcessExec) {
        let process_state = self
            .processes
            .entry(ctx.pid)
            .or_insert_with(|| ProcessState {
                parent_pid: None,
                owner_pid: None,
                status: ProcessStatus::Forked,
            });

        if matches!(process_state.status, ProcessStatus::Execed) {
            self.events.push_back(Event {
                timestamp: ctx.timestamp,
                pid: ctx.pid,
                owner_pid: process_state.owner_pid,
                log: ctx.log.clone(),
                kind: EventKind::StopProcess(StopProcessEvent::ReExeced),
            });
        }
        process_state.status = ProcessStatus::Execed;

        self.events.push_back(Event {
            timestamp: ctx.timestamp,
            pid: ctx.pid,
            owner_pid: process_state.owner_pid,
            log: ctx.log,
            kind: EventKind::StartProcess(StartProcessEvent {
                parent_pid: process_state.parent_pid,
                owner_pid: process_state.owner_pid,
                command: exec.command,
                args: exec.args,
                env: exec.env,
            }),
        });
    }

    fn handle_stopped(&mut self, ctx: EventContext, stopped: StopProcessEvent) {
        let process_state = self
            .processes
            .entry(ctx.pid)
            .or_insert_with(|| ProcessState {
                parent_pid: None,
                owner_pid: None,
                status: ProcessStatus::Stopped,
            });
        let did_exec = matches!(process_state.status, ProcessStatus::Execed);
        process_state.status = ProcessStatus::Stopped;

        if did_exec {
            self.events.push_back(Event {
                timestamp: ctx.timestamp,
                pid: ctx.pid,
                owner_pid: process_state.owner_pid,
                log: ctx.log,
                kind: EventKind::StopProcess(stopped),
            });
        } else {
            self.handle_log(ctx);
        }
    }

    fn find_owner_pid(&self, mut pid: Pid) -> Option<Pid> {
        loop {
            let Some(process_state) = self.processes.get(&pid) else {
                break None;
            };

            if matches!(process_state.status, ProcessStatus::Execed) {
                break Some(pid);
            }

            let Some(parent_pid) = process_state.parent_pid else {
                break None;
            };
            pid = parent_pid;
        }
    }

    fn handle_log(&mut self, ctx: EventContext) {
        let process_state = self.processes.get(&ctx.pid);
        let owner_pid = process_state.and_then(|process_state| process_state.owner_pid);

        self.events.push_back(Event {
            timestamp: ctx.timestamp,
            pid: ctx.pid,
            owner_pid,
            log: ctx.log,
            kind: EventKind::Log,
        });
    }
}

struct ProcessState {
    parent_pid: Option<Pid>,
    owner_pid: Option<Pid>,
    status: ProcessStatus,
}

enum ProcessStatus {
    Forked,
    Execed,
    Stopped,
}

struct EventContext {
    timestamp: jiff::Timestamp,
    pid: Pid,
    log: String,
}

struct ProcessExec {
    command: Option<bstr::BString>,
    args: Option<Vec<bstr::BString>>,
    env: Option<Vec<(bstr::BString, bstr::BString)>>,
}
