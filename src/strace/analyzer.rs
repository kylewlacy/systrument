use std::{borrow::Cow, collections::HashMap};

use bstr::ByteSlice;

use crate::{
    Pid,
    event::{
        Event, EventKind, ExecProcessEvent, ForkProcessEvent, ProcessExec, ProcessStoppedReason,
        StopProcessEvent,
    },
    strace::parser::StraceParseError,
};

#[derive(Default)]
pub struct Analyzer {
    processes: HashMap<Pid, ProcessState>,
}

impl Analyzer {
    pub fn analyze<'a>(&mut self, line: super::Line<'a>) -> Result<Event<'a>, StraceParseError> {
        let kind = match &line.event {
            super::Event::Syscall(event) => match event.name {
                "fork" | "vfork" | "clone" | "clone3" => {
                    let result = event.result()?;

                    let child_pid = result.returned.and_then(|value| value.as_i32());
                    child_pid.map_or(EventKind::Log, |child_pid| {
                        self.handle_fork(&line, child_pid)
                    })
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
                        &line,
                        ProcessExec {
                            command,
                            args: exec_args,
                            env,
                        },
                    )
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
                        &line,
                        ProcessExec {
                            command,
                            args: exec_args,
                            env,
                        },
                    )
                }
                _ => EventKind::Log,
            },
            super::Event::Signal { .. } => EventKind::Log,
            super::Event::Exited(event) => {
                let code = event.code()?;
                let stopped = ProcessStoppedReason::Exited {
                    code: code.as_i32(),
                };
                self.handle_stopped(&line, stopped)
            }
            super::Event::KilledBy { signal_string } => {
                let signal = signal_string.split(" ").next().unwrap();
                let stopped = ProcessStoppedReason::Killed {
                    signal: Some(signal.value.to_string()),
                };
                self.handle_stopped(&line, stopped)
            }
        };

        let process_state = self.processes.get(&line.pid);

        Ok(Event {
            kind,
            owner_pid: process_state.and_then(|state| state.owner_pid),
            parent_pid: process_state.and_then(|state| state.parent_pid),
            pid: line.pid,
            timestamp: line.timestamp,
            strace: line,
        })
    }

    fn handle_fork(&mut self, strace: &super::Line, child_pid: Pid) -> EventKind {
        let child_owner_pid = self.find_owner_pid(strace.pid);
        let child_process_state = self
            .processes
            .entry(child_pid)
            .or_insert_with(|| ProcessState {
                parent_pid: Some(strace.pid),
                owner_pid: child_owner_pid,
                status: ProcessStatus::Forked,
            });

        EventKind::ForkProcess(ForkProcessEvent {
            child_pid,
            child_owner_pid: child_process_state.owner_pid,
        })
    }

    fn handle_exec(&mut self, strace: &super::Line, exec: ProcessExec) -> EventKind {
        let process_state = self
            .processes
            .entry(strace.pid)
            .or_insert_with(|| ProcessState {
                parent_pid: None,
                owner_pid: None,
                status: ProcessStatus::Forked,
            });

        let re_exec = matches!(process_state.status, ProcessStatus::Execed);
        process_state.status = ProcessStatus::Execed;

        EventKind::ExecProcess(ExecProcessEvent { exec, re_exec })
    }

    fn handle_stopped(&mut self, strace: &super::Line, stopped: ProcessStoppedReason) -> EventKind {
        let process_state = self
            .processes
            .entry(strace.pid)
            .or_insert_with(|| ProcessState {
                parent_pid: None,
                owner_pid: None,
                status: ProcessStatus::Stopped,
            });
        let did_exec = matches!(process_state.status, ProcessStatus::Execed);
        process_state.status = ProcessStatus::Stopped;

        EventKind::StopProcess(StopProcessEvent { stopped, did_exec })
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
}

#[derive(Debug, Clone, Copy)]
struct ProcessState {
    parent_pid: Option<Pid>,
    owner_pid: Option<Pid>,
    status: ProcessStatus,
}

#[derive(Debug, Clone, Copy)]
enum ProcessStatus {
    Forked,
    Execed,
    Stopped,
}
