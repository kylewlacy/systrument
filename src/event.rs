use bstr::ByteSlice as _;

use crate::Pid;

#[derive(Debug, Clone)]
pub struct Event<'a> {
    pub timestamp: jiff::Timestamp,
    pub pid: Pid,
    pub parent_pid: Option<Pid>,
    pub owner_pid: Option<Pid>,
    pub strace: crate::strace::Line<'a>,
    pub kind: EventKind,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    ForkProcess(ForkProcessEvent),
    ExecProcess(ExecProcessEvent),
    StopProcess(StopProcessEvent),
    Log,
}

#[derive(Debug, Default, Clone)]
pub struct ForkProcessEvent {
    pub child_pid: Pid,
    pub child_owner_pid: Option<Pid>,
}

#[derive(Debug, Default, Clone)]
pub struct ExecProcessEvent {
    pub exec: ProcessExec,
    pub re_exec: bool,
}

#[derive(Debug, Default, Clone)]
pub struct ProcessExec {
    pub command: Option<bstr::BString>,
    pub args: Option<Vec<bstr::BString>>,
    pub env: Option<Vec<(bstr::BString, bstr::BString)>>,
}

impl ProcessExec {
    pub fn command_name(&self) -> Option<&bstr::BStr> {
        let command = self.command.as_ref()?;
        let name = if let Some((_, name)) = command.rsplit_once_str("/") {
            name
        } else {
            command
        };
        Some(bstr::BStr::new(name))
    }
}

#[derive(Debug, Clone)]
pub struct StopProcessEvent {
    pub stopped: ProcessStoppedReason,
    pub did_exec: bool,
}

#[derive(Debug, Clone)]
pub enum ProcessStoppedReason {
    Exited { code: Option<i32> },
    Killed { signal: Option<String> },
}
