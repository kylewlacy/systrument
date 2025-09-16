use bstr::ByteSlice as _;

use crate::Pid;

#[derive(Debug)]
pub struct Event {
    pub timestamp: jiff::Timestamp,
    pub pid: Pid,
    pub owner_pid: Option<Pid>,
    pub log: String,
    pub kind: EventKind,
}

#[derive(Debug)]
pub enum EventKind {
    StartProcess(StartProcessEvent),
    StopProcess(StopProcessEvent),
    Log,
}

#[derive(Debug, Default)]
pub struct StartProcessEvent {
    pub parent_pid: Option<i32>,
    pub owner_pid: Option<i32>,
    pub command: Option<bstr::BString>,
    pub args: Option<Vec<bstr::BString>>,
    pub env: Option<Vec<(bstr::BString, bstr::BString)>>,
}

impl StartProcessEvent {
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

#[derive(Debug)]
pub enum StopProcessEvent {
    Exited { code: Option<i32> },
    Killed { signal: Option<String> },
    ReExeced,
}
