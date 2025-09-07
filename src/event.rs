#[derive(Debug)]
pub struct Event {
    pub timestamp: jiff::Timestamp,
    pub pid: libc::pid_t,
    pub kind: EventKind,
}

#[derive(Debug)]
pub enum EventKind {
    StartProcess,
    StopProcess(StopProcessEvent),
    ExecProcess(ProcessExec),
}

#[derive(Debug)]
pub struct ProcessExec {
    pub command: Option<bstr::BString>,
    pub args: Option<Vec<bstr::BString>>,
    pub env: Option<Vec<(bstr::BString, bstr::BString)>>,
}

#[derive(Debug)]
pub enum StopProcessEvent {
    Exited { code: Option<i32> },
    Killed { signal: Option<String> },
}
