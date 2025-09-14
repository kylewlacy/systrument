pub mod event;
pub mod otel;
pub mod perfetto;
pub mod strace;
pub mod utils;

pub type Pid = libc::pid_t;
