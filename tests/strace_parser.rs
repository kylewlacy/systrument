use systrument::strace::{Event, SyscallEvent};

fn parse_strace_line(
    line: &'_ str,
) -> Result<systrument::strace::Line<'_>, systrument::strace::parser::ParseLineError> {
    systrument::strace::parser::parse_line(
        line,
        &systrument::strace::LineSourceLocation {
            filename: "<test>",
            line_index: 0,
        },
    )
}

fn syscall_event(event: Event) -> miette::Result<SyscallEvent> {
    let Event::Syscall(event) = event else {
        miette::bail!("expected syscall event, got {event:?}");
    };
    Ok(event)
}

fn parse_strace_line_syscall(line: &'_ str) -> miette::Result<SyscallEvent<'_>> {
    let strace = parse_strace_line(line)?;
    let syscall = syscall_event(strace.event)?;
    Ok(syscall)
}

#[test]
fn test_strace_parse_line_basic() {
    let strace =
        parse_strace_line("2391133 1757048541.498563 brk(NULL)     = 0x555589aac000 <0.000007>")
            .unwrap();
    assert_eq!(strace.pid, 2391133);
    assert_eq!(
        strace.timestamp,
        jiff::Timestamp::constant(1757048541, 498563000),
    );
    let syscall = syscall_event(strace.event).unwrap();
    assert_eq!(syscall.name, "brk");
    assert_eq!(syscall.args.value, "NULL");
    assert_eq!(syscall.result, "0x555589aac000");
    assert_eq!(syscall.duration, std::time::Duration::from_micros(7));

    let strace = parse_strace_line(
        "1234 1757048541 syscall_0xbad() = -1 ENOSYS (Function not implemented) <123>",
    )
    .unwrap();
    assert_eq!(strace.pid, 1234);
    assert_eq!(strace.timestamp, jiff::Timestamp::constant(1757048541, 0),);
    let syscall = syscall_event(strace.event).unwrap();
    assert_eq!(syscall.name, "syscall_0xbad");
    assert_eq!(syscall.args.value, "");
    assert_eq!(syscall.result, "-1 ENOSYS (Function not implemented)");
    assert_eq!(syscall.duration, std::time::Duration::from_secs(123));

    let strace = parse_strace_line("37755 1757467412.646253 +++ killed by SIGTERM +++").unwrap();
    assert_eq!(strace.pid, 37755);
    assert_eq!(
        strace.timestamp,
        jiff::Timestamp::constant(1757467412, 646253000),
    );
    let Event::KilledBy { signal } = strace.event else {
        panic!("expected killed-by event, got {:?}", strace.event);
    };
    assert_eq!(signal, "SIGTERM");

    let strace = parse_strace_line("37755 1757467412.646253 +++ killed by SIGTERM +++").unwrap();
    assert_eq!(strace.pid, 37755);
    assert_eq!(
        strace.timestamp,
        jiff::Timestamp::constant(1757467412, 646253000),
    );
    let Event::KilledBy { signal } = strace.event else {
        panic!("expected killed-by event, got {:?}", strace.event);
    };
    assert_eq!(signal, "SIGTERM");

    let strace = parse_strace_line("37755 1757467412.646087 --- SIGTERM {si_signo=SIGTERM, si_code=SI_USER, si_pid=37799, si_uid=1000} ---").unwrap();
    assert_eq!(strace.pid, 37755);
    assert_eq!(
        strace.timestamp,
        jiff::Timestamp::constant(1757467412, 646087000),
    );
    let Event::Signal { signal } = strace.event else {
        panic!("expected signal event, got {:?}", strace.event);
    };
    assert_eq!(
        signal,
        "SIGTERM {si_signo=SIGTERM, si_code=SI_USER, si_pid=37799, si_uid=1000}"
    );
}

#[test]
fn test_strace_parse_line_examples() {
    let syscall = parse_strace_line_syscall(
        "2386219 1757048486.908740 fstat(3</dev/urandom<char 1:9>>, {st_dev=makedev(0, 0x6), st_ino=9, st_mode=S_IFCHR|0666, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=0, st_rdev=makedev(0x1, 0x9), st_atime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */, st_atime_nsec=972352920, st_mtime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */, st_mtime_nsec=972352920, st_ctime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */, st_ctime_nsec=972352920}) = 0 <0.000008>",
    )
    .unwrap();
    assert_eq!(syscall.name, "fstat");
    assert_eq!(
        syscall.args.value,
        "3</dev/urandom<char 1:9>>, {st_dev=makedev(0, 0x6), st_ino=9, st_mode=S_IFCHR|0666, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=0, st_rdev=makedev(0x1, 0x9), st_atime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */, st_atime_nsec=972352920, st_mtime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */, st_mtime_nsec=972352920, st_ctime=1755889791 /* 2025-08-22T12:09:51.972352920-0700 */, st_ctime_nsec=972352920}"
    );
    assert_eq!(syscall.result, "0");

    let syscall = parse_strace_line_syscall("2386273 1757048575.815138 close(15</var/home/kyle/.local/share/brioche/brioche.db-shm>(deleted)) = 0 <0.000083>").unwrap();
    assert_eq!(syscall.name, "close");
    assert_eq!(
        syscall.args.value,
        "15</var/home/kyle/.local/share/brioche/brioche.db-shm>(deleted)"
    );
    assert_eq!(syscall.result, "0");

    let syscall = parse_strace_line_syscall(
        "2386236 1757048490.393433 futex(0x7f299461a648, FUTEX_WAIT_PRIVATE, 1, NULL) = ? ERESTARTSYS (To be restarted if SA_RESTART is set) <85.383775>",
    ).unwrap();
    assert_eq!(syscall.name, "futex");
    assert_eq!(
        syscall.args.value,
        "0x7f299461a648, FUTEX_WAIT_PRIVATE, 1, NULL"
    );
    assert_eq!(
        syscall.result,
        "? ERESTARTSYS (To be restarted if SA_RESTART is set)"
    );

    let syscall = parse_strace_line_syscall(
        "2386276 1757048489.047729 clone(child_stack=0x7f2934be37d0, flags=CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET|SIGCHLD) = 2386283 <0.001704>",
    ).unwrap();
    assert_eq!(syscall.name, "clone");
    assert_eq!(
        syscall.args.value,
        "child_stack=0x7f2934be37d0, flags=CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET|SIGCHLD"
    );
    assert_eq!(syscall.result, "2386283");

    let syscall = parse_strace_line_syscall(r#"2386272 1757048488.670037 connect(16<UNIX-STREAM:[167063691]>, {sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 42) = 0 <0.000020>"#).unwrap();
    assert_eq!(syscall.name, "connect");
    assert_eq!(
        syscall.args.value,
        r#"16<UNIX-STREAM:[167063691]>, {sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 42"#
    );
    assert_eq!(syscall.result, "0");

    let syscall = parse_strace_line_syscall(r#"2386272 1757048488.670128 sendto(16<UNIX-STREAM:[167063691->167059833]>, "{\"method\":\"io.systemd.Resolve.ResolveHostname\",\"parameters\":{\"name\":\"cache.brioche.dev\",\"flags\":0}}\0", 100, MSG_DONTWAIT|MSG_NOSIGNAL, NULL, 0) = 100 <0.000010>"#).unwrap();
    assert_eq!(syscall.name, "sendto");
    assert_eq!(
        syscall.args.value,
        r#"16<UNIX-STREAM:[167063691->167059833]>, "{\"method\":\"io.systemd.Resolve.ResolveHostname\",\"parameters\":{\"name\":\"cache.brioche.dev\",\"flags\":0}}\0", 100, MSG_DONTWAIT|MSG_NOSIGNAL, NULL, 0"#
    );
    assert_eq!(syscall.result, "100");

    let syscall = parse_strace_line_syscall("2386272 1757048488.670247 ppoll([{fd=16<UNIX-STREAM:[167063691->167059833]>, events=POLLIN}], 1, {tv_sec=119, tv_nsec=999966000}, NULL, 8) = 1 ([{fd=16, revents=POLLIN}], left {tv_sec=119, tv_nsec=999799867}) <0.000174>").unwrap();
    assert_eq!(syscall.name, "ppoll");
    assert_eq!(
        syscall.args.value,
        "[{fd=16<UNIX-STREAM:[167063691->167059833]>, events=POLLIN}], 1, {tv_sec=119, tv_nsec=999966000}, NULL, 8"
    );
    assert_eq!(
        syscall.result,
        "1 ([{fd=16, revents=POLLIN}], left {tv_sec=119, tv_nsec=999799867})"
    );

    let syscall = parse_strace_line_syscall(r#"2386272 1757048488.670449 recvfrom(16<UNIX-STREAM:[167063691->167059833]>, "{\"parameters\":{\"addresses\":[{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,100,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,104,21,64,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,100,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]}],\"name\":\"cache.brioche.dev\",\"flags\":1048577}}\0", 131080, MSG_DONTWAIT, NULL, NULL) = 965 <0.000009>"#).unwrap();
    assert_eq!(syscall.name, "recvfrom");
    assert_eq!(
        syscall.args.value,
        r#"16<UNIX-STREAM:[167063691->167059833]>, "{\"parameters\":{\"addresses\":[{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,100,1]},{\"ifindex\":2,\"family\":2,\"address\":[127,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,104,21,64,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,100,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]},{\"ifindex\":2,\"family\":10,\"address\":[32,1,219,8,1,10,0,0,0,0,0,0,100,10,10,1]}],\"name\":\"cache.brioche.dev\",\"flags\":1048577}}\0", 131080, MSG_DONTWAIT, NULL, NULL"#
    );
    assert_eq!(syscall.result, "965");

    let syscall = parse_strace_line_syscall("2386272 1757048488.670902 sendto(16<NETLINK:[ROUTE:2386219]>, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1757048488, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20 <0.000021>").unwrap();
    assert_eq!(syscall.name, "sendto");
    assert_eq!(
        syscall.args.value,
        "16<NETLINK:[ROUTE:2386219]>, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1757048488, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12"
    );
    assert_eq!(syscall.result, "20");

    let syscall = parse_strace_line_syscall(r#"2386272 1757048488.671755 getsockname(16<UDP:[192.168.1.203:56186->127.10.10.1:0]>, {sa_family=AF_INET, sin_port=htons(56186), sin_addr=inet_addr("192.168.1.203")}, [28 => 16]) = 0 <0.000012>"#).unwrap();
    assert_eq!(syscall.name, "getsockname");
    assert_eq!(
        syscall.args.value,
        r#"16<UDP:[192.168.1.203:56186->127.10.10.1:0]>, {sa_family=AF_INET, sin_port=htons(56186), sin_addr=inet_addr("192.168.1.203")}, [28 => 16]"#
    );
    assert_eq!(syscall.result, "0");

    let syscall = parse_strace_line_syscall(r#"2386272 1757048488.672892 connect(16<UDPv6:[[2001:db8:1000:1000:1000:100:100:1000]:41629->[2001:db8:1000::1000:1000]:0]>, {sa_family=AF_UNSPEC, sa_data="\0\0\0\0\0\0\0\0\0\0\0\0\0\0"}, 16) = 0 <0.000011>"#).unwrap();
    assert_eq!(syscall.name, "connect");
    assert_eq!(
        syscall.args.value,
        r#"16<UDPv6:[[2001:db8:1000:1000:1000:100:100:1000]:41629->[2001:db8:1000::1000:1000]:0]>, {sa_family=AF_UNSPEC, sa_data="\0\0\0\0\0\0\0\0\0\0\0\0\0\0"}, 16"#
    );
    assert_eq!(syscall.result, "0");
}
