# systrument

systrument is a collection of tools for instrumenting processes. Currently, that means parsing strace output, and converting it to other formats for exploration.

## Installation

systrument is a bare-bones Rust project. After [installing Rust and Cargo](https://www.rust-lang.org/tools/install) and checking out the `systrument` repo, you can install systrument by running the following command within the repo:

```sh
cargo install --locked --path .
```

This will install the `systrument` executable.

> [!NOTE]
> You'll also need to make sure you have [`strace`](https://strace.io/) installed too!

## Usage

### `systrument record`

Run a command via strace. Records with appropriate defaults for later parsing.

```sh
systrument record -o bash.strace -- bash -c 'echo "hello world"'
```

Can be used to convert the output to Perfetto or OpenTelemetry as well without doing a separate conversion.


```sh
systrument record --output-perfetto bash.pftrace --otel -- bash -c 'echo "hello world"'
```

By default, only file and process syscalls are recorded. Pass `--all` to record all syscalls. Or check ["Supported strace output"](#supported-strace-output) below for details on how to call strace directly for more control.

### `systrument strace2perfetto`

Convert strace output to a Perfetto binary `.pftrace` file, which can then be loaded via the [Perfetto UI](https://ui.perfetto.dev/).

![Perfetto UI, showing the process `brioche` with lots of nested subprocesses](.github/screenshots/perfetto.png)

```sh
systrument strace2perfetto bash.strace -o bash.pftrace
```

Pass `--logs` to also include the strace output as Perfetto logs (shows up under the "Android logs" tab in the Perfetto UI).

### `systrument strace2otel`

Parse strace output and write traces / spans for proceses to an OpenTelemetry OTLP endpoint (Grafana Tempo, Jaeger, etc.).

Any OpenTelemetry provider should work. For a simple out-of-the-box experience, consider my <https://github.com/kylewlacy/docker-otel-lgtm> fork (forked from Grafana's `docker-otel-lgtm` with higher resource limits, since systrument can write a lot of data really fast to OTLP endpoints!)

![Grafana Tempo UI, showing the process `brioche` with lots of nested subprocesses](.github/screenshots/grafana-tempo.png)

```sh
systrument strace2otel bash.strace
```

Currently only supports the OTLP HTTP protocol. Follows the OpenTelemetry SDK conventions and writes to the OTLP endpoint `http://localhost:4318` by default. Set the environment variable `$OTEL_EXPORTER_OTLP_ENDPOINT` to control the endpoint explicitly.

By default, timestamps from the strace file are used, but some OTLP providers may drop old data, including Grafana Tempo. Pass `--relative-to-now` to adjust the timestamps relative to the current time (durations are still preserved).

Only traces and spans for subprocesses are written by default. Pass `--logs` to also send OpenTelemetry logs.


## Supported strace output

strace's output is complex! To keep things simple, systrument only supports parsing a subset of the strace output format. The output from `systrument record` is always supported of course, but doesn't offer much customization over what syscalls are recorded.

If you run strace manually, here are the recommended flags to use:

```sh
strace --seccomp-bpf -fe 'status=!unfinished' -Ttttyyv -s 4096 -- command
```

Additional filters can also be passed with `-e`. If you're only recording a subset of syscalls, you should also at least include `-e trace=process` to record process syscalls (`fork`, `execve`, etc.).

Different status filters can be used, but unfinished log lines currently can't be parsed.

`-f` (`--follow-forks`) can also be omitted, but `--always-show-pid` must then be used.

`--seccomp-bpf` isn't actually required, but makes traced processes run much more quickly when only some syscalls are captured!
