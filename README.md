# `ciprof`

> **tcpdump for your CI bill.** Where did the four minutes go?

<!-- badges: Linux · yeet · eBPF (GPL) · CI profiling -->

![demo screenshot (required, lives in assets/)](assets/ciprof.gif)

**`ciprof` is a zero-instrumentation build profiler for GitHub Actions that attaches eBPF probes to the kernel's process and TCP layers and, at the end of a job, reports where the wall-clock time actually went, broken down by step into network, process spawn, and bytes transferred.**

> [!TIP]
> No code changes, no wrapper around your commands, no language-specific agent. ciprof watches every `exec`, `exit`, and TCP connection from the kernel side and attributes each one to the step that caused it by walking the parent-PID chain back to the Actions runner.

## Quick start

Add two steps to your job: one to start profiling, one to print the report.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Start ciprof
        run: yeet run https://github.com/yeet-src/ciprof -- --start

      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test

      - name: ciprof report
        if: always()
        run: yeet run https://github.com/yeet-src/ciprof -- --report
```

`--json` emits the report as structured JSON instead of the terminal view, handy for uploading as an artifact or diffing across runs. `--runner-pid <pid>` overrides automatic runner detection if your job uses a non-standard wrapper.

## A 60-second primer on CI profiling with eBPF

The slow part of a CI job is usually invisible. A green check tells you the job took four minutes; it doesn't tell you that three of them were `npm` pulling 340 MB from a registry. Traditional profilers want you to instrument your code, but a CI job isn't your code, it's a pile of shell steps spawning hundreds of processes that each do their own thing.

eBPF sidesteps this. Instead of instrumenting anything, you attach small programs to kernel hook points and watch the events flow past. The vocabulary you need for the rest of this README:

| Term | What it means here |
|---|---|
| **exec / exit** | the kernel events fired when a process starts (`execve`) and ends. Counting these tells you how many processes a step spawned and how long they lived. |
| **fentry / fexit** | eBPF program types that attach to the entry and exit of a kernel function with near-zero overhead. ciprof uses them on `tcp_connect` and `tcp_close`. |
| **tracepoint (tp_btf)** | a stable, named kernel instrumentation point. ciprof uses `sched_process_exec` and `sched_process_exit`. |
| **runner PID** | the process ID of the GitHub Actions runner. Every step runs as a direct child of it, which is how ciprof figures out which step a given process or connection belongs to. |

The trick is correlation: a TCP connection happens deep inside some `node` subprocess, but its parent chain leads back to the runner, and the runner child it descends from is the step. Walk the chain, attribute the bytes.

## Common use cases

Mostly platform engineers shaving minutes off CI for the whole org, and individual developers staring at a job that's mysteriously slow.

- Your CI job takes four minutes and you don't know why. Where did the time actually go?
- A workflow got slower last week. Was it more network, more processes, or a single step?
- You suspect dependency downloads dominate the build. How many megabytes, and from where?
- You want to know what your CI talks to over the network. Any outbound destinations you didn't expect?

## What you're looking at

The report has four blocks, top to bottom.

The **STEPS** table is the headline: one row per step, with wall-clock time, processes spawned, and bytes moved. A step that's high on `net` is download-bound; a step high on `procs` with low `net` is spawn-bound (lots of short-lived shells and tool invocations). In the sample run, `npm ci` is 4m 12s of a 4m 52s job and moved 340 MB, so it owns the build, and it owns it on the network.

The **NETWORK** block ranks destinations by bytes, with the step each belongs to. `registry.npmjs.org:443 ... 338.1 MB ↓` under `npm ci` is the smoking gun: nearly the entire job's traffic is one registry pulling packages. The `↓` / `↑` / `↕` arrows show direction (down, up, both).

The **PROCESS OVERHEAD** block counts total processes and median lifetime, then lists top spawners by command name. A median lifetime of 38 ms across 3,298 processes tells you the job is paying a lot of fork/exec tax, which is typical of `npm` and worth knowing before you reach for a bigger runner.

The **OBSERVATIONS** block is heuristic commentary, not measurement. A `⚠` flags a likely win (here: cache your npm downloads); a `✓` confirms something benign (no unexpected outbound destinations). Treat these as hints, not verdicts; the numbers above them are the ground truth.

## How it works

- **The BPF side.** Four attach points, emitting events into a ring buffer:

  | Hook | Type | Captures |
  |---|---|---|
  | `sched_process_exec` | `tp_btf` | every exec: PID, parent PID, command, argv (capped at 128 bytes) |
  | `sched_process_exit` | `tp_btf` | every thread-group leader exit, for process lifetime and count |
  | `tcp_connect` | `fentry` | outbound connections, with source and destination addr/port (v4 and v6) |
  | `tcp_close` | `fentry` | connection teardown, with bytes sent and received from `tcp_sock` |

- **The JS side.** A yeet script subscribes to the ring buffer via `yeet:bpf`, keeps a live map of PID to step, and on `--report` aggregates the accumulated events into the four report blocks and renders them. `--json` skips rendering and dumps the aggregated structure.

- **The data flow.** Steps are identified as direct children of the runner PID. The first child opens step one; each subsequent direct child closes the previous step and opens the next. Every exec and TCP event is attributed to the open step by walking its parent chain back to a known runner child.

## Requirements

> [!IMPORTANT]
> Needs a kernel built with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and `fentry`/`fexit` support, which in practice means Linux 5.10+ (5.15+ recommended). GitHub Actions `ubuntu-latest` satisfies this today and the runner already has the `CAP_BPF` privilege the load requires.

The yeet daemon, which handles the privileged BPF load. `curl -fsSL https://yeet.cx | sh` installs it.

## Honest caveats

> [!NOTE]
> ciprof measures wall-clock and bytes, not CPU and not latency. Read the report as "where did the time and the traffic go," not "what was the machine doing."

- Process timing is wall-clock, not CPU time. A sleeping process and a compute-bound one count the same.
- Network time is inferred from bytes transferred, not measured directly. The "estimated X% network" line in OBSERVATIONS is a heuristic, not a stopwatch.
- Step boundaries come from direct children of the runner PID. If your job uses a thread pool, a custom wrapper, or re-parents work, attribution can land on the wrong step. Use `--runner-pid` to correct detection.
- argv is capped at 128 bytes in the kernel, so long command lines are truncated in the process listing.
- Destinations may be shown as `IP:port` with no reverse DNS.

## Community questions

**Do I need to change my workflow's commands or add an agent?**
No. You add two steps (`--start` and `--report`) and leave every other step untouched. ciprof watches from the kernel, so it doesn't care what language your build is in or how your commands are written.

**Will the probes slow my build down?**
No measurably. Overhead is roughly 2µs per exec/exit event and 1µs per TCP event. A job spawning thousands of processes pays single-digit milliseconds total.

**Why is a step's time attributed to the wrong place, or why don't I see a step?**
Step boundaries are inferred from direct children of the runner PID. Wrappers, thread pools, or re-parented work can blur the boundary. Pass `--runner-pid <pid>` to pin detection to the right process.

**Is it safe to run this on shared CI infrastructure, and does it see other jobs?**
ciprof only attributes events that descend from the runner PID it's watching, so it reports on your job, not co-tenants. It does observe kernel-wide exec and TCP events to do that filtering, so run it only on runners you control or are authorized to profile.

**How is this different from `time`, `strace`, or step timing in the Actions UI?**
The Actions UI gives you per-step wall-clock and nothing underneath it. `time` measures one command. `strace` is per-process, heavy, and says nothing about the network. ciprof gives you the whole job at once: every process and every connection, attributed to a step, with bytes and destinations, at a fraction of `strace`'s overhead because it reads kernel events rather than trapping syscalls.

## Building from source

```sh
make vmlinux  # generate include/vmlinux.h from the running kernel's BTF
make          # compile ciprof.bpf.c -> bin/ciprof.bpf.o
make clean
```

Requires clang for the BPF object, bpftool for `vmlinux.h` generation, and kernel headers. The generated `vmlinux.h` and `bin/` are gitignored because they're host-specific build artifacts.

## License

GPL-2.0. The BPF program declares `SEC("license") = "GPL"` because it calls GPL-only kernel helpers; this is required for the probes to load. The rest of the repository is GPL-2.0 to match.

---

Built with [yeet](https://yeet.cx/?utm_source=github&utm_medium=readme&utm_campaign=ciprof), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/dYZu9PjKB?utm_source=github&utm_medium=readme&utm_campaign=ciprof).
