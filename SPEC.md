# ciprof — build profiler for GitHub Actions runners

## What it is

A zero-instrumentation system-level profiler for CI builds. It attaches eBPF
probes to the kernel's process and TCP layers, auto-detects the Actions runner
process, and at the end of the job emits a structured report showing where the
build time actually went — network vs CPU vs process startup overhead — broken
down by step.

No code changes required in the repo being built. Add one step at the top of
the job and one at the bottom.

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

The `--start` invocation forks into the background and writes its PID to
`/tmp/ciprof.pid`. The `--report` invocation signals it to flush and exit, then
renders the report to stdout and writes `ciprof-report.json` as a job artifact.

---

## Report format

```
╔══════════════════════════════════════════════════════════════════╗
║  ciprof  ·  build #1234  ·  ubuntu-latest  ·  total 4m 52s      ║
╚══════════════════════════════════════════════════════════════════╝

STEPS
  ─────────────────────────────────────────────── wall    procs   net
  actions/checkout@v4                              0m 08s    14    2.1 MB
  npm ci                                           4m 12s  3241  340.8 MB
  npm test                                         0m 32s    43    6.2 MB
  ───────────────────────────────────────────────────────────────────
  total                                            4m 52s  3298  349.1 MB

NETWORK  (top destinations)
  registry.npmjs.org:443 ........... 847 conns  338.1 MB ↓   npm ci
  objects.githubusercontent.com:443   3 conns    2.1 MB ↓   checkout
  localhost:5432 ..................  156 conns    6.2 MB ↕   npm test

PROCESS OVERHEAD
  3,298 processes spawned  ·  median lifetime 38 ms
  top spawners:  npm (1,847)  node (892)  sh (431)  git (52)

OBSERVATIONS
  ⚠  npm ci spent an estimated 2m 48s on network (66% of step time).
     Consider actions/setup-node with cache: 'npm' to skip downloads.
  ✓  No unexpected outbound destinations detected.
```

---

## Architecture

```
ciprof.bpf.c      eBPF: exec/exit tracking + TCP connect/close
main.js           entry point: arg parsing, BPF setup, daemon/report mode
state.js          process tree, step grouping, network accounting
report.js         terminal + JSON report rendering
format.js         shared formatting (bytes, duration, addresses)
Makefile          vmlinux.h generation, BPF compile
```

---

## BPF program design

### Event struct

```c
enum event_type {
    EV_EXEC    = 1,
    EV_EXIT    = 2,
    EV_CONNECT = 3,
    EV_CLOSE   = 4,
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    char  comm[16];
    char  argv[128];      // first 128 bytes of /proc/pid/cmdline, NUL-separated
    __u8  src_addr[16];   // IPv4 in first 4 bytes, IPv6 in all 16
    __u8  dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  is_ipv6;
    __u8  pad[3];
    __u64 bytes_sent;     // only on EV_CLOSE
    __u64 bytes_received; // only on EV_CLOSE
    __s32 exit_code;      // only on EV_EXIT
};

// Forces struct event into BTF for yeet's decoder.
struct event __event_dummy __attribute__((section("dummy"), unused)) = {};
```

### Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");
```

### Programs

**`fentry/do_execveat_common` (or `tp_btf/sched_process_exec` as fallback)**

Fires on every exec. Captures pid, ppid, comm, and the first 128 bytes of the
new process's argv from `current->mm->arg_start`. Use `bpf_probe_read_user`
to read the argv bytes. Emit EV_EXEC.

Note: `do_execveat_common` is the right fentry target on kernels 5.10+. On
older kernels fall back to `tp_btf/sched_process_exec`, which has less argv
context. The Makefile should probe for it the same way tcpsnoop probes for
fentry support.

**`tp_btf/sched_process_exit`**

Fires on process exit. Captures pid and exit code. Emit EV_EXIT.

**`fentry/tcp_connect`**

Same as tcpsnoop. Emit EV_CONNECT with src/dst addrs, ports, pid, comm.

**`fexit/inet_csk_accept`**

Same as tcpsnoop. Function signature on kernel 6.8+:
```c
int BPF_PROG(inet_csk_accept_exit,
             struct sock *sk, struct proto_accept_arg *arg,
             struct sock *ret_sock)
```
On older kernels:
```c
int BPF_PROG(inet_csk_accept_exit,
             struct sock *sk, int flags, int *err, bool kern,
             struct sock *ret_sock)
```
The Makefile should detect this by checking if `proto_accept_arg` is defined in
`include/vmlinux.h` and setting a `-DHAVE_PROTO_ACCEPT_ARG` flag.

**`fentry/tcp_close`**

Same as tcpsnoop. Reads `tcp_sock.bytes_sent` and `tcp_sock.bytes_received`.
Emit EV_CLOSE.

### Argv reading

```c
SEC("fentry/do_execveat_common")
int BPF_PROG(on_exec, ...)
{
    struct event *e = reserve();
    if (!e) return 0;
    e->type = EV_EXEC;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Read argv from mm->arg_start
    struct mm_struct *mm = BPF_CORE_READ(current, mm);
    unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
    bpf_probe_read_user(e->argv, sizeof(e->argv), (void *)arg_start);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

The argv bytes are NUL-separated (kernel layout of `/proc/pid/cmdline`).
Replace NUL bytes with spaces in JS to reconstruct the command string, up to
the first two NULs so you get `comm arg0 arg1` without the whole arg list.

---

## JS: main.js

### CLI

```
ciprof --start            begin profiling, fork to background, write PID to /tmp/ciprof.pid
ciprof --report           signal daemon to stop, wait, render report
ciprof --json             emit report as JSON only (for downstream tooling)
ciprof --output <file>    write JSON report to this path (default: ciprof-report.json)
```

### Daemon mode (`--start`)

1. Detect the runner PID: walk up from `yeet.args._runner_pid` if supplied, or
   read `$RUNNER_PID` from the environment (GitHub Actions sets this), or fall
   back to the parent of the current process via `yeet.graph.query` on the
   process tree (see graph API below).

2. Set up BPF:
   ```js
   import bpfObj from './bin/ciprof.bpf.o';
   import { RingBuf } from 'yeet:bpf';

   bpfObj.bind('events', { kind: 'ring_buf', btf_struct: 'event', capacity: 8192 });
   const ctl = await bpfObj.start();
   const sub = await new RingBuf(ctl, 'events').subscribe(onEvent, onError);
   ```

3. Write `ctl.id` and start timestamp to `/tmp/ciprof.state` so the report
   command can find them. Since yeet scripts can't write files directly, use
   `yeet.graph` or encode the state in the pid file name:
   `/tmp/ciprof-<ctlid>.pid`.

   Actually: the report step is a new isolate that can't share state with the
   daemon. The daemon should write a JSONL event log to a well-known path using
   a different mechanism. The simplest approach: emit the report from the daemon
   itself when it receives SIGTERM, and have `--report` just send SIGTERM to
   the PID in `/tmp/ciprof.pid`.

   The daemon listens for shutdown via a `setInterval` polling
   `/tmp/ciprof.stop` (written by `--report`). When it sees that file, it
   flushes and renders the report. This works because yeet scripts can read from
   `yeet.graph` for system state.

   Actually, simplest approach given yeet's constraints: the daemon writes
   accumulated state as JSONL events to stdout (console.log), which the runner
   captures in the Actions log. The `--report` command parses those logs from
   the Actions API.

   **Better**: keep it in-process. The daemon accumulates state in memory and
   renders the report on SIGINT/Ctrl-C. In Actions, the `--report` step runs
   `kill $(cat /tmp/ciprof.pid)` and waits, while the daemon outputs the report
   before exiting. This is clean and doesn't require IPC.

   Implementation: use a `setInterval` that polls for a signal file
   (`/tmp/ciprof.stop`) every 500ms. When detected, render report and call
   `yeet.exit()`.

4. Event loop runs until shutdown signal.

### Runner PID detection

```js
// Read parent PID from yeet graph
const { data } = await yeet.graph.query(`{
  process(pid: ${currentPid}) {
    parent { pid comm }
  }
}`);
const runnerPid = data.process.parent.pid;
```

If the graph doesn't expose this, fall back to reading `/proc/self/status` for
`PPid:` via a graph query for the raw procfs field, or accept `--runner-pid`
as a CLI arg.

In GitHub Actions, the environment variable `RUNNER_PID` may be available.
Check `yeet.args.runner_pid` first, then env detection, then parent detection.

### Step boundary detection

Each step in an Actions job is executed as a direct child of the runner process.
Steps run sequentially (no overlap), so direct children of `runnerPid` appear
one at a time.

In state.js, maintain:
```js
const steps = [];        // [{name, startTime, endTime, rootPid, procs, netBytes}]
let currentStep = null;
```

When an EV_EXEC event arrives with `ppid === runnerPid`, it's a new step root.
Close the previous step and open a new one.

Step names aren't available from the kernel — the runner process shows up as
`Runner.Worker` or a shell name. Label steps as `step-1`, `step-2`, etc. and
note the root command (`comm + argv`).

If the user sets `CIPROF_STEP_NAME` env var at the start of each step, the
daemon can read that from the exec's environment — but reading environment
variables from `do_execveat_common` is complex (needs walking the envp array).
Skip this for v1; numeric step labels are fine.

### Process tree accounting

```js
const procs = new Map(); // pid -> { comm, argv, ppid, startMs, endMs, exitCode }
const stepOf = new Map(); // pid -> stepIndex (propagated from parent)

function onEvent(raw) {
  const ev = raw.event;
  // ...
  if (type === EV_EXEC) {
    procs.set(pid, { comm, argv, ppid, startMs: Date.now() });
    // inherit step from parent
    const parentStep = stepOf.get(ppid) ?? currentStepIndex();
    stepOf.set(pid, parentStep);
  }
  if (type === EV_EXIT) {
    const p = procs.get(pid);
    if (p) { p.endMs = Date.now(); p.exitCode = ev.exit_code; }
  }
  // ...
}
```

### Network accounting

Per-connection state, keyed by `src:sport:dst:dport`:
```js
const conns = new Map(); // key -> { pid, stepIdx, dst, dstPort, startMs }
// On EV_CONNECT: open entry
// On EV_CLOSE: close entry, accumulate bytes into step
```

Per-step network totals:
```js
step.netBytesDown += ev.bytes_received;
step.netBytesUp   += ev.bytes_sent;
step.netDests.add(formatAddr(ev.dst_addr, ev.dst_port, ev.is_ipv6));
```

Global destination table for the network section of the report:
```js
const destStats = new Map(); // "host:port" -> { conns, bytesDown, bytesUp, steps: Set }
```

---

## JS: state.js

Exports:
```js
export function ingestEvent(raw)         // called from RingBuf subscriber
export function getReport(startMs)       // returns structured report object
```

Report object shape:
```js
{
  meta: {
    startMs, endMs, totalMs,
    runnerPid, hostname,
  },
  steps: [
    {
      index: 1,
      rootComm: "npm",
      rootArgv: "npm ci",
      wallMs: 252000,
      procCount: 3241,
      netBytesDown: 356483072,
      netBytesUp: 14096,
      topDests: ["registry.npmjs.org:443", ...],
    },
    ...
  ],
  network: [
    {
      dest: "registry.npmjs.org:443",
      connCount: 847,
      bytesDown: 354334720,
      bytesUp: 8192,
      stepIndices: [2],
    },
    ...
  ],
  processes: {
    total: 3298,
    medianLifetimeMs: 38,
    topComms: [["npm", 1847], ["node", 892], ["sh", 431]],
  },
  observations: [
    {
      level: "warn",
      message: "npm ci spent an estimated 66% of step time on network. Consider caching.",
    },
  ],
}
```

### Observations engine

Generate observations from the report data:

- If any step has >50% of its wall time attributable to network (heuristic:
  `netBytesDown > 10MB && wallMs > 60000 && netBytesDown/wallMs > 100KB/s`),
  suggest caching for the relevant package manager.
  Detect package manager from `rootComm`: `npm`/`pnpm`/`yarn` → suggest
  `actions/setup-node cache`; `pip`/`uv` → `actions/setup-python cache`;
  `cargo` → `Swatinem/rust-cache`; `go` → `actions/cache` for GOPATH.

- If any dest outside `*.github.com`, `*.githubusercontent.com`, `*.npmjs.org`,
  `*.pypi.org`, `crates.io`, `*.golang.org`, `*.docker.io` is hit, emit an
  info observation listing it (not a warning — just surfacing it).

- If process count > 5000, note that process startup overhead may be
  significant.

---

## JS: report.js

Two renderers:

**`renderTerminal(report)`** — ANSI-formatted string for stdout.
Use `style.*` from the yeet runtime. Follow the layout shown in the Report
Format section above. Keep it under 100 chars wide.

**`renderJson(report)`** — `JSON.stringify(report, null, 2)`. Written to
`ciprof-report.json` via... this is the tricky part. Yeet scripts can't write
files. Options:
- Print to stdout with a sentinel prefix (`CIPROF_JSON:` + base64) so the
  Actions log captures it, and provide a companion action that extracts it.
- Write via `yeet.graph` if there's a file-write capability there.
- Just print JSON to stdout when `--json` flag is set and let the user redirect.

Simplest: `console.log(JSON.stringify(report))` when `--json`, terminal render
otherwise. Advise users to redirect: `ciprof --report --json > ciprof.json`.

---

## JS: format.js

```js
export function formatBytes(n)           // "340.8 MB", "6.2 KB" etc
export function formatDuration(ms)       // "4m 12s", "0m 08s"
export function formatAddr(addrObj, port, isV6)  // "registry.npmjs.org:443" (no reverse DNS in yeet; use raw IP)
export function formatArgv(rawBytes)     // NUL-separated bytes -> "npm ci --prefer-offline"
```

Note: `addrObj` from yeet's BTF decoder is `{0: byte, 1: byte, ...}`, not an
array. Access bytes as `addrObj[i]`.

Note: `bytes_sent` and `bytes_received` arrive as BigInt. Convert with
`Number(BigInt(ev.bytes_sent ?? 0n))`.

---

## Makefile

Mirror tcpsnoop's Makefile exactly. Key targets:

```makefile
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX := include/vmlinux.h
BPF_OBJ := bin/ciprof.bpf.o

# Detect inet_csk_accept signature change (kernel 6.8+)
HAVE_PROTO_ACCEPT_ARG := $(shell grep -c 'proto_accept_arg' include/vmlinux.h 2>/dev/null || echo 0)
ifneq ($(strip $(HAVE_PROTO_ACCEPT_ARG)),0)
  BPF_CFLAGS += -DHAVE_PROTO_ACCEPT_ARG
endif
```

In `ciprof.bpf.c`:
```c
#ifdef HAVE_PROTO_ACCEPT_ARG
SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit,
             struct sock *sk, struct proto_accept_arg *arg,
             struct sock *ret_sock)
#else
SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit,
             struct sock *sk, int flags, int *err, bool kern,
             struct sock *ret_sock)
#endif
```

---

## Yeet API notes

These are non-obvious behaviors learned from building tcpsnoop — the agent
will need these:

**BPF object binding:**
```js
bpfObj.bind('events', { kind: 'ring_buf', btf_struct: 'event', capacity: 8192 });
```
`kind` and `btf_struct` are both required. `btf_struct` must match the C struct
name exactly (just `event`, not `struct event`).

**BTF export for the struct:**
The struct must appear in a dummy ELF section or it won't be in BTF and the
decoder won't know how to decode events:
```c
struct event __event_dummy __attribute__((section("dummy"), unused)) = {};
```
Do NOT use `__type(value, struct event)` in the ring buffer map definition —
that causes EINVAL on load.

**No `.attach()` calls needed for fentry/fexit programs.**
They auto-attach based on the `SEC()` annotation. Calling `.attach()` with
an empty spec causes a validation error.

**Event shape:**
Events arrive wrapped in the struct name:
```js
function onEvent(raw) {
  const ev = raw.event; // unwrap
  // ev.pid, ev.comm, etc.
}
```

**Address fields:**
Arrive as plain objects with numeric string keys, not arrays:
```js
// ev.dst_addr is {0: 93, 1: 184, 2: 216, 3: 34, ...}
function normalizeAddr(obj) {
  const arr = [];
  for (let i = 0; i < 16; i++) arr.push(obj[i] || 0);
  return arr;
}
```

**BigInt fields:**
`bytes_sent`, `bytes_received` arrive as BigInt:
```js
const sent = Number(BigInt(ev.bytes_sent ?? 0n));
```

**RingBuf subscription:**
```js
import { RingBuf } from 'yeet:bpf';
const ctl = await bpfObj.start();
const sub = await new RingBuf(ctl, 'events').subscribe(onEvent, onError);
// later:
await sub.unsubscribe();
await ctl.stop();
```

**No filesystem access.** Yeet scripts cannot read or write files. State
between `--start` and `--report` must be communicated via OS-level mechanisms
(signals, `/tmp` files written by the shell wrapper, etc.). The shell wrapper
script (`ciprof`) handles this:
```sh
#!/bin/sh
if [ "$1" = "--start" ]; then
  yeet run "$(dirname $0)/main.js" --start &
  echo $! > /tmp/ciprof.pid
elif [ "$1" = "--report" ]; then
  touch /tmp/ciprof.stop
  wait $(cat /tmp/ciprof.pid)
fi
```
The yeet script polls `/tmp/ciprof.stop` via... actually it can't read files
either. Use a different approach: the `--report` command kills the daemon with
SIGINT, and the daemon's `setInterval` shutdown handler runs. The shell wrapper
catches the exit and the daemon's stdout (the report) flows to the terminal
naturally.

The cleanest pattern: daemon runs until killed, renders report to stdout on
any exit. `--report` just does `kill $(cat /tmp/ciprof.pid)`.

**Timers:**
`setTimeout` and `setInterval` work. `Date.now()` works. No `performance.now()`.

---

## What to build / file list

```
ciprof.bpf.c
Makefile
format.js
state.js
report.js
main.js
ciprof          (shell wrapper, executable)
.gitignore      (bin/ include/)
README.md
```

The README should follow the same structure as tcpsnoop/fdsnoop/airtop:
badges, GIF placeholder, bold intro, TIP callout, quick start, primer,
use cases, what you're looking at, how it works table, options, requirements,
honest caveats, community questions, build instructions, license.

---

## Honest caveats (for README)

- Process timing is wall-clock from exec to exit, not CPU time. A process
  sleeping counts the same as one computing.
- Network time is inferred from bytes transferred, not measured directly.
  The "estimated X% network" observation is a heuristic.
- Step boundaries are detected from direct children of the runner PID. If the
  runner uses a thread pool or wrapper process, step attribution may be off.
- Argv is capped at 128 bytes from the kernel. Long command lines are truncated.
- The profiler itself adds a small overhead: ~2µs per exec/exit event, ~1µs
  per TCP event. Immeasurable on a typical build.
- No reverse DNS. Destinations are shown as IP:port. A future version could
  resolve them, but that requires network access from the script.
