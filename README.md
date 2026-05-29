# ciprof

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
![platform: linux](https://img.shields.io/badge/platform-linux-blue)
![requires: eBPF](https://img.shields.io/badge/requires-eBPF-blueviolet)

**Zero-instrumentation build profiler for GitHub Actions.**

ciprof attaches eBPF probes to the kernel's process and TCP layers, auto-detects the Actions runner process, and at the end of your job emits a structured report showing where the build time actually went — network vs CPU vs process startup overhead — broken down by step.

> **TIP:** No changes to your repo required. Add two steps: one at the top, one at the bottom.

---

## Quick start

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

---

## What you get

```
╔══════════════════════════════════════════════════════════════════╗
║  ciprof  ·  ubuntu-latest  ·  total 4m 52s                      ║
╚══════════════════════════════════════════════════════════════════╝

STEPS
  ──────────────────────────────────────────────── wall    procs   net
  actions/checkout@v4                               0m 08s    14    2.1 MB
  npm ci                                            4m 12s  3241  340.8 MB
  npm test                                          0m 32s    43    6.2 MB
  ─────────────────────────────────────────────────────────────────
  total                                             4m 52s  3298  349.1 MB

NETWORK  (top destinations)
  registry.npmjs.org:443 ........... 847 conns  338.1 MB ↓   npm ci
  objects.githubusercontent.com:443   3 conns    2.1 MB ↓   checkout
  localhost:5432 ..................  156 conns    6.2 MB ↕   npm test

PROCESS OVERHEAD
  3,298 processes spawned  ·  median lifetime 38 ms
  top spawners:  npm (1,847)  node (892)  sh (431)  git (52)

OBSERVATIONS
  ⚠  npm ci spent an estimated 66% of step time on network.
     Consider actions/setup-node with cache: 'npm' to skip downloads.
  ✓  No unexpected outbound destinations detected.
```

---

## How it works

| Layer | Mechanism | What it captures |
|-------|-----------|-----------------|
| Process | `fentry/do_execveat_common` + `tp_btf/sched_process_exit` | Every exec/exit with PID, parent PID, command, argv |
| Network | `fentry/tcp_connect` + `fexit/inet_csk_accept` + `fentry/tcp_close` | Every TCP connection with bytes sent/received |
| Correlation | Parent-PID walk from runner process | Which step each process/connection belongs to |

Steps are identified as direct children of the Actions runner process. Each subsequent child closes the previous step and opens a new one.

---

## Options

```
--start                 Begin profiling, fork to background
--report                Signal daemon to stop and print the report
--json                  Emit JSON only (no terminal formatting)
--runner-pid <pid>      Override automatic runner PID detection
```

---

## Requirements

- Linux kernel 5.10+ (5.15+ recommended for fentry support)
- `CAP_BPF` / root — the runner has this on GitHub Actions `ubuntu-latest`
- `yeet` runtime installed
- `clang` + `bpftool` for building from source

---

## Honest caveats

- **Process timing is wall-clock**, not CPU time. A sleeping process counts the same as a computing one.
- **Network time is inferred** from bytes transferred, not measured directly. The "estimated X% network" observation is a heuristic.
- **Step boundaries** are detected from direct children of the runner PID. If the runner uses a thread pool or wrapper, attribution may be off.
- **Argv is capped at 128 bytes** from the kernel. Long command lines are truncated.
- **No reverse DNS.** Destinations are shown as `IP:port`. A future version could resolve them.
- **Overhead is negligible**: ~2µs per exec/exit event, ~1µs per TCP event.

---

## Build from source

```sh
make vmlinux    # generate include/vmlinux.h from running kernel
make            # compile ciprof.bpf.c -> bin/ciprof.bpf.o
```

Requires: `clang`, `bpftool`, kernel headers.

---

## License

MIT
