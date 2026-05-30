import { formatAddr, formatArgv, formatNumber } from './format.js';

const EV_EXEC    = 1;
const EV_EXIT    = 2;
const EV_CONNECT = 3;
const EV_CLOSE   = 4;

// Network heuristic thresholds
const NET_BYTES_THRESHOLD  = 10 * 1024 * 1024; // 10 MB
const NET_WALL_THRESHOLD   = 60_000;            // 60s
const NET_RATE_THRESHOLD   = 100 * 1024;        // 100 KB/s

const KNOWN_DESTINATIONS = [
    /\.github\.com$/,
    /\.githubusercontent\.com$/,
    /\.npmjs\.org$/,
    /\.npmjs\.com$/,
    /\.pypi\.org$/,
    /^crates\.io$/,
    /\.golang\.org$/,
    /\.docker\.io$/,
    /\.ghcr\.io$/,
    /^registry-1\.docker\.io$/,
];

let runnerPid = null;
const steps = [];
let currentStepIdx = -1;

const procs = new Map();   // pid -> { comm, argv, ppid, startMs, endMs, exitCode }
const stepOf = new Map();  // pid -> stepIndex
const conns = new Map();   // "pid:sport:dip:dport" -> { stepIdx, dst, dstPort, isV6 }
const destStats = new Map(); // "host:port" -> { conns, bytesDown, bytesUp, steps: Set }

export function setRunnerPid(pid) {
    runnerPid = pid;
}

function currentStepIndex() {
    return currentStepIdx;
}

function openStep(rootPid, comm, argv) {
    if (currentStepIdx >= 0) {
        steps[currentStepIdx].endMs = Date.now();
    }
    currentStepIdx++;
    steps.push({
        index: currentStepIdx + 1,
        rootPid,
        rootComm: comm,
        rootArgv: argv,
        startMs: Date.now(),
        endMs: null,
        procCount: 0,
        netBytesDown: 0,
        netBytesUp: 0,
        topDests: [],
        _dests: new Set(),
    });
    stepOf.set(rootPid, currentStepIdx);
}

export function ingestEvent(raw) {
    const ev = raw.event;
    if (!ev) return;

    const { type, pid, ppid, comm } = ev;
    const argv = formatArgv(ev.argv);

    if (type === EV_EXEC) {
        procs.set(pid, { comm, argv, ppid, startMs: Date.now(), endMs: null, exitCode: null });

        if (runnerPid !== null && ppid === runnerPid) {
            openStep(pid, comm, argv);
        } else {
            const parentStep = stepOf.get(ppid);
            if (parentStep !== undefined) {
                stepOf.set(pid, parentStep);
            } else if (currentStepIdx >= 0) {
                stepOf.set(pid, currentStepIdx);
            } else if (runnerPid === null) {
                // No runner PID — open a catch-all step on the first exec we see
                openStep(pid, comm, argv);
            }
        }

        const stepIdx = stepOf.get(pid);
        if (stepIdx !== undefined && steps[stepIdx]) {
            steps[stepIdx].procCount++;
        }
    }

    if (type === EV_EXIT) {
        const p = procs.get(pid);
        if (p) {
            p.endMs = Date.now();
            p.exitCode = ev.exit_code;
        }
    }

    if (type === EV_CONNECT) {
        const stepIdx = stepOf.get(pid) ?? currentStepIdx;
        const dst = formatAddr(ev.dst_addr, ev.dst_port, ev.is_ipv6);
        const key = `${pid}:${ev.src_port}:${dst}`;
        conns.set(key, { stepIdx, dst, dstPort: ev.dst_port, isV6: ev.is_ipv6 });
    }

    if (type === EV_CLOSE) {
        const dst = formatAddr(ev.dst_addr, ev.dst_port, ev.is_ipv6);
        const key = `${ev.pid}:${ev.src_port}:${dst}`;
        const conn = conns.get(key);

        const bytesDown = Number(BigInt(ev.bytes_received ?? 0n));
        const bytesUp   = Number(BigInt(ev.bytes_sent ?? 0n));
        const stepIdx   = conn ? conn.stepIdx : currentStepIdx;

        if (stepIdx >= 0 && steps[stepIdx]) {
            steps[stepIdx].netBytesDown += bytesDown;
            steps[stepIdx].netBytesUp   += bytesUp;
            steps[stepIdx]._dests.add(dst);
        }

        // Accumulate global dest stats
        let ds = destStats.get(dst);
        if (!ds) {
            ds = { conns: 0, bytesDown: 0, bytesUp: 0, steps: new Set() };
            destStats.set(dst, ds);
        }
        ds.conns++;
        ds.bytesDown += bytesDown;
        ds.bytesUp   += bytesUp;
        if (stepIdx >= 0) ds.steps.add(stepIdx + 1);

        if (conn) conns.delete(key);
    }
}

function buildObservations(steps, network) {
    const obs = [];

    for (const step of steps) {
        if (
            step.netBytesDown > NET_BYTES_THRESHOLD &&
            step.wallMs > NET_WALL_THRESHOLD &&
            step.netBytesDown / step.wallMs > NET_RATE_THRESHOLD
        ) {
            const pct = Math.round((step.netBytesDown / (step.wallMs * 1024 / 1000)) / 1024 * 100) / 100;
            let suggestion = 'Consider caching dependencies.';
            const cmd = step.rootComm;
            if (cmd === 'npm' || cmd === 'pnpm' || cmd === 'yarn') {
                suggestion = "Consider actions/setup-node with cache: 'npm' to skip downloads.";
            } else if (cmd === 'pip' || cmd === 'uv') {
                suggestion = "Consider actions/setup-python with cache: 'pip'.";
            } else if (cmd === 'cargo') {
                suggestion = 'Consider Swatinem/rust-cache to skip crate downloads.';
            } else if (cmd === 'go') {
                suggestion = 'Consider actions/cache for GOPATH/pkg/mod.';
            }

            const netPct = Math.round(step.netBytesDown / (step.wallMs / 1000) / 1024);
            obs.push({
                level: 'warn',
                message: `${step.rootArgv || step.rootComm} spent an estimated ${formatPct(step)}% of step time on network (${netPct} KB/s). ${suggestion}`,
            });
        }
    }

    // Unknown destinations
    const unknownDests = [];
    for (const [dest] of destStats) {
        const hostname = dest.split(':')[0].replace(/^\[/, '').replace(/]$/, '');
        const isKnown = KNOWN_DESTINATIONS.some(re => re.test(hostname));
        if (!isKnown) unknownDests.push(dest);
    }
    if (unknownDests.length > 0) {
        obs.push({
            level: 'info',
            message: `Outbound connections to: ${unknownDests.slice(0, 5).join(', ')}${unknownDests.length > 5 ? ` (+${unknownDests.length - 5} more)` : ''}.`,
        });
    }

    // Process count warning
    const totalProcs = steps.reduce((s, st) => s + st.procCount, 0);
    if (totalProcs > 5000) {
        obs.push({
            level: 'info',
            message: `${formatNumber(totalProcs)} processes spawned — process startup overhead may be significant.`,
        });
    }

    return obs;
}

function formatPct(step) {
    if (!step.wallMs) return 0;
    // Rough heuristic: bytes at ~100MB/s => network time
    const estimatedNetMs = step.netBytesDown / (100 * 1024 * 1024 / 1000);
    return Math.min(99, Math.round(estimatedNetMs / step.wallMs * 100));
}

function buildTopComms() {
    const counts = new Map();
    for (const p of procs.values()) {
        counts.set(p.comm, (counts.get(p.comm) || 0) + 1);
    }
    return [...counts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
}

function buildMedianLifetime() {
    const lifetimes = [];
    for (const p of procs.values()) {
        if (p.endMs && p.startMs) {
            lifetimes.push(p.endMs - p.startMs);
        }
    }
    if (!lifetimes.length) return 0;
    lifetimes.sort((a, b) => a - b);
    return lifetimes[Math.floor(lifetimes.length / 2)];
}

export function getReport(startMs) {
    const endMs = Date.now();

    // Close open step
    if (currentStepIdx >= 0 && steps[currentStepIdx]) {
        if (!steps[currentStepIdx].endMs) {
            steps[currentStepIdx].endMs = endMs;
        }
    }

    // Per-step top comms
    const stepCommCounts = new Map(); // stepIdx -> Map(comm -> count)
    for (const [pid, p] of procs) {
        const stepIdx = stepOf.get(pid);
        if (stepIdx === undefined) continue;
        if (!stepCommCounts.has(stepIdx)) stepCommCounts.set(stepIdx, new Map());
        const cm = stepCommCounts.get(stepIdx);
        cm.set(p.comm, (cm.get(p.comm) || 0) + 1);
    }

    const reportSteps = steps.map((s, i) => {
        const wallMs = (s.endMs || endMs) - s.startMs;
        // Estimated network time: assume 100 MB/s sustained download
        const estNetMs = s.netBytesDown / (100 * 1024 * 1024 / 1000);
        const netPct = wallMs > 0 ? Math.min(99, Math.round(estNetMs / wallMs * 100)) : 0;

        const topComms = [...(stepCommCounts.get(i) || new Map()).entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([comm, count]) => ({ comm, count }));

        const topDests = [...destStats.entries()]
            .filter(([, ds]) => ds.steps.has(s.index))
            .sort((a, b) => b[1].bytesDown - a[1].bytesDown)
            .slice(0, 3)
            .map(([dest, ds]) => ({
                dest,
                bytesDown: ds.bytesDown,
                bytesUp: ds.bytesUp,
                connCount: ds.conns,
            }));

        return {
            index: s.index,
            rootComm: s.rootComm,
            rootArgv: s.rootArgv,
            wallMs,
            procCount: s.procCount,
            netBytesDown: s.netBytesDown,
            netBytesUp: s.netBytesUp,
            netPct,
            topComms,
            topDests,
        };
    });

    const network = [...destStats.entries()]
        .sort((a, b) => b[1].bytesDown - a[1].bytesDown)
        .slice(0, 10)
        .map(([dest, ds]) => ({
            dest,
            connCount: ds.conns,
            bytesDown: ds.bytesDown,
            bytesUp:   ds.bytesUp,
            stepIndices: [...ds.steps],
        }));

    const totalProcs = procs.size;
    const observations = buildObservations(reportSteps, network);

    return {
        meta: {
            startMs,
            endMs,
            totalMs: endMs - startMs,
            runnerPid,
            hostname: 'unknown',
        },
        steps: reportSteps,
        network,
        processes: {
            total: totalProcs,
            medianLifetimeMs: buildMedianLifetime(),
            topComms: buildTopComms(),
        },
        observations,
    };
}
