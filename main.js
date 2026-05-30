import bpfObj from './bin/ciprof.bpf.o';
import { RingBuf } from 'yeet:bpf';
import { ingestEvent, setRunnerPid, getReport } from './state.js';
import { renderTerminal, renderJson } from './report.js';

const EV_UNLINK = 5;

const args = yeet.args;
const startMs = Date.now();

let sentinelStopCb = null;

// ─── Runner PID detection ─────────────────────────────────────────────────────

async function detectRunnerPid() {
    if (args.runner_pid) return Number(args.runner_pid);

    const { data } = await yeet.graph.query(`{
        procs { pid cmdline status { name } }
    }`).catch(() => ({ data: null }));

    if (data?.procs) {
        for (const p of data.procs) {
            const name    = p.status?.name || '';
            const cmd0    = p.cmdline?.[0] || '';
            const cmdline = (p.cmdline || []).join(' ');
            if (
                name === 'Runner.Worker'   || name === 'Runner.Listener' ||
                cmd0 === 'Runner.Worker'   || cmd0 === 'Runner.Listener' ||
                cmdline.includes('Runner.Worker') ||
                cmdline.includes('actions/runner') ||
                cmdline.includes('github/runner')
            ) {
                console.warn(`ciprof: runner PID ${p.pid} (${name || cmd0})`);
                return p.pid;
            }
        }
    }

    // Log running processes so we can tune detection
    if (data?.procs) {
        const names = data.procs
            .map(p => p.status?.name || p.cmdline?.[0] || '?')
            .filter((n, i, a) => a.indexOf(n) === i)
            .sort()
            .join(', ');
        console.warn(`ciprof: procs visible: ${names}`);
    }
    console.warn('ciprof: runner PID not found — attributing all events to a single job step');
    return null;
}

// ─── Event handler ────────────────────────────────────────────────────────────

function onEvent(raw) {
    if (raw.event?.type === EV_UNLINK) {
        if (sentinelStopCb && String(raw.event.ino) === String(args.sentinel_inode)) {
            const cb = sentinelStopCb;
            sentinelStopCb = null;
            cb();
        }
        return;
    }
    try {
        ingestEvent(raw);
    } catch (e) {
        console.warn('ciprof: event error:', e.message);
    }
}

// ─── Shutdown + report ────────────────────────────────────────────────────────

function emitReport() {
    const report = getReport(startMs);
    if (args.json) {
        console.log(renderJson(report));
    } else {
        console.log(renderTerminal(report));
    }
}

// ─── Stop detection ──────────────────────────────────────────────────────────
//
// Pass --sentinel-inode <ino> (the inode of a file you create before starting).
// Delete that file to trigger the report. The BPF unlink probe fires an
// EV_UNLINK event which onEvent() catches and routes here.
//
// For --duration mode (local testing without a sentinel file), a setTimeout
// fires instead.

async function watchForStop(onStop) {
    const durationSec = args.duration ? Number(args.duration) : 0;
    if (durationSec > 0) {
        setTimeout(onStop, durationSec * 1000);
        return;
    }
    sentinelStopCb = onStop;
    console.warn(`ciprof: waiting for sentinel inode ${args.sentinel_inode} to be unlinked`);
}

// ─── --start mode ────────────────────────────────────────────────────────────

async function runDaemon() {
    const runnerPid = await detectRunnerPid();
    if (runnerPid) {
        setRunnerPid(runnerPid);
        console.warn(`ciprof: monitoring runner PID ${runnerPid}`);
    }

    bpfObj.bind('events', { kind: 'ring_buf', btf_struct: 'event', capacity: 8192 });
    const ctl = await bpfObj.start();
    await new RingBuf(ctl, 'events').subscribe(onEvent, (err) => console.warn('ciprof: ringbuf:', err.message));

    console.warn('ciprof: BPF probes loaded, collecting events');

    await new Promise(resolve => watchForStop(async () => {
        emitReport();
        await ctl.stop();
        resolve();
    }));

    yeet.exit();
}

// ─── Entry ────────────────────────────────────────────────────────────────────

if (args.start) {
    runDaemon().catch(e => {
        console.error('ciprof: fatal:', e.message, e.stack);
        yeet.exit();
    });
} else {
    console.log('Usage: ciprof --start [--duration <secs>] [--json] [--runner-pid <pid>]');
    yeet.exit();
}
