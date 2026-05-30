import bpfObj from './bin/ciprof.bpf.o';
import { RingBuf } from 'yeet:bpf';
import { ingestEvent, setRunnerPid, getReport } from './state.js';
import { renderTerminal, renderJson } from './report.js';

const args = yeet.args;
const startMs = Date.now();

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
// yeet scripts can't read files, so we detect stop via the process table.
// The shell wrapper creates a sentinel: `sh -c 'exec -a ciprof-stop sleep 600'`
// in background before doing `wait $DAEMON_PID`. We poll for that comm.
//
// For --duration mode (testing), we just use a setTimeout instead.

async function watchForStop(onStop) {
    const durationSec = args.duration ? Number(args.duration) : 0;

    if (durationSec > 0) {
        setTimeout(onStop, durationSec * 1000);
        return;
    }

    // Poll process table for sentinel process named 'ciprof-stop'
    const interval = setInterval(async () => {
        const { data } = await yeet.graph.query(`{
            procs { pid cmdline }
        }`).catch(() => ({ data: null }));

        if (!data?.procs) return;
        const found = data.procs.some(p => p.cmdline?.[0] === 'ciprof-stop');
        if (found) {
            clearInterval(interval);
            onStop();
        }
    }, 500);
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
