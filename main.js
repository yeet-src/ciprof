import bpfObj from './bin/ciprof.bpf.o';
import { RingBuf } from 'yeet:bpf';
import { ingestEvent, setRunnerPid, getReport } from './state.js';
import { renderTerminal, renderJson } from './report.js';

const args = yeet.args;
const startMs = Date.now();

// ─── Runner PID detection ─────────────────────────────────────────────────────

async function detectRunnerPid() {
    if (args.runner_pid) return Number(args.runner_pid);

    // Walk procs to find a process named Runner.Worker or actions/runner
    const { data, errors } = await yeet.graph.query(`{
        procs { pid status { name ppid } }
    }`).catch(() => ({ data: null }));

    if (data?.procs) {
        for (const p of data.procs) {
            const name = p.status?.name || '';
            if (name === 'Runner.Worker' || name === 'runner' || name === 'Runner.Listener') {
                return p.pid;
            }
        }
    }

    console.warn('ciprof: could not detect runner PID — step attribution disabled');
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
