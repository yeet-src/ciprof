import { formatBytes, formatDuration, formatNumber } from './format.js';

const COL_WIDTH = 68;

function pad(str, width, char = ' ') {
    const plain = stripAnsi(str);
    const extra = str.length - plain.length; // ansi bytes don't count toward visual width
    const needed = width - plain.length;
    if (needed <= 0) return str;
    return str + char.repeat(needed);
}

function stripAnsi(str) {
    // Rough: remove ESC sequences
    return str.replace(/\x1b\[[0-9;]*m/g, '');
}

function rpad(str, width) {
    return pad(str, width);
}

function lpad(str, width) {
    const plain = stripAnsi(str);
    const needed = width - plain.length;
    if (needed <= 0) return str;
    return ' '.repeat(needed) + str;
}

export function renderTerminal(report) {
    const lines = [];

    const totalStr = formatDuration(report.meta.totalMs);
    const header = `  ciprof  ·  ubuntu-latest  ·  total ${totalStr}  `;
    const border = '═'.repeat(Math.max(header.length, 66));

    lines.push(style.cyan('╔' + border + '╗'));
    lines.push(style.cyan('║') + style.bold(header.padEnd(border.length)) + style.cyan('║'));
    lines.push(style.cyan('╚' + border + '╝'));
    lines.push('');

    // ─── STEPS ───────────────────────────────────────────────────────────────
    lines.push(style.bold('STEPS'));
    const sepLine = '  ' + '─'.repeat(border.length - 2);
    lines.push(style.dim(sepLine));

    const HDR_NAME  = 46;
    const HDR_WALL  = 8;
    const HDR_PROCS = 7;
    lines.push(
        '  ' +
        rpad(style.dim(''), HDR_NAME) +
        lpad(style.dim('wall'), HDR_WALL) + '  ' +
        lpad(style.dim('procs'), HDR_PROCS) + '  ' +
        style.dim('net')
    );

    let totalWall = 0, totalProcs = 0, totalNet = 0;
    for (const step of report.steps) {
        const name = step.rootArgv || step.rootComm || `step-${step.index}`;
        const wall = formatDuration(step.wallMs);
        const net  = formatBytes(step.netBytesDown + step.netBytesUp);
        totalWall  += step.wallMs;
        totalProcs += step.procCount;
        totalNet   += step.netBytesDown + step.netBytesUp;

        lines.push(
            '  ' +
            rpad(name, HDR_NAME) +
            lpad(wall, HDR_WALL) + '  ' +
            lpad(String(step.procCount), HDR_PROCS) + '  ' +
            net
        );
    }

    lines.push(style.dim(sepLine));
    lines.push(
        '  ' +
        rpad(style.bold('total'), HDR_NAME) +
        lpad(style.bold(formatDuration(totalWall)), HDR_WALL) + '  ' +
        lpad(style.bold(String(totalProcs)), HDR_PROCS) + '  ' +
        style.bold(formatBytes(totalNet))
    );
    lines.push('');

    // ─── NETWORK ─────────────────────────────────────────────────────────────
    if (report.network.length > 0) {
        lines.push(style.bold('NETWORK') + style.dim('  (top destinations)'));
        for (const n of report.network) {
            const dest = rpad(n.dest, 40);
            const conns = lpad(`${n.connCount} conns`, 10);
            const down  = lpad(formatBytes(n.bytesDown) + ' ↓', 12);
            lines.push(`  ${dest} ${conns}  ${down}`);
        }
        lines.push('');
    }

    // ─── PROCESS OVERHEAD ────────────────────────────────────────────────────
    const { total, medianLifetimeMs, topComms } = report.processes;
    lines.push(style.bold('PROCESS OVERHEAD'));
    lines.push(
        `  ${formatNumber(total)} processes spawned  ·  median lifetime ${medianLifetimeMs} ms`
    );
    if (topComms.length) {
        const spawnerStr = topComms.map(([c, n]) => `${c} (${n})`).join('  ');
        lines.push(`  top spawners:  ${spawnerStr}`);
    }
    lines.push('');

    // ─── OBSERVATIONS ────────────────────────────────────────────────────────
    if (report.observations.length > 0) {
        lines.push(style.bold('OBSERVATIONS'));
        for (const obs of report.observations) {
            const icon = obs.level === 'warn'
                ? style.yellow('⚠')
                : style.blue('✓');
            const words = obs.message.split(' ');
            const maxW  = COL_WIDTH - 4;
            let line = '';
            const wrapped = [];
            for (const w of words) {
                if ((line + ' ' + w).length > maxW) {
                    wrapped.push(line);
                    line = w;
                } else {
                    line = line ? line + ' ' + w : w;
                }
            }
            if (line) wrapped.push(line);
            lines.push(`  ${icon}  ${wrapped[0]}`);
            for (let i = 1; i < wrapped.length; i++) {
                lines.push(`     ${wrapped[i]}`);
            }
        }
    }

    return lines.join('\n');
}

export function renderJson(report) {
    return JSON.stringify(report, null, 2);
}
