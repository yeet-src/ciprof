import { formatBytes, formatDuration, formatNumber } from './format.js';

const BAR_WIDTH = 22;

function stripAnsi(s) {
    return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function rpad(s, w) {
    const len = stripAnsi(s).length;
    return len >= w ? s : s + ' '.repeat(w - len);
}

function lpad(s, w) {
    const len = stripAnsi(s).length;
    return len >= w ? s : ' '.repeat(w - len) + s;
}

function bar(pct) {
    const filled = Math.round(pct / 100 * BAR_WIDTH);
    const empty  = BAR_WIDTH - filled;
    return style.cyan('█'.repeat(filled)) + style.dim('░'.repeat(empty));
}

function netEstLabel(pct) {
    if (pct === 0)  return style.dim('no network activity');
    if (pct < 10)   return style.green(`net ~${pct}%`);
    if (pct < 50)   return style.yellow(`net ~${pct}%`);
    return style.red(`net ~${pct}%`);
}

export function renderTerminal(report) {
    const lines = [];

    const totalStr = formatDuration(report.meta.totalMs);
    const title = `  ciprof  ·  ubuntu-latest  ·  total ${totalStr}  `;
    const W = Math.max(title.length, 68);
    const rule = '═'.repeat(W);

    lines.push(style.cyan(`╔${rule}╗`));
    lines.push(style.cyan('║') + style.bold(title.padEnd(W)) + style.cyan('║'));
    lines.push(style.cyan(`╚${rule}╝`));
    lines.push('');

    let totalWall = 0, totalProcs = 0, totalNet = 0;

    for (const step of report.steps) {
        totalWall  += step.wallMs;
        totalProcs += step.procCount;
        totalNet   += step.netBytesDown + step.netBytesUp;

        const label = step.rootArgv || step.rootComm || `step-${step.index}`;
        const wall  = formatDuration(step.wallMs);
        const net   = formatBytes(step.netBytesDown + step.netBytesUp);
        const procs = formatNumber(step.procCount);

        // Header row
        lines.push(
            '  ' +
            rpad(style.bold(label), 46) + '  ' +
            lpad(style.dim(wall), 7)    + '  ' +
            lpad(style.dim(procs + 'p'), 7) + '  ' +
            style.dim(net)
        );

        // Time-share bar
        const computePct = 100 - step.netPct;
        lines.push(
            `  ${bar(step.netPct)}  ` +
            netEstLabel(step.netPct) +
            style.dim(`  /  compute ~${computePct}%`)
        );

        // Top processes
        if (step.topComms.length > 0) {
            const commStr = step.topComms
                .map(({ comm, count }) => `${style.cyan(comm)}×${formatNumber(count)}`)
                .join('  ');
            lines.push(`    ${style.dim('↳ procs')}    ${commStr}`);
        }

        // Top network destinations
        for (const d of step.topDests) {
            const bytes = formatBytes(d.bytesDown);
            const conns = d.connCount > 1 ? style.dim(`  ${d.connCount} conns`) : '';
            lines.push(`    ${style.dim('↳ network')}  ${rpad(d.dest, 38)}  ${lpad(bytes, 9)} ↓${conns}`);
        }

        lines.push('');
    }

    // Summary line
    const sepLine = '  ' + style.dim('─'.repeat(W - 2));
    lines.push(sepLine);
    lines.push(
        '  ' +
        rpad(style.bold('total'), 46) + '  ' +
        lpad(style.bold(formatDuration(totalWall)), 7) + '  ' +
        lpad(style.bold(formatNumber(totalProcs) + 'p'), 7) + '  ' +
        style.bold(formatBytes(totalNet))
    );
    lines.push('');

    // Observations
    if (report.observations.length > 0) {
        for (const obs of report.observations) {
            const icon = obs.level === 'warn' ? style.yellow('⚠') : style.blue('✓');
            lines.push(`  ${icon}  ${obs.message}`);
        }
        lines.push('');
    }

    return lines.join('\n');
}

export function renderJson(report) {
    return JSON.stringify(report, null, 2);
}
