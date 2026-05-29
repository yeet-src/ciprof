export function formatNumber(n) {
    const s = String(Math.round(n));
    let result = '';
    for (let i = 0; i < s.length; i++) {
        if (i > 0 && (s.length - i) % 3 === 0) result += ',';
        result += s[i];
    }
    return result;
}

export function formatBytes(n) {
    if (n >= 1_073_741_824) return (n / 1_073_741_824).toFixed(1) + ' GB';
    if (n >= 1_048_576)     return (n / 1_048_576).toFixed(1) + ' MB';
    if (n >= 1_024)         return (n / 1_024).toFixed(1) + ' KB';
    return n + ' B';
}

export function formatDuration(ms) {
    const totalSec = Math.floor(ms / 1000);
    const m = Math.floor(totalSec / 60);
    const s = totalSec % 60;
    return `${m}m ${String(s).padStart(2, '0')}s`;
}

export function formatAddr(addrObj, port, isV6) {
    if (!addrObj) return `?:${port}`;
    const arr = [];
    for (let i = 0; i < 16; i++) arr.push(addrObj[i] || 0);

    if (isV6) {
        // Format as IPv6
        const groups = [];
        for (let i = 0; i < 16; i += 2) {
            groups.push(((arr[i] << 8) | arr[i + 1]).toString(16));
        }
        return `[${groups.join(':')}]:${port}`;
    } else {
        return `${arr[0]}.${arr[1]}.${arr[2]}.${arr[3]}:${port}`;
    }
}

export function formatArgv(rawBytes) {
    if (!rawBytes) return '';
    // rawBytes is an object with numeric keys (from BTF decoder)
    let bytes;
    if (Array.isArray(rawBytes)) {
        bytes = rawBytes;
    } else {
        bytes = [];
        for (let i = 0; i < 128; i++) bytes.push(rawBytes[i] || 0);
    }

    let result = '';
    let nullCount = 0;
    for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === 0) {
            nullCount++;
            if (nullCount >= 2) break;
            result += ' ';
        } else {
            result += String.fromCharCode(bytes[i]);
        }
    }
    return result.trim();
}
