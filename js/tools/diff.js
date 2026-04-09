function myersDiff(a, b) {
    const aLines = a.split('\n');
    const bLines = b.split('\n');
    const result = [];

    const n = aLines.length;
    const m = bLines.length;
    const max = n + m;
    const v = new Array(2 * max + 1);
    const trace = [];

    v[max + 1] = 0;

    for (let d = 0; d <= max; d++) {
        const vSnap = v.slice();
        trace.push(vSnap);

        for (let k = -d; k <= d; k += 2) {
            let x;
            if (k === -d || (k !== d && v[max + k - 1] < v[max + k + 1])) {
                x = v[max + k + 1];
            } else {
                x = v[max + k - 1] + 1;
            }
            let y = x - k;

            while (x < n && y < m && aLines[x] === bLines[y]) {
                x++;
                y++;
            }

            v[max + k] = x;

            if (x >= n && y >= m) {
                // Backtrack
                const ops = [];
                let cx = n, cy = m;
                for (let dd = d; dd > 0; dd--) {
                    const vv = trace[dd - 1];
                    const kk = cx - cy;
                    let prevK;
                    if (kk === -dd || (kk !== dd && vv[max + kk - 1] < vv[max + kk + 1])) {
                        prevK = kk + 1;
                    } else {
                        prevK = kk - 1;
                    }
                    const prevX = vv[max + prevK];
                    const prevY = prevX - prevK;

                    while (cx > prevX && cy > prevY) {
                        cx--; cy--;
                        ops.unshift({ type: 'equal', line: aLines[cx] });
                    }

                    if (cx > prevX) {
                        cx--;
                        ops.unshift({ type: 'delete', line: aLines[cx] });
                    } else if (cy > prevY) {
                        cy--;
                        ops.unshift({ type: 'insert', line: bLines[cy] });
                    }
                }
                while (cx > 0 && cy > 0) {
                    cx--; cy--;
                    ops.unshift({ type: 'equal', line: aLines[cx] });
                }

                return ops;
            }
        }
    }

    return result;
}

function renderDiff() {
    const left = document.getElementById('diffLeft').value;
    const right = document.getElementById('diffRight').value;
    const resultsDiv = document.getElementById('diffResults');

    if (!left && !right) {
        resultsDiv.innerHTML = '';
        return;
    }

    const ops = myersDiff(left, right);

    let leftNum = 0, rightNum = 0;
    const rows = ops.map(op => {
        const escaped = op.line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        if (op.type === 'equal') {
            leftNum++; rightNum++;
            return `<tr><td class="px-2 text-slate-400 text-right select-none w-10">${leftNum}</td><td class="px-2 text-slate-400 text-right select-none w-10">${rightNum}</td><td class="px-2 text-slate-300 select-none w-6">&nbsp;</td><td class="px-3 font-mono whitespace-pre">${escaped}</td></tr>`;
        }
        if (op.type === 'delete') {
            leftNum++;
            return `<tr class="bg-red-50"><td class="px-2 text-red-400 text-right select-none w-10">${leftNum}</td><td class="px-2 text-slate-300 text-right select-none w-10"></td><td class="px-2 text-red-500 select-none w-6 font-bold">-</td><td class="px-3 font-mono text-red-700 whitespace-pre">${escaped}</td></tr>`;
        }
        if (op.type === 'insert') {
            rightNum++;
            return `<tr class="bg-emerald-50"><td class="px-2 text-slate-300 text-right select-none w-10"></td><td class="px-2 text-emerald-400 text-right select-none w-10">${rightNum}</td><td class="px-2 text-emerald-500 select-none w-6 font-bold">+</td><td class="px-3 font-mono text-emerald-700 whitespace-pre">${escaped}</td></tr>`;
        }
        return '';
    }).join('');

    const added = ops.filter(o => o.type === 'insert').length;
    const removed = ops.filter(o => o.type === 'delete').length;

    resultsDiv.innerHTML = `
        <p class="text-xs text-slate-500 mb-3"><span class="text-emerald-600 font-semibold">+${added}</span> added, <span class="text-red-600 font-semibold">-${removed}</span> removed</p>
        <div class="border border-slate-200 rounded-lg overflow-x-auto">
            <table class="min-w-full text-xs"><tbody>${rows}</tbody></table>
        </div>`;
}

export function initDiffTool() {
    document.getElementById('diffCompareBtn').addEventListener('click', renderDiff);
}
