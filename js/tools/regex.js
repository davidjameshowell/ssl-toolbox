function runRegex() {
    const pattern = document.getElementById('regexPattern').value;
    const flags = document.getElementById('regexFlags').value;
    const testStr = document.getElementById('regexTestString').value;
    const resultsDiv = document.getElementById('regexResults');
    const highlightDiv = document.getElementById('regexHighlight');

    if (!pattern) {
        resultsDiv.innerHTML = '';
        highlightDiv.innerHTML = escapeHtml(testStr);
        return;
    }

    try {
        const regex = new RegExp(pattern, flags);
        const allMatches = [...testStr.matchAll(new RegExp(pattern, flags.includes('g') ? flags : flags + 'g'))];

        if (allMatches.length === 0) {
            resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">No matches found.</p>';
            highlightDiv.innerHTML = escapeHtml(testStr);
            return;
        }

        // Build highlighted text
        let highlighted = '';
        let lastIndex = 0;
        for (const match of allMatches) {
            const start = match.index;
            const end = start + match[0].length;
            highlighted += escapeHtml(testStr.slice(lastIndex, start));
            highlighted += `<mark class="bg-yellow-200 text-yellow-900 rounded px-0.5">${escapeHtml(match[0])}</mark>`;
            lastIndex = end;
        }
        highlighted += escapeHtml(testStr.slice(lastIndex));
        highlightDiv.innerHTML = highlighted;

        // Build match details
        let html = `<p class="text-sm text-slate-600 mb-3">${allMatches.length} match${allMatches.length > 1 ? 'es' : ''} found</p>`;
        html += '<div class="space-y-2">';
        allMatches.forEach((m, i) => {
            html += `<div class="bg-white border border-slate-200 rounded-lg p-3 text-xs">`;
            html += `<span class="font-bold text-slate-600">Match ${i + 1}:</span> <code class="text-emerald-700 font-mono">${escapeHtml(m[0])}</code>`;
            html += ` <span class="text-slate-400">at index ${m.index}</span>`;
            if (m.length > 1) {
                html += '<div class="mt-1 ml-4 space-y-0.5">';
                for (let g = 1; g < m.length; g++) {
                    html += `<div><span class="text-slate-500">Group ${g}:</span> <code class="text-blue-700 font-mono">${escapeHtml(m[g] ?? '(undefined)')}</code></div>`;
                }
                html += '</div>';
            }
            html += '</div>';
        });
        html += '</div>';

        resultsDiv.innerHTML = html;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ Invalid regex: ${err.message}</p>`;
        highlightDiv.innerHTML = escapeHtml(testStr);
    }
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function initRegexTool() {
    let debounce;
    const handler = () => {
        clearTimeout(debounce);
        debounce = setTimeout(runRegex, 150);
    };

    document.getElementById('regexPattern').addEventListener('input', handler);
    document.getElementById('regexFlags').addEventListener('input', handler);
    document.getElementById('regexTestString').addEventListener('input', handler);
}
