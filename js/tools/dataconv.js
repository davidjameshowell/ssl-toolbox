/* global jsyaml */

function jsonToYaml(json) {
    if (typeof jsyaml === 'undefined') throw new Error('js-yaml library not loaded.');
    const obj = JSON.parse(json);
    return jsyaml.dump(obj);
}

function yamlToJson(yaml) {
    if (typeof jsyaml === 'undefined') throw new Error('js-yaml library not loaded.');
    const obj = jsyaml.load(yaml);
    return JSON.stringify(obj, null, 2);
}

function jsonToXml(json, rootName = 'root') {
    const obj = JSON.parse(json);
    function toXml(o, tag) {
        if (o === null || o === undefined) return `<${tag}/>`;
        if (typeof o !== 'object') return `<${tag}>${String(o).replace(/&/g, '&amp;').replace(/</g, '&lt;')}</${tag}>`;
        if (Array.isArray(o)) return o.map(item => toXml(item, 'item')).join('\n');
        return `<${tag}>\n${Object.entries(o).map(([k, v]) => '  ' + toXml(v, k)).join('\n')}\n</${tag}>`;
    }
    return `<?xml version="1.0" encoding="UTF-8"?>\n${toXml(obj, rootName)}`;
}

function xmlToJson(xml) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, 'text/xml');
    const errors = doc.getElementsByTagName('parsererror');
    if (errors.length) throw new Error('Invalid XML');

    function nodeToObj(node) {
        if (node.nodeType === Node.TEXT_NODE) return node.textContent.trim() || null;
        const obj = {};
        for (const child of node.childNodes) {
            if (child.nodeType === Node.TEXT_NODE) {
                const text = child.textContent.trim();
                if (text && node.childNodes.length === 1) return text;
                continue;
            }
            const name = child.nodeName;
            const val = nodeToObj(child);
            if (obj[name] !== undefined) {
                if (!Array.isArray(obj[name])) obj[name] = [obj[name]];
                obj[name].push(val);
            } else {
                obj[name] = val;
            }
        }
        return obj;
    }

    return JSON.stringify(nodeToObj(doc.documentElement), null, 2);
}

function csvToJson(csv) {
    const lines = csv.trim().split('\n');
    if (lines.length < 2) throw new Error('CSV must have a header row and at least one data row.');
    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    const rows = lines.slice(1).map(line => {
        const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
        const obj = {};
        headers.forEach((h, i) => obj[h] = values[i] || '');
        return obj;
    });
    return JSON.stringify(rows, null, 2);
}

function jsonToCsv(json) {
    const arr = JSON.parse(json);
    if (!Array.isArray(arr) || arr.length === 0) throw new Error('Input must be a JSON array of objects.');
    const headers = Object.keys(arr[0]);
    const rows = arr.map(obj => headers.map(h => {
        const val = String(obj[h] ?? '');
        return val.includes(',') || val.includes('"') || val.includes('\n') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(','));
    return [headers.join(','), ...rows].join('\n');
}

function beautifyJson(json) {
    return JSON.stringify(JSON.parse(json), null, 2);
}

function minifyJson(json) {
    return JSON.stringify(JSON.parse(json));
}

function detectFormat(input) {
    const trimmed = input.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
    if (trimmed.startsWith('<?xml') || trimmed.startsWith('<')) return 'xml';
    if (trimmed.includes(',') && trimmed.includes('\n')) return 'csv';
    return 'yaml';
}

function convert() {
    const input = document.getElementById('dataconvInput').value;
    const fromFormat = document.getElementById('dataconvFrom').value;
    const toFormat = document.getElementById('dataconvTo').value;
    const output = document.getElementById('dataconvOutput');
    const statusEl = document.getElementById('dataconvStatus');

    try {
        const from = fromFormat === 'auto' ? detectFormat(input) : fromFormat;
        let jsonStr;

        switch (from) {
            case 'json': jsonStr = input; break;
            case 'yaml': jsonStr = yamlToJson(input); break;
            case 'xml': jsonStr = xmlToJson(input); break;
            case 'csv': jsonStr = csvToJson(input); break;
            default: throw new Error(`Unknown format: ${from}`);
        }

        let result;
        switch (toFormat) {
            case 'json': result = beautifyJson(jsonStr); break;
            case 'json-min': result = minifyJson(jsonStr); break;
            case 'yaml': result = jsonToYaml(jsonStr); break;
            case 'xml': result = jsonToXml(jsonStr); break;
            case 'csv': result = jsonToCsv(jsonStr); break;
            default: throw new Error(`Unknown target format: ${toFormat}`);
        }

        output.value = result;
        statusEl.textContent = `Converted ${from.toUpperCase()} → ${toFormat.toUpperCase()}`;
        statusEl.className = 'text-xs text-emerald-600 mt-2';
    } catch (err) {
        output.value = '';
        statusEl.textContent = `Error: ${err.message}`;
        statusEl.className = 'text-xs text-red-600 mt-2';
    }
}

export function initDataconvTool() {
    document.getElementById('dataconvConvertBtn').addEventListener('click', convert);
    document.getElementById('dataconvCopy').addEventListener('click', () => {
        const text = document.getElementById('dataconvOutput').value;
        if (text) navigator.clipboard.writeText(text);
    });
}
