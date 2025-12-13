/* Test harness for QR utility functions */
// polyfill for atob/btoa in node
global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');

function cleanConfigString(text) {
  if (!text || typeof text !== 'string') return text;
  let t = text.trim();
  t = t.replace(/^<pre[^>]*>/i, '').replace(/<\/pre>$/i, '').trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    t = t.slice(1, -1).trim();
  }
  if (/^vmess:\/\//i.test(t)) {
    const body = t.slice(8).replace(/\s+/g, '');
    t = 'vmess://' + body;
  } else if (/^\s*[\{\[]/.test(t)) {
    try {
      const parsed = JSON.parse(t);
      if (parsed && (parsed.add || parsed.id || parsed.ps || parsed.port)) {
        const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(parsed))));
        t = 'vmess://' + encoded;
      }
    } catch (e) {
      t = t.replace(/\s+/g, '');
    }
  } else if (/^[A-Za-z0-9+\/=\s]{40,}$/.test(t) && t.indexOf('://') === -1) {
    t = t.replace(/\s+/g, '');
  } else {
    t = t.replace(/\r?\n/g, '').trim();
  }
  return t;
}

function validateOptimizedPayload(text) {
  if (!text || typeof text !== 'string') return { valid: false, message: 'Empty payload' };
  const t = text.trim();
  if (/^vmess:\/\//i.test(t)) {
    const payload = t.slice(8).replace(/\s+/g, '');
    try {
      const json = atob(payload);
      JSON.parse(json);
      return { valid: true };
    } catch (e) {
      return { valid: false, message: 'Invalid vmess base64 or JSON' };
    }
  }
  if (/^(vless|ss|trojan):\/\//i.test(t)) {
    if (t.includes('@') || /:\/\//.test(t)) return { valid: true };
    return { valid: false, message: 'Malformed proxy URL' };
  }
  return { valid: true };
}

// Test cases
const tests = [
  {
    name: 'vmess base64 with spaces/newlines',
    input: 'vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImlkIjoiMTIzNDU2In0=',
  },
  {
    name: 'vmess JSON object',
    input: JSON.stringify({ add: 'example.com', id: '12345', port: '443' }),
  },
  {
    name: 'vmess raw base64 block with breaks',
    input: 'eyJhZGQiOiJleGFt\n cGxlLmNvbSIsImlkIjoiMTIzNDU2In0=',
  },
  {
    name: 'vless url',
    input: 'vless://uuid@example.com:443?encryption=none#name',
  },
  {
    name: 'malformed vless',
    input: 'vless://not_valid',
  }
];

for (const t of tests) {
  const cleaned = cleanConfigString(t.input);
  const valid = validateOptimizedPayload(cleaned);
  console.log(`${t.name}: cleaned='${cleaned}', valid=${JSON.stringify(valid)}`);
}
