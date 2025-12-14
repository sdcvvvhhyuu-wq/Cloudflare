// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - COMPLETE UNIFIED VERSION
 * ============================================================================
 * 
 * Combined Features:
 * - Advanced Admin Panel with Auto-Refresh
 * - User Panel with Self-Contained QR Code Generator
 * - Health Check & Auto-Switching System
 * - Scamalytics IP Reputation Check
 * - RASPS (Responsive Adaptive Smart Polling)
 * - Complete Geo-location Detection
 * - D1 Database Integration
 * - Full Security Headers & CSRF Protection
 * 
 * Last Updated: December 2025
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION SECTION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  
  scamalytics: {
    username: 'victoriacrossn',
    apiKey: 'ed89b4fef21aba43c15cdd15cff2138dd8d3bbde5aaaa4690ad8e94990448516',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },

  async fromEnv(env) {
    let selectedProxyIP = null;

    if (env.DB) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
        ).all();
        selectedProxyIP = results[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log('Using best healthy proxy from DB: ' + selectedProxyIP);
        }
      } catch (e) {
        console.error('Failed to read proxy health from DB: ' + e.message);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log('Using proxy from env.PROXYIP: ' + selectedProxyIP);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log('Using proxy from config list: ' + selectedProxyIP);
      }
    }
    
    if (!selectedProxyIP) {
      console.error('CRITICAL: No proxy IP available');
      selectedProxyIP = this.proxyIPs[0]; 
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      proxyAddress: selectedProxyIP,
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

// ============================================================================
// CONSTANTS
// ============================================================================

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  AUTO_REFRESH_INTERVAL: 60000,
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000,
  HEALTH_CHECK_TIMEOUT: 5000,
};

// ============================================================================
// CORE SECURITY & HELPER FUNCTIONS
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const scriptSrc = nonce 
    ? "script-src 'self' 'nonce-" + nonce + "' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com"
    : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'";
  
  const imgSrc = "img-src 'self' data: blob: https: " + (cspDomains.img || '');
  const connectSrc = "connect-src 'self' https: wss: " + (cspDomains.connect || '');
  
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    imgSrc.trim(),
    connectSrc.trim(),
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=0');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aLen = a.length;
  const bLen = b.length;
  let result = 0;

  if (aLen !== bLen) {
    for (let i = 0; i < aLen; i++) {
      result |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false;
  }
  
  for (let i = 0; i < aLen; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, function(m) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return map[m];
  });
}

function safeBase64Encode(str) {
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch (e) {
    return btoa(unescape(encodeURIComponent(str)));
  }
}

function generateUUID() {
  return crypto.randomUUID();
}

function isValidUUID(uuid) {
  if (typeof uuid !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
  if (!expDate || !expTime) return true;
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? expTime + ':00' : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(expDate + 'T' + cleanTime + 'Z');
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// KEY-VALUE STORAGE FUNCTIONS (D1-based)
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.error('kvGet: Database not available for key ' + key);
    return null;
  }
  try {
    const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
    const res = await stmt.first();
    
    if (!res) return null;
    
    if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
      await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      return null;
    }
    
    if (type === 'json') {
      try {
        return JSON.parse(res.value);
      } catch (e) {
        console.error('Failed to parse JSON for key ' + key + ': ' + e);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error('kvGet error for ' + key + ': ' + e);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.error('kvPut: Database not available for key ' + key);
    return;
  }
  try {
    if (typeof value === 'object') {
      value = JSON.stringify(value);
    }
    
    const exp = options.expirationTtl 
      ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
      : null;
    
    await db.prepare(
      "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
    ).bind(key, value, exp).run();
  } catch (e) {
    console.error('kvPut error for ' + key + ': ' + e);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.error('kvDelete: Database not available for key ' + key);
    return;
  }
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error('kvDelete error for ' + key + ': ' + e);
  }
}

// ============================================================================
// USER DATA MANAGEMENT
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = 'user:' + uuid;
    
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error('Failed to get cached data for ' + uuid, e);
    }

    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    return userFromDb;
  } catch (e) {
    console.error('getUserData error for ' + uuid + ': ' + e.message);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: D1 binding missing");
    return;
  }
  
  const usageLockKey = 'usage_lock:' + uuid;
  let lockAcquired = false;
  
  try {
    while (!lockAcquired) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare(
      "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
    ).bind(usage, uuid).run();
    
    const deleteCachePromise = kvDelete(env.DB, 'user:' + uuid);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
  } catch (err) {
    console.error('Failed to update usage for ' + uuid + ':', err);
  } finally {
    if (lockAcquired) {
      try {
        await kvDelete(env.DB, usageLockKey);
      } catch (e) {
        console.error('Failed to release lock for ' + uuid + ':', e);
      }
    }
  }
}

async function cleanupOldIps(env, ctx) {
  if (!env.DB) {
    console.warn('cleanupOldIps: D1 binding not available');
    return;
  }
  try {
    const cleanupPromise = env.DB.prepare(
      "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
    ).bind('-' + CONST.IP_CLEANUP_AGE_DAYS + ' days').run();
    
    if (ctx) {
      ctx.waitUntil(cleanupPromise);
    } else {
      await cleanupPromise;
    }
  } catch (e) {
    console.error('cleanupOldIps error: ' + e.message);
  }
}

// ============================================================================
// SCAMALYTICS IP REPUTATION CHECK
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn('Scamalytics not configured. IP ' + ip + ' allowed (fail-open).');
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = scamalyticsConfig.baseUrl + 'score?username=' + scamalyticsConfig.username + '&ip=' + ip + '&key=' + scamalyticsConfig.apiKey;
    const response = await fetch(url, { signal: controller.signal });
    
    if (!response.ok) {
      console.warn('Scamalytics API returned ' + response.status + ' for ' + ip + '. Allowing (fail-open).');
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn('Scamalytics timeout for ' + ip + '. Allowing (fail-open).');
    } else {
      console.error('Scamalytics error for ' + ip + ': ' + e.message + '. Allowing (fail-open).');
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// 2FA (TOTP) VALIDATION SYSTEM
// ============================================================================

function base32ToBuffer(base32) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = base32.toUpperCase().replace(/=+$/, '');
  
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor(str.length * 5 / 8));
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const charValue = base32Chars.indexOf(char);
    if (charValue === -1) throw new Error('Invalid Base32 character');
    
    value = (value << 5) | charValue;
    bits += 5;
    
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return output.buffer;
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
  const hmacBuffer = new Uint8Array(hmac);
  
  const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
  const otp = binary % 1000000;
  
  return otp.toString().padStart(6, '0');
}

async function validateTOTP(secret, code) {
  if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }
  
  let secretBuffer;
  try {
    secretBuffer = base32ToBuffer(secret);
  } catch (e) {
    console.error("Failed to decode TOTP secret:", e.message);
    return false;
  }
  
  const timeStep = 30;
  const epoch = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(epoch / timeStep);
  
  const counters = [currentCounter, currentCounter - 1, currentCounter + 1];

  for (const counter of counters) {
    const generatedCode = await generateHOTP(secretBuffer, counter);
    if (timingSafeEqual(code, generatedCode)) {
      return true;
    }
  }
  
  return false;
}

async function hashSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

async function checkRateLimit(db, key, limit, ttl) {
  if (!db) return false;
  try {
    const countStr = await kvGet(db, key);
    const count = parseInt(countStr, 10) || 0;
    if (count >= limit) return true;
    await kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
    return false;
  } catch (e) {
    console.error('checkRateLimit error for ' + key + ': ' + e);
    return false;
  }
}

// ============================================================================
// UUID UTILITIES
// ============================================================================

const byteToHex = Array.from({ length: 256 }, function(_, i) { return (i + 0x100).toString(16).slice(1); });

function unsafeStringify(arr, offset) {
  offset = offset || 0;
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + 
    byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
    byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
    byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset) {
  offset = offset || 0;
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION LINK GENERATION
// ============================================================================

function generateRandomPath(length) {
  length = length || 12;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return '/' + result;
}

function makeName(tag, proto) {
  return tag + '-' + proto.toUpperCase();
}

function randomizeCase(str) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

function createVlessLink(opts) {
  const params = new URLSearchParams({
    encryption: 'none',
    type: 'ws',
    host: opts.host,
    path: opts.path,
  });

  if (opts.security) {
    params.set('security', opts.security);
    if (opts.security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (opts.sni) params.set('sni', opts.sni);
  if (opts.fp) params.set('fp', opts.fp);
  if (opts.alpn) params.set('alpn', opts.alpn);

  if (opts.extra) {
    for (const k in opts.extra) {
      params.set(k, opts.extra[k]);
    }
  }

  return 'vless://' + opts.userID + '@' + opts.address + ':' + opts.port + '?' + params.toString() + '#' + encodeURIComponent(opts.name);
}

function buildLink(opts) {
  const presets = {
    xray: {
      tls: { security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: { ed: '2560' } },
      tcp: { security: 'none', fp: 'chrome', extra: { ed: '2560' } },
    },
    sb: {
      tls: { security: 'tls', fp: 'firefox', alpn: 'h3', extra: CONST.ED_PARAMS },
      tcp: { security: 'none', fp: 'firefox', extra: CONST.ED_PARAMS },
    },
  };

  const p = presets[opts.core][opts.proto];
  return createVlessLink({
    userID: opts.userID,
    address: opts.address,
    port: opts.port,
    host: opts.hostName,
    path: generateRandomPath(opts.core === 'sb' ? 18 : 12),
    security: p.security,
    sni: p.security === 'tls' ? randomizeCase(opts.hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(opts.tag, opts.proto),
  });
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ============================================================================
// SUBSCRIPTION HANDLER
// ============================================================================

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [
    hostName,
    'creativecommons.org',
    'www.speedtest.net',
    'sky.rethinkdns.com',
    'cfip.1323123.xyz',
    'go.inmobi.com',
    'www.visa.com',
    'www.wto.org',
    'cf.090227.xyz',
    'cdnjs.com',
    'zula.ir',
    'mail.tm',
    'temp-mail.org',
    'ipaddress.my',
    'mdbmax.com',
    'check-host.net',
    'kodambroker.com',
    'iplocation.io',
    'whatismyip.org',
    'www.linkedin.com',
    'exir.io',
    'arzex.io',
    'ok-ex.io',
    'arzdigital.com',
    'pouyanit.com',
    'auth.grok.com',
    'grok.com',
    'maxmind.com',
    'whatsmyip.com',
    'iplocation.net',
    'ipchicken.com',
    'showmyip.com',
    'router-network.com',
    'whatismyipaddress.com',
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  var links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach(function(domain, i) {
    links.push(
      buildLink({
        core: core,
        proto: 'tls',
        userID: userID,
        hostName: hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: 'D' + (i + 1),
      })
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core: core,
          proto: 'tcp',
          userID: userID,
          hostName: hostName,
          address: domain,
          port: pick(httpPorts),
          tag: 'D' + (i + 1),
        })
      );
    }
  });

  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json'
    );
    if (r.ok) {
      const json = await r.json();
      const ipv4List = json.ipv4 || [];
      const ipv6List = json.ipv6 || [];
      const ips = ipv4List.concat(ipv6List).slice(0, 20).map(function(x) { return x.ip; });
      ips.forEach(function(ip, i) {
        const formattedAddress = ip.includes(':') ? '[' + ip + ']' : ip;
        links.push(
          buildLink({
            core: core,
            proto: 'tls',
            userID: userID,
            hostName: hostName,
            address: formattedAddress,
            port: pick(httpsPorts),
            tag: 'IP' + (i + 1),
          })
        );

        if (!isPagesDeployment) {
          links.push(
            buildLink({
              core: core,
              proto: 'tcp',
              userID: userID,
              hostName: hostName,
              address: formattedAddress,
              port: pick(httpPorts),
              tag: 'IP' + (i + 1),
            })
          );
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e);
  }

  const headers = new Headers({ 
    'Content-Type': 'text/plain;charset=utf-8',
    'Profile-Update-Interval': '6',
  });
  addSecurityHeaders(headers, null, {});

  return new Response(safeBase64Encode(links.join('\n')), { headers: headers });
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) {
    console.warn('ensureTablesExist: D1 binding not available');
    return;
  }
  
  try {
    const createTables = [
      "CREATE TABLE IF NOT EXISTS users (uuid TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expiration_date TEXT NOT NULL, expiration_time TEXT NOT NULL, notes TEXT, traffic_limit INTEGER, traffic_used INTEGER DEFAULT 0, ip_limit INTEGER DEFAULT -1)",
      "CREATE TABLE IF NOT EXISTS user_ips (uuid TEXT, ip TEXT, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (uuid, ip), FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE)",
      "CREATE TABLE IF NOT EXISTS key_value (key TEXT PRIMARY KEY, value TEXT NOT NULL, expiration INTEGER)",
      "CREATE TABLE IF NOT EXISTS proxy_health (ip_port TEXT PRIMARY KEY, is_healthy INTEGER NOT NULL, latency_ms INTEGER, last_check INTEGER DEFAULT (strftime('%s', 'now')))"
    ];
    
    const stmts = createTables.map(function(sql) { return env.DB.prepare(sql); });
    await env.DB.batch(stmts);
    
    const testUUID = env.UUID || Config.userID;
    const futureDate = new Date();
    futureDate.setMonth(futureDate.getMonth() + 1);
    const expDate = futureDate.toISOString().split('T')[0];
    const expTime = '23:59:59';
    
    try {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1).run();
    } catch (insertErr) {
      // User may already exist
    }
    
    console.log('D1 tables initialized successfully');
  } catch (e) {
    console.error('Failed to create D1 tables:', e);
  }
}

// ============================================================================
// HEALTH CHECK SYSTEM
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: D1 binding not available');
    return;
  }
  
  const proxyIps = env.PROXYIPS 
    ? env.PROXYIPS.split(',').map(function(ip) { return ip.trim(); }) 
    : Config.proxyIPs;
  
  const healthStmts = [];
  
  for (var idx = 0; idx < proxyIps.length; idx++) {
    const ipPort = proxyIps[idx];
    const parts = ipPort.split(':');
    const host = parts[0];
    const port = parts[1] || '443';
    var latency = null;
    var isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(function() { controller.abort(); }, CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch('https://' + host + ':' + port, { 
        signal: controller.signal,
        method: 'HEAD',
      });
      clearTimeout(timeoutId);
      
      if (response.ok || response.status === 404) {
        latency = Date.now() - start;
        isHealthy = 1;
      }
    } catch (e) {
      console.error('Health check failed for ' + ipPort + ': ' + e.message);
    }
    
    healthStmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
      ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
    );
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('Proxy health check completed');
  } catch (e) {
    console.error('performHealthCheck batch error: ' + e.message);
  }
}

// ============================================================================
// ADMIN PANEL HTML
// ============================================================================

function getAdminLoginHTML(nonce, adminBasePath, errorMsg) {
  return '<!DOCTYPE html>' +
'<html lang="en">' +
'<head>' +
'  <meta charset="UTF-8">' +
'  <meta name="viewport" content="width=device-width, initial-scale=1.0">' +
'  <title>Admin Login - VLESS Proxy</title>' +
'  <style nonce="' + nonce + '">' +
'    * { box-sizing: border-box; margin: 0; padding: 0; }' +
'    body {' +
'      display: flex; justify-content: center; align-items: center;' +
'      min-height: 100vh; margin: 0;' +
'      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);' +
'      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;' +
'    }' +
'    .login-container {' +
'      background: rgba(255, 255, 255, 0.05);' +
'      backdrop-filter: blur(10px);' +
'      padding: 40px;' +
'      border-radius: 16px;' +
'      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);' +
'      text-align: center;' +
'      width: 100%;' +
'      max-width: 400px;' +
'      border: 1px solid rgba(255, 255, 255, 0.1);' +
'    }' +
'    h1 {' +
'      color: #ffffff;' +
'      margin-bottom: 24px;' +
'      font-weight: 600;' +
'      font-size: 28px;' +
'    }' +
'    form { display: flex; flex-direction: column; gap: 16px; }' +
'    input[type="password"], input[type="text"] {' +
'      background: rgba(255, 255, 255, 0.1);' +
'      border: 1px solid rgba(255, 255, 255, 0.2);' +
'      color: #ffffff;' +
'      padding: 14px;' +
'      border-radius: 8px;' +
'      font-size: 16px;' +
'      transition: all 0.3s;' +
'    }' +
'    input:focus {' +
'      outline: none;' +
'      border-color: #3b82f6;' +
'      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);' +
'      background: rgba(255, 255, 255, 0.15);' +
'    }' +
'    input::placeholder { color: rgba(255, 255, 255, 0.5); }' +
'    button {' +
'      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);' +
'      color: white;' +
'      border: none;' +
'      padding: 14px;' +
'      border-radius: 8px;' +
'      font-size: 16px;' +
'      font-weight: 600;' +
'      cursor: pointer;' +
'      transition: all 0.3s;' +
'    }' +
'    button:hover {' +
'      transform: translateY(-2px);' +
'      box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4);' +
'    }' +
'    .error {' +
'      color: #ff6b6b;' +
'      margin-top: 16px;' +
'      font-size: 14px;' +
'      background: rgba(255, 107, 107, 0.1);' +
'      padding: 12px;' +
'      border-radius: 8px;' +
'      border: 1px solid rgba(255, 107, 107, 0.3);' +
'    }' +
'  </style>' +
'</head>' +
'<body>' +
'  <div class="login-container">' +
'    <h1>Admin Login</h1>' +
'    <form method="POST" action="' + adminBasePath + '">' +
'      <input type="password" name="password" placeholder="Enter admin password" required autocomplete="current-password">' +
'      <input type="text" name="totp" placeholder="2FA Code (if enabled)" autocomplete="off" inputmode="numeric" pattern="[0-9]*" maxlength="6">' +
'      <button type="submit">Login</button>' +
'    </form>' +
(errorMsg ? '<p class="error">' + errorMsg + '</p>' : '') +
'  </div>' +
'</body>' +
'</html>';
}

function getAdminPanelHTML(nonce, apiBasePath) {
  return '<!DOCTYPE html>' +
'<html lang="en">' +
'<head>' +
'  <meta charset="UTF-8">' +
'  <meta name="viewport" content="width=device-width, initial-scale=1.0">' +
'  <title>Admin Dashboard - VLESS Proxy Manager</title>' +
'  <style nonce="' + nonce + '">' +
'    :root {' +
'      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;' +
'      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;' +
'      --accent: #3B82F6; --accent-hover: #2563EB;' +
'      --danger: #EF4444; --success: #22C55E; --warning: #F59e0b;' +
'    }' +
'    * { margin: 0; padding: 0; box-sizing: border-box; }' +
'    body {' +
'      font-family: Inter, system-ui, -apple-system, sans-serif;' +
'      background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0a0e17 100%);' +
'      color: var(--text-primary);' +
'      min-height: 100vh;' +
'      padding: 20px;' +
'    }' +
'    .container { max-width: 1400px; margin: 0 auto; }' +
'    h1 { font-size: 28px; margin-bottom: 24px; color: var(--accent); }' +
'    h2 { font-size: 18px; margin-bottom: 16px; border-bottom: 2px solid var(--accent); padding-bottom: 8px; }' +
'    .card {' +
'      background: var(--bg-card);' +
'      border-radius: 12px;' +
'      padding: 24px;' +
'      border: 1px solid var(--border);' +
'      margin-bottom: 20px;' +
'    }' +
'    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }' +
'    .stat-card {' +
'      background: var(--bg-card);' +
'      padding: 20px;' +
'      border-radius: 12px;' +
'      text-align: center;' +
'      border: 1px solid var(--border);' +
'    }' +
'    .stat-value { font-size: 28px; font-weight: 700; color: var(--accent); }' +
'    .stat-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; }' +
'    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }' +
'    .form-group { display: flex; flex-direction: column; }' +
'    .form-group label { margin-bottom: 6px; font-size: 13px; color: var(--text-secondary); }' +
'    input, select {' +
'      background: #374151;' +
'      border: 1px solid #4B5563;' +
'      color: var(--text-primary);' +
'      padding: 10px;' +
'      border-radius: 6px;' +
'      font-size: 14px;' +
'    }' +
'    input:focus, select:focus { outline: none; border-color: var(--accent); }' +
'    .btn {' +
'      padding: 10px 18px;' +
'      border: none;' +
'      border-radius: 8px;' +
'      font-weight: 600;' +
'      cursor: pointer;' +
'      transition: all 0.2s;' +
'      font-size: 14px;' +
'    }' +
'    .btn-primary { background: var(--accent); color: white; }' +
'    .btn-primary:hover { background: var(--accent-hover); }' +
'    .btn-danger { background: var(--danger); color: white; }' +
'    .btn-secondary { background: #4B5563; color: white; }' +
'    table { width: 100%; border-collapse: collapse; }' +
'    th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }' +
'    th { color: var(--text-secondary); font-size: 12px; text-transform: uppercase; }' +
'    .status-active { color: var(--success); }' +
'    .status-expired { color: var(--danger); }' +
'    #toast {' +
'      position: fixed; top: 20px; right: 20px;' +
'      background: var(--bg-card); color: white;' +
'      padding: 16px 20px; border-radius: 8px;' +
'      display: none; z-index: 1000;' +
'      border: 1px solid var(--border);' +
'    }' +
'    #toast.show { display: block; }' +
'    #toast.success { border-left: 4px solid var(--success); }' +
'    #toast.error { border-left: 4px solid var(--danger); }' +
'    .modal-overlay {' +
'      position: fixed; top: 0; left: 0; width: 100%; height: 100%;' +
'      background: rgba(0,0,0,0.7); z-index: 1000;' +
'      display: flex; justify-content: center; align-items: center;' +
'      opacity: 0; visibility: hidden; transition: all 0.3s;' +
'    }' +
'    .modal-overlay.show { opacity: 1; visibility: visible; }' +
'    .modal-content {' +
'      background: var(--bg-card); padding: 28px; border-radius: 12px;' +
'      width: 90%; max-width: 500px; border: 1px solid var(--border);' +
'    }' +
'    .header-actions { display: flex; gap: 12px; margin-bottom: 20px; }' +
'  </style>' +
'</head>' +
'<body>' +
'  <div class="container">' +
'    <h1>Admin Dashboard</h1>' +
'    <div class="header-actions">' +
'      <button id="healthCheckBtn" class="btn btn-secondary">Health Check</button>' +
'      <button id="logoutBtn" class="btn btn-danger">Logout</button>' +
'    </div>' +
'    <div class="stats">' +
'      <div class="stat-card"><div class="stat-value" id="total-users">0</div><div class="stat-label">Total Users</div></div>' +
'      <div class="stat-card"><div class="stat-value" id="active-users">0</div><div class="stat-label">Active</div></div>' +
'      <div class="stat-card"><div class="stat-value" id="expired-users">0</div><div class="stat-label">Expired</div></div>' +
'      <div class="stat-card"><div class="stat-value" id="total-traffic">0</div><div class="stat-label">Traffic</div></div>' +
'    </div>' +
'    <div class="card">' +
'      <h2>Create New User</h2>' +
'      <form id="createUserForm" class="form-grid">' +
'        <div class="form-group" style="grid-column: 1 / -1;">' +
'          <label>UUID</label>' +
'          <div style="display:flex;gap:8px;">' +
'            <input type="text" id="uuid" required style="flex:1;">' +
'            <button type="button" id="generateUUID" class="btn btn-secondary">Generate</button>' +
'          </div>' +
'        </div>' +
'        <div class="form-group"><label>Expiry Date</label><input type="date" id="expiryDate" required></div>' +
'        <div class="form-group"><label>Expiry Time</label><input type="time" id="expiryTime" step="1" required></div>' +
'        <div class="form-group"><label>Notes</label><input type="text" id="notes" placeholder="Optional"></div>' +
'        <div class="form-group">' +
'          <label>Data Limit</label>' +
'          <div style="display:flex;gap:8px;">' +
'            <input type="number" id="dataLimit" min="0" step="0.01" style="flex:1;">' +
'            <select id="dataUnit"><option value="KB">KB</option><option value="MB">MB</option><option value="GB" selected>GB</option><option value="TB">TB</option><option value="unlimited">Unlimited</option></select>' +
'          </div>' +
'        </div>' +
'        <div class="form-group"><label>IP Limit</label><input type="number" id="ipLimit" min="-1" value="-1" placeholder="-1 = Unlimited"></div>' +
'        <div class="form-group"><button type="submit" class="btn btn-primary">Create User</button></div>' +
'      </form>' +
'    </div>' +
'    <div class="card">' +
'      <h2>User Management</h2>' +
'      <input type="text" id="searchInput" placeholder="Search..." style="width:100%;margin-bottom:16px;">' +
'      <button id="deleteSelected" class="btn btn-danger" style="margin-bottom:16px;">Delete Selected</button>' +
'      <div style="overflow-x:auto;">' +
'        <table>' +
'          <thead><tr>' +
'            <th><input type="checkbox" id="selectAll"></th>' +
'            <th>UUID</th><th>Created</th><th>Expiry</th><th>Status</th><th>Notes</th><th>Limit</th><th>Usage</th><th>Actions</th>' +
'          </tr></thead>' +
'          <tbody id="userList"></tbody>' +
'        </table>' +
'      </div>' +
'    </div>' +
'  </div>' +
'  <div id="editModal" class="modal-overlay">' +
'    <div class="modal-content">' +
'      <h2>Edit User</h2>' +
'      <form id="editUserForm">' +
'        <input type="hidden" id="editUuid">' +
'        <div class="form-group" style="margin-top:16px;"><label>Expiry Date</label><input type="date" id="editExpiryDate" required></div>' +
'        <div class="form-group" style="margin-top:12px;"><label>Expiry Time</label><input type="time" id="editExpiryTime" step="1" required></div>' +
'        <div class="form-group" style="margin-top:12px;"><label>Notes</label><input type="text" id="editNotes"></div>' +
'        <div class="form-group" style="margin-top:12px;">' +
'          <label>Data Limit</label>' +
'          <div style="display:flex;gap:8px;">' +
'            <input type="number" id="editDataLimit" min="0" step="0.01" style="flex:1;">' +
'            <select id="editDataUnit"><option value="KB">KB</option><option value="MB">MB</option><option value="GB" selected>GB</option><option value="TB">TB</option><option value="unlimited">Unlimited</option></select>' +
'          </div>' +
'        </div>' +
'        <div class="form-group" style="margin-top:12px;"><label>IP Limit</label><input type="number" id="editIpLimit" min="-1"></div>' +
'        <div class="form-group" style="margin-top:12px;"><label><input type="checkbox" id="resetTraffic" style="width:auto;margin-right:8px;">Reset Traffic</label></div>' +
'        <div style="display:flex;gap:12px;margin-top:20px;">' +
'          <button type="button" id="modalCancelBtn" class="btn btn-secondary">Cancel</button>' +
'          <button type="submit" class="btn btn-primary">Save</button>' +
'        </div>' +
'      </form>' +
'    </div>' +
'  </div>' +
'  <div id="toast"></div>' +
'  <script nonce="' + nonce + '">' +
'    (function() {' +
'      var API_BASE = "' + apiBasePath + '";' +
'      var allUsers = [];' +
'      function escapeHTML(s) { if (typeof s !== "string") return ""; return s.replace(/[&<>"\']/g, function(m) { return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","\'":"&#39;"}[m]; }); }' +
'      function formatBytes(b) { if (b === 0) return "0 B"; var k = 1024, s = ["B","KB","MB","GB","TB"], i = Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(2)) + " " + s[i]; }' +
'      function showToast(msg, isErr) { var t = document.getElementById("toast"); t.textContent = msg; t.className = (isErr ? "error" : "success") + " show"; setTimeout(function() { t.className = ""; }, 3000); }' +
'      function getCsrfToken() { var m = document.cookie.match(/csrf_token=([^;]+)/); return m ? m[1] : ""; }' +
'      function api(method, endpoint, body) {' +
'        var opts = { method: method, credentials: "include", headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() } };' +
'        if (body) opts.body = JSON.stringify(body);' +
'        return fetch(API_BASE + endpoint, opts).then(function(r) {' +
'          if (r.status === 401) { showToast("Session expired", true); setTimeout(function() { location.reload(); }, 2000); throw new Error("Unauthorized"); }' +
'          if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || "Failed"); });' +
'          return r.status === 204 ? null : r.json();' +
'        });' +
'      }' +
'      function pad(n) { return n.toString().padStart(2, "0"); }' +
'      function localToUTC(d, t) {' +
'        var dt = new Date(d + "T" + t);' +
'        if (isNaN(dt.getTime())) return { utcDate: "", utcTime: "" };' +
'        return { utcDate: dt.getUTCFullYear() + "-" + pad(dt.getUTCMonth()+1) + "-" + pad(dt.getUTCDate()), utcTime: pad(dt.getUTCHours()) + ":" + pad(dt.getUTCMinutes()) + ":" + pad(dt.getUTCSeconds()) };' +
'      }' +
'      function utcToLocal(d, t) {' +
'        var dt = new Date(d + "T" + t + "Z");' +
'        if (isNaN(dt.getTime())) return { localDate: "", localTime: "" };' +
'        return { localDate: dt.getFullYear() + "-" + pad(dt.getMonth()+1) + "-" + pad(dt.getDate()), localTime: pad(dt.getHours()) + ":" + pad(dt.getMinutes()) + ":" + pad(dt.getSeconds()) };' +
'      }' +
'      function fetchStats() {' +
'        api("GET", "/stats").then(function(s) {' +
'          document.getElementById("total-users").textContent = s.total_users;' +
'          document.getElementById("active-users").textContent = s.active_users;' +
'          document.getElementById("expired-users").textContent = s.expired_users;' +
'          document.getElementById("total-traffic").textContent = formatBytes(s.total_traffic);' +
'        }).catch(function(e) { showToast(e.message, true); });' +
'      }' +
'      function renderUsers(users) {' +
'        var list = document.getElementById("userList");' +
'        list.innerHTML = "";' +
'        if (!users || users.length === 0) { list.innerHTML = "<tr><td colspan=9 style=text-align:center>No users</td></tr>"; return; }' +
'        users.forEach(function(u) {' +
'          var exp = new Date(u.expiration_date + "T" + u.expiration_time + "Z");' +
'          var isExp = exp <= new Date();' +
'          var tr = document.createElement("tr");' +
'          tr.innerHTML = "<td><input type=checkbox class=user-cb data-uuid=\\"" + u.uuid + "\\"></td>" +' +
'            "<td title=\\"" + u.uuid + "\\">" + u.uuid.substring(0,8) + "...</td>" +' +
'            "<td>" + new Date(u.created_at).toLocaleString() + "</td>" +' +
'            "<td>" + exp.toLocaleString() + "</td>" +' +
'            "<td class=\\"" + (isExp ? "status-expired" : "status-active") + "\\">" + (isExp ? "Expired" : "Active") + "</td>" +' +
'            "<td>" + escapeHTML(u.notes || "-") + "</td>" +' +
'            "<td>" + (u.traffic_limit ? formatBytes(u.traffic_limit) : "Unlimited") + "</td>" +' +
'            "<td>" + formatBytes(u.traffic_used || 0) + "</td>" +' +
'            "<td><button class=btn-edit data-uuid=\\"" + u.uuid + "\\">Edit</button> <button class=btn-del data-uuid=\\"" + u.uuid + "\\">Del</button></td>";' +
'          list.appendChild(tr);' +
'        });' +
'      }' +
'      function fetchUsers() {' +
'        api("GET", "/users").then(function(users) {' +
'          allUsers = users || [];' +
'          allUsers.sort(function(a,b) { return new Date(b.created_at) - new Date(a.created_at); });' +
'          renderUsers(allUsers);' +
'          fetchStats();' +
'        }).catch(function(e) { showToast(e.message, true); });' +
'      }' +
'      function setDefaultExpiry() {' +
'        var d = new Date(); d.setDate(d.getDate() + 30);' +
'        document.getElementById("expiryDate").value = d.getFullYear() + "-" + pad(d.getMonth()+1) + "-" + pad(d.getDate());' +
'        document.getElementById("expiryTime").value = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());' +
'      }' +
'      document.getElementById("generateUUID").addEventListener("click", function() { document.getElementById("uuid").value = crypto.randomUUID(); });' +
'      document.getElementById("createUserForm").addEventListener("submit", function(e) {' +
'        e.preventDefault();' +
'        var utc = localToUTC(document.getElementById("expiryDate").value, document.getElementById("expiryTime").value);' +
'        if (!utc.utcDate) { showToast("Invalid date/time", true); return; }' +
'        var dl = document.getElementById("dataLimit").value;' +
'        var du = document.getElementById("dataUnit").value;' +
'        var tl = null;' +
'        if (du !== "unlimited" && dl) {' +
'          var mult = { KB: 1024, MB: 1024*1024, GB: 1024*1024*1024, TB: 1024*1024*1024*1024 };' +
'          tl = parseFloat(dl) * (mult[du] || 1);' +
'        }' +
'        api("POST", "/users", {' +
'          uuid: document.getElementById("uuid").value,' +
'          exp_date: utc.utcDate,' +
'          exp_time: utc.utcTime,' +
'          notes: document.getElementById("notes").value,' +
'          traffic_limit: tl,' +
'          ip_limit: parseInt(document.getElementById("ipLimit").value) || -1' +
'        }).then(function() {' +
'          showToast("User created!");' +
'          document.getElementById("createUserForm").reset();' +
'          document.getElementById("uuid").value = crypto.randomUUID();' +
'          setDefaultExpiry();' +
'          fetchUsers();' +
'        }).catch(function(e) { showToast(e.message, true); });' +
'      });' +
'      document.getElementById("userList").addEventListener("click", function(e) {' +
'        var t = e.target;' +
'        if (t.classList.contains("btn-edit")) openEditModal(t.dataset.uuid);' +
'        else if (t.classList.contains("btn-del")) {' +
'          if (confirm("Delete user " + t.dataset.uuid + "?")) {' +
'            api("DELETE", "/users/" + t.dataset.uuid).then(function() { showToast("Deleted!"); fetchUsers(); }).catch(function(e) { showToast(e.message, true); });' +
'          }' +
'        }' +
'      });' +
'      function openEditModal(uuid) {' +
'        var u = allUsers.find(function(x) { return x.uuid === uuid; });' +
'        if (!u) return;' +
'        var loc = utcToLocal(u.expiration_date, u.expiration_time);' +
'        document.getElementById("editUuid").value = u.uuid;' +
'        document.getElementById("editExpiryDate").value = loc.localDate;' +
'        document.getElementById("editExpiryTime").value = loc.localTime;' +
'        document.getElementById("editNotes").value = u.notes || "";' +
'        if (!u.traffic_limit) { document.getElementById("editDataUnit").value = "unlimited"; document.getElementById("editDataLimit").value = ""; }' +
'        else {' +
'          var b = u.traffic_limit, unit = "KB", val = b/1024;' +
'          if (val >= 1024) { val /= 1024; unit = "MB"; }' +
'          if (val >= 1024) { val /= 1024; unit = "GB"; }' +
'          if (val >= 1024) { val /= 1024; unit = "TB"; }' +
'          document.getElementById("editDataLimit").value = val.toFixed(2);' +
'          document.getElementById("editDataUnit").value = unit;' +
'        }' +
'        document.getElementById("editIpLimit").value = u.ip_limit !== null ? u.ip_limit : -1;' +
'        document.getElementById("resetTraffic").checked = false;' +
'        document.getElementById("editModal").classList.add("show");' +
'      }' +
'      document.getElementById("modalCancelBtn").addEventListener("click", function() { document.getElementById("editModal").classList.remove("show"); });' +
'      document.getElementById("editModal").addEventListener("click", function(e) { if (e.target === this) this.classList.remove("show"); });' +
'      document.getElementById("editUserForm").addEventListener("submit", function(e) {' +
'        e.preventDefault();' +
'        var utc = localToUTC(document.getElementById("editExpiryDate").value, document.getElementById("editExpiryTime").value);' +
'        if (!utc.utcDate) { showToast("Invalid date/time", true); return; }' +
'        var dl = document.getElementById("editDataLimit").value;' +
'        var du = document.getElementById("editDataUnit").value;' +
'        var tl = null;' +
'        if (du !== "unlimited" && dl) {' +
'          var mult = { KB: 1024, MB: 1024*1024, GB: 1024*1024*1024, TB: 1024*1024*1024*1024 };' +
'          tl = parseFloat(dl) * (mult[du] || 1);' +
'        }' +
'        api("PUT", "/users/" + document.getElementById("editUuid").value, {' +
'          exp_date: utc.utcDate,' +
'          exp_time: utc.utcTime,' +
'          notes: document.getElementById("editNotes").value,' +
'          traffic_limit: tl,' +
'          ip_limit: parseInt(document.getElementById("editIpLimit").value) || -1,' +
'          reset_traffic: document.getElementById("resetTraffic").checked' +
'        }).then(function() {' +
'          showToast("Updated!");' +
'          document.getElementById("editModal").classList.remove("show");' +
'          fetchUsers();' +
'        }).catch(function(e) { showToast(e.message, true); });' +
'      });' +
'      document.getElementById("selectAll").addEventListener("change", function(e) {' +
'        document.querySelectorAll(".user-cb").forEach(function(cb) { cb.checked = e.target.checked; });' +
'      });' +
'      document.getElementById("deleteSelected").addEventListener("click", function() {' +
'        var sel = Array.from(document.querySelectorAll(".user-cb:checked")).map(function(cb) { return cb.dataset.uuid; });' +
'        if (!sel.length) { showToast("None selected", true); return; }' +
'        if (confirm("Delete " + sel.length + " users?")) {' +
'          api("POST", "/users/bulk-delete", { uuids: sel }).then(function() { showToast("Deleted!"); fetchUsers(); }).catch(function(e) { showToast(e.message, true); });' +
'        }' +
'      });' +
'      document.getElementById("searchInput").addEventListener("input", function() {' +
'        var q = this.value.toLowerCase();' +
'        var filtered = allUsers.filter(function(u) { return u.uuid.toLowerCase().includes(q) || (u.notes && u.notes.toLowerCase().includes(q)); });' +
'        renderUsers(filtered);' +
'      });' +
'      document.getElementById("logoutBtn").addEventListener("click", function() {' +
'        api("POST", "/logout", {}).then(function() { showToast("Logged out!"); setTimeout(function() { location.reload(); }, 1000); }).catch(function(e) { showToast(e.message, true); });' +
'      });' +
'      document.getElementById("healthCheckBtn").addEventListener("click", function() {' +
'        api("POST", "/health-check", {}).then(function() { showToast("Health check done!"); fetchUsers(); }).catch(function(e) { showToast(e.message, true); });' +
'      });' +
'      setDefaultExpiry();' +
'      document.getElementById("uuid").value = crypto.randomUUID();' +
'      fetchUsers();' +
'      setInterval(fetchUsers, 60000);' +
'    })();' +
'  </script>' +
'</body>' +
'</html>';
}

// ============================================================================
// ADMIN REQUEST HANDLER
// ============================================================================

async function isAdmin(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const tokenMatch = cookieHeader.match(/auth_token=([^;]+)/);
  const token = tokenMatch ? tokenMatch[1] : null;
  if (!token) return false;

  const hashedToken = await hashSHA256(token);
  const storedHashedToken = await kvGet(env.DB, 'admin_session_token_hash');
  return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
}

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  try {
    await ensureTablesExist(env, ctx);
    
    const url = new URL(request.url);
    const jsonHeader = { 'Content-Type': 'application/json' };
    const htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    const clientIp = request.headers.get('CF-Connecting-IP');

    if (!env.ADMIN_KEY) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Admin panel not configured', { status: 503, headers: htmlHeaders });
    }

    if (env.ADMIN_IP_WHITELIST) {
      const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(function(ip) { return ip.trim(); });
      if (!allowedIps.includes(clientIp)) {
        console.warn('Admin access denied for IP: ' + clientIp);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    } else {
      const scamalyticsConfig = {
        username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
      };
      if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
        console.warn('Admin access denied for suspicious IP: ' + clientIp);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    }

    if (env.ADMIN_HEADER_KEY) {
      const headerValue = request.headers.get('X-Admin-Auth');
      if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) {
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    }

    const adminBasePath = '/' + adminPrefix + '/' + env.ADMIN_KEY;

    if (!url.pathname.startsWith(adminBasePath)) {
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Not found', { status: 404, headers: headers });
    }

    const adminSubPath = url.pathname.substring(adminBasePath.length) || '/';

    // API Routes
    if (adminSubPath.startsWith('/api/')) {
      if (!env.DB) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Database not configured' }), { status: 503, headers: headers });
      }

      if (!(await isAdmin(request, env))) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: headers });
      }

      const apiRateKey = 'admin_api_rate:' + clientIp;
      if (await checkRateLimit(env.DB, apiRateKey, 100, 60)) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429, headers: headers });
      }

      if (request.method !== 'GET') {
        const origin = request.headers.get('Origin');
        const secFetch = request.headers.get('Sec-Fetch-Site');

        if (!origin || new URL(origin).hostname !== url.hostname) {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid request origin' }), { status: 403, headers: headers });
        }

        const csrfToken = request.headers.get('X-CSRF-Token');
        const cookieCsrfMatch = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/);
        const cookieCsrf = cookieCsrfMatch ? cookieCsrfMatch[1] : null;
        if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers: headers });
        }
      }

      // API: Get Stats
      if (adminSubPath === '/api/stats' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
          const expiredQuery = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')"
          ).first();
          const expiredUsers = expiredQuery?.count || 0;
          const activeUsers = totalUsers - expiredUsers;
          const totalTrafficQuery = await env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first();
          const totalTraffic = totalTrafficQuery?.sum || 0;
          
          return new Response(JSON.stringify({ 
            total_users: totalUsers, 
            active_users: activeUsers, 
            expired_users: expiredUsers, 
            total_traffic: totalTraffic
          }), { status: 200, headers: headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: headers });
        }
      }

      // API: Get Users
      if (adminSubPath === '/api/users' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { results } = await env.DB.prepare(
            "SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC"
          ).all();
          return new Response(JSON.stringify(results || []), { status: 200, headers: headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: headers });
        }
      }

      // API: Create User
      if (adminSubPath === '/api/users' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const body = await request.json();
          const uuid = body.uuid;
          const expDate = body.exp_date;
          const expTime = body.exp_time;
          const notes = body.notes;
          const traffic_limit = body.traffic_limit;
          const ip_limit = body.ip_limit;

          if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid or missing fields');
          }

          await env.DB.prepare(
            "INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)"
          ).bind(uuid, expDate, expTime, notes || null, traffic_limit, ip_limit || -1).run();

          return new Response(JSON.stringify({ success: true, uuid: uuid }), { status: 201, headers: headers });
        } catch (error) {
          if (error.message && error.message.includes('UNIQUE constraint failed')) {
            return new Response(JSON.stringify({ error: 'UUID already exists' }), { status: 409, headers: headers });
          }
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: headers });
        }
      }

      // API: Bulk Delete
      if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const body = await request.json();
          const uuids = body.uuids;
          if (!Array.isArray(uuids) || uuids.length === 0) {
            throw new Error('Invalid request: Expected array of UUIDs');
          }

          const deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?");
          const stmts = uuids.map(function(uuid) { return deleteUserStmt.bind(uuid); });
          await env.DB.batch(stmts);

          return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers: headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: headers });
        }
      }

      // API: Update User
      const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);
      if (userRouteMatch && request.method === 'PUT') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          const body = await request.json();
          const expDate = body.exp_date;
          const expTime = body.exp_time;
          const notes = body.notes;
          const traffic_limit = body.traffic_limit;
          const ip_limit = body.ip_limit;
          const reset_traffic = body.reset_traffic;
          
          if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid date/time format');
          }

          var query = "UPDATE users SET expiration_date = ?, expiration_time = ?, notes = ?, traffic_limit = ?, ip_limit = ?";
          var binds = [expDate, expTime, notes || null, traffic_limit, ip_limit || -1];
          
          if (reset_traffic) {
            query += ", traffic_used = 0";
          }
          
          query += " WHERE uuid = ?";
          binds.push(uuid);

          await env.DB.prepare(query).bind.apply(env.DB.prepare(query), binds).run();
          ctx.waitUntil(kvDelete(env.DB, 'user:' + uuid));

          return new Response(JSON.stringify({ success: true, uuid: uuid }), { status: 200, headers: headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: headers });
        }
      }

      // API: Delete User
      if (userRouteMatch && request.method === 'DELETE') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
          ctx.waitUntil(kvDelete(env.DB, 'user:' + uuid));
          return new Response(JSON.stringify({ success: true, uuid: uuid }), { status: 200, headers: headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: headers });
        }
      }

      // API: Logout
      if (adminSubPath === '/api/logout' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await kvDelete(env.DB, 'admin_session_token_hash');
          headers.append('Set-Cookie', 'auth_token=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
          headers.append('Set-Cookie', 'csrf_token=; Max-Age=0; Path=/; Secure; SameSite=Strict');
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: headers });
        }
      }

      // API: Health Check
      if (adminSubPath === '/api/health-check' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await performHealthCheck(env, ctx);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: headers });
        }
      }

      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers: headers });
    }

    // Login Page
    if (adminSubPath === '/') {
      if (request.method === 'POST') {
        const rateLimitKey = 'login_fail_ip:' + clientIp;
        
        try {
          const failCountStr = await kvGet(env.DB, rateLimitKey);
          const failCount = parseInt(failCountStr, 10) || 0;
          
          if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
            addSecurityHeaders(htmlHeaders, null, {});
            return new Response('Too many failed attempts. Try again later.', { status: 429, headers: htmlHeaders });
          }
          
          const formData = await request.formData();
          
          if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
            if (env.ADMIN_TOTP_SECRET) {
              const totpCode = formData.get('totp');
              if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpCode))) {
                const nonce = generateNonce();
                addSecurityHeaders(htmlHeaders, nonce, {});
                ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
                return new Response(getAdminLoginHTML(nonce, adminBasePath, 'Invalid TOTP code. Attempt ' + (failCount + 1) + '/' + CONST.ADMIN_LOGIN_FAIL_LIMIT), { status: 401, headers: htmlHeaders });
              }
            }
            
            const token = crypto.randomUUID();
            const csrfToken = crypto.randomUUID();
            const hashedToken = await hashSHA256(token);
            
            ctx.waitUntil(Promise.all([
              kvPut(env.DB, 'admin_session_token_hash', hashedToken, { expirationTtl: 86400 }),
              kvDelete(env.DB, rateLimitKey)
            ]));
            
            const headers = new Headers({ 'Location': adminBasePath });
            headers.append('Set-Cookie', 'auth_token=' + token + '; HttpOnly; Secure; Path=' + adminBasePath + '; Max-Age=86400; SameSite=Strict');
            headers.append('Set-Cookie', 'csrf_token=' + csrfToken + '; Secure; Path=' + adminBasePath + '; Max-Age=86400; SameSite=Strict');
            addSecurityHeaders(headers, null, {});
            
            return new Response(null, { status: 302, headers: headers });
          } else {
            ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
            
            const nonce = generateNonce();
            addSecurityHeaders(htmlHeaders, nonce, {});
            return new Response(getAdminLoginHTML(nonce, adminBasePath, 'Invalid password. Attempt ' + (failCount + 1) + '/' + CONST.ADMIN_LOGIN_FAIL_LIMIT), { status: 401, headers: htmlHeaders });
          }
        } catch (e) {
          console.error("Admin login error:", e);
          addSecurityHeaders(htmlHeaders, null, {});
          return new Response('Internal error during login', { status: 500, headers: htmlHeaders });
        }
      }

      if (request.method === 'GET') {
        const nonce = generateNonce();
        addSecurityHeaders(htmlHeaders, nonce, {});
        
        var html;
        if (await isAdmin(request, env)) {
          html = getAdminPanelHTML(nonce, adminBasePath + '/api');
        } else {
          html = getAdminLoginHTML(nonce, adminBasePath, '');
        }
        
        return new Response(html, { headers: htmlHeaders });
      }

      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Method Not Allowed', { status: 405, headers: headers });
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers: headers });
  } catch (e) {
    console.error('handleAdminRequest error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers: headers });
  }
}

// ============================================================================
// USER PANEL HTML WITH WORKING QR CODE GENERATOR
// ============================================================================

async function resolveProxyIP(proxyHost) {
  const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;

  if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
    return proxyHost;
  }

  const dnsAPIs = [
    { url: 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(proxyHost) + '&type=A', parse: function(data) { var a = data.Answer; return a ? (a.find(function(x) { return x.type === 1; }) || {}).data : null; } },
    { url: 'https://dns.google/resolve?name=' + encodeURIComponent(proxyHost) + '&type=A', parse: function(data) { var a = data.Answer; return a ? (a.find(function(x) { return x.type === 1; }) || {}).data : null; } }
  ];

  for (var i = 0; i < dnsAPIs.length; i++) {
    const api = dnsAPIs[i];
    try {
      const response = await fetch(api.url, { headers: { 'accept': 'application/dns-json' } });
      if (response.ok) {
        const data = await response.json();
        const ip = api.parse(data);
        if (ip && ipv4Regex.test(ip)) return ip;
      }
    } catch (e) {
      // Try next provider
    }
  }
  return proxyHost;
}

async function getGeo(ip, cfHeaders) {
  if (cfHeaders && (cfHeaders.city || cfHeaders.country)) {
    return {
      city: cfHeaders.city || '',
      country: cfHeaders.country || '',
      isp: cfHeaders.asOrganization || ''
    };
  }
  
  const geoAPIs = [
    {
      url: 'https://ip-api.com/json/' + ip + '?fields=status,message,city,country,isp',
      parse: async function(r) {
        const data = await r.json();
        if (data.status === 'fail') throw new Error(data.message || 'API Error');
        return { city: data.city || '', country: data.country || '', isp: data.isp || '' };
      }
    },
    {
      url: 'https://ipwho.is/' + ip,
      parse: async function(r) {
        const data = await r.json();
        if (!data.success) throw new Error('API Error');
        return { city: data.city || '', country: data.country || '', isp: (data.connection ? data.connection.isp : '') || '' };
      }
    }
  ];

  for (var i = 0; i < geoAPIs.length; i++) {
    const api = geoAPIs[i];
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(function() { controller.abort(); }, 3000);
      
      const response = await fetch(api.url, { 
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const geo = await api.parse(response);
        if (geo && (geo.city || geo.country)) return geo;
      }
    } catch (e) {
      // Try next provider
    }
  }
  
  return { city: '', country: 'Global', isp: 'Cloudflare' };
}

function getUserPanelHTML(opts) {
  const nonce = opts.nonce;
  const userID = opts.userID;
  const hostName = opts.hostName;
  const proxyAddress = opts.proxyAddress;
  const proxyIP = opts.proxyIP;
  const proxyGeo = opts.proxyGeo;
  const clientIp = opts.clientIp;
  const clientGeo = opts.clientGeo;
  const userData = opts.userData;
  const singleXrayConfig = opts.singleXrayConfig;
  const singleSingboxConfig = opts.singleSingboxConfig;
  const subXrayUrl = opts.subXrayUrl;
  const subSbUrl = opts.subSbUrl;
  const isUserExpired = opts.isUserExpired;
  const usageDisplay = opts.usageDisplay;
  const trafficLimitStr = opts.trafficLimitStr;
  const usagePercentage = opts.usagePercentage;
  const expirationDateTime = opts.expirationDateTime;
  
  const proxyLocation = [proxyGeo.city, proxyGeo.country].filter(Boolean).join(', ') || 'Unknown';
  const clientLocation = [clientGeo.city, clientGeo.country].filter(Boolean).join(', ') || 'Unknown';

  return '<!DOCTYPE html>' +
'<html lang="en">' +
'<head>' +
'  <meta charset="UTF-8">' +
'  <meta name="viewport" content="width=device-width, initial-scale=1.0">' +
'  <title>User Panel - VLESS Configuration</title>' +
'  <style nonce="' + nonce + '">' +
'    :root {' +
'      --bg: #0b1220; --card: #0f1724; --muted: #9aa4b2; --accent: #3b82f6;' +
'      --success: #22c55e; --danger: #ef4444; --warning: #f59e0b;' +
'    }' +
'    * { box-sizing: border-box; margin: 0; padding: 0; }' +
'    body {' +
'      font-family: Inter, system-ui, -apple-system, sans-serif;' +
'      background: linear-gradient(135deg, #030712 0%, #0f172a 50%, #030712 100%);' +
'      color: #e6eef8; min-height: 100vh; padding: 20px;' +
'    }' +
'    .container { max-width: 1100px; margin: 0 auto; }' +
'    .card {' +
'      background: rgba(15, 23, 36, 0.9);' +
'      backdrop-filter: blur(20px);' +
'      border-radius: 16px; padding: 24px;' +
'      border: 1px solid rgba(255,255,255,0.06);' +
'      margin-bottom: 20px;' +
'    }' +
'    h1 { font-size: 28px; margin-bottom: 8px; color: var(--accent); }' +
'    h2 { font-size: 18px; margin-bottom: 16px; border-bottom: 2px solid var(--accent); padding-bottom: 8px; }' +
'    .lead { color: var(--muted); margin-bottom: 24px; }' +
'    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }' +
'    .stat {' +
'      padding: 16px; background: rgba(30, 41, 59, 0.6);' +
'      border-radius: 12px; text-align: center;' +
'      border: 1px solid rgba(255,255,255,0.04);' +
'    }' +
'    .stat .val { font-size: 22px; font-weight: 700; margin-bottom: 4px; }' +
'    .stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; }' +
'    .stat.active .val { color: var(--success); }' +
'    .stat.expired .val { color: var(--danger); }' +
'    .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-top: 16px; }' +
'    .info-item { background: rgba(255,255,255,0.02); padding: 12px; border-radius: 8px; }' +
'    .info-item .label { font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px; }' +
'    .info-item .value { font-weight: 600; word-break: break-all; font-size: 13px; }' +
'    .progress-bar {' +
'      height: 12px; background: rgba(7,21,41,0.8);' +
'      border-radius: 8px; overflow: hidden; margin: 12px 0;' +
'    }' +
'    .progress-fill { height: 100%; border-radius: 8px; transition: width 1s ease; }' +
'    .progress-fill.low { background: linear-gradient(90deg, #22c55e, #16a34a); }' +
'    .progress-fill.medium { background: linear-gradient(90deg, #f59e0b, #d97706); }' +
'    .progress-fill.high { background: linear-gradient(90deg, #ef4444, #dc2626); }' +
'    .btn {' +
'      display: inline-flex; align-items: center; gap: 8px;' +
'      padding: 10px 16px; border-radius: 8px; border: none;' +
'      cursor: pointer; font-weight: 600; font-size: 14px;' +
'      transition: all 0.2s; text-decoration: none; color: inherit;' +
'    }' +
'    .btn.primary { background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; }' +
'    .btn.primary:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(59,130,246,0.4); }' +
'    .btn.ghost { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: var(--muted); }' +
'    .btn.ghost:hover { background: rgba(255,255,255,0.1); color: white; }' +
'    .buttons { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }' +
'    pre.config {' +
'      background: #071529; padding: 12px; border-radius: 8px;' +
'      overflow: auto; font-family: monospace; font-size: 12px;' +
'      color: #cfe8ff; max-height: 180px; display: none; margin-top: 12px;' +
'    }' +
'    pre.config.show { display: block; }' +
'    .qr-container {' +
'      background: white; padding: 20px; border-radius: 16px;' +
'      display: inline-block; box-shadow: 0 8px 25px rgba(0,0,0,0.2);' +
'      margin: 16px 0;' +
'    }' +
'    #qr-display { min-height: 280px; display: flex; align-items: center; justify-content: center; flex-direction: column; }' +
'    #toast {' +
'      position: fixed; right: 20px; top: 20px;' +
'      background: rgba(15,27,42,0.98); backdrop-filter: blur(20px);' +
'      padding: 14px 18px; border-radius: 12px;' +
'      border: 1px solid rgba(255,255,255,0.08);' +
'      display: none; color: #cfe8ff; z-index: 1000;' +
'    }' +
'    #toast.show { display: block; }' +
'    #toast.success { border-left: 4px solid var(--success); }' +
'    #toast.error { border-left: 4px solid var(--danger); }' +
'    .grid { display: grid; grid-template-columns: 1fr 360px; gap: 20px; }' +
'    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }' +
'    .text-center { text-align: center; }' +
'    .expiry-warning { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); padding: 12px; border-radius: 8px; margin-top: 12px; color: #fca5a5; }' +
'    .expiry-info { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); padding: 12px; border-radius: 8px; margin-top: 12px; color: #86efac; }' +
'  </style>' +
'</head>' +
'<body>' +
'  <div class="container">' +
'    <h1>VXR.SXR Configuration Panel</h1>' +
'    <p class="lead">Manage your proxy configuration and view subscription links.</p>' +
'    <div class="stats">' +
'      <div class="stat ' + (isUserExpired ? 'expired' : 'active') + '">' +
'        <div class="val">' + (isUserExpired ? 'Expired' : 'Active') + '</div>' +
'        <div class="lbl">Status</div>' +
'      </div>' +
'      <div class="stat">' +
'        <div class="val">' + usageDisplay + '</div>' +
'        <div class="lbl">Data Used</div>' +
'      </div>' +
'      <div class="stat">' +
'        <div class="val">' + trafficLimitStr + '</div>' +
'        <div class="lbl">Data Limit</div>' +
'      </div>' +
'      <div class="stat">' +
'        <div class="val" id="expiry-countdown">--</div>' +
'        <div class="lbl">Time Left</div>' +
'      </div>' +
'    </div>' +
(userData.traffic_limit && userData.traffic_limit > 0 ? 
'    <div class="card">' +
'      <h2>Usage Statistics</h2>' +
'      <div class="progress-bar">' +
'        <div class="progress-fill ' + (usagePercentage > 80 ? 'high' : usagePercentage > 50 ? 'medium' : 'low') + '" style="width:' + usagePercentage.toFixed(2) + '%"></div>' +
'      </div>' +
'      <p class="text-center" style="color:var(--muted);">' + usageDisplay + ' of ' + trafficLimitStr + ' (' + usagePercentage.toFixed(2) + '%)</p>' +
'    </div>' : '') +
(expirationDateTime ? 
'    <div class="card">' +
'      <h2>Expiration</h2>' +
'      <p id="expiry-local" style="color:var(--muted);">Loading...</p>' +
(isUserExpired ? '<div class="expiry-warning">Your account has expired. Please contact admin to renew.</div>' : '<div class="expiry-info">Your account is active.</div>') +
'    </div>' : '') +
'    <div class="grid">' +
'      <div>' +
'        <div class="card">' +
'          <h2>Network Information</h2>' +
'          <div class="info-grid">' +
'            <div class="info-item"><span class="label">Proxy Host</span><span class="value">' + escapeHTML(proxyAddress || hostName) + '</span></div>' +
'            <div class="info-item"><span class="label">Proxy IP</span><span class="value">' + escapeHTML(proxyIP) + '</span></div>' +
'            <div class="info-item"><span class="label">Proxy Location</span><span class="value">' + escapeHTML(proxyLocation) + '</span></div>' +
'            <div class="info-item"><span class="label">Your IP</span><span class="value">' + escapeHTML(clientIp) + '</span></div>' +
'            <div class="info-item"><span class="label">Your Location</span><span class="value">' + escapeHTML(clientLocation) + '</span></div>' +
'            <div class="info-item"><span class="label">Your ISP</span><span class="value">' + escapeHTML(clientGeo.isp || 'Unknown') + '</span></div>' +
'          </div>' +
'        </div>' +
'        <div class="card">' +
'          <h2>Subscription Links</h2>' +
'          <h3 style="font-size:15px;margin:12px 0 8px;color:var(--accent);">Xray / V2Ray</h3>' +
'          <div class="buttons">' +
'            <button class="btn primary" id="btn-copy-xray-sub">Copy Sub Link</button>' +
'            <button class="btn ghost" id="btn-copy-xray-config">Copy Config</button>' +
'            <button class="btn ghost" id="btn-toggle-xray">View Config</button>' +
'            <button class="btn ghost" id="btn-qr-xray">QR Code</button>' +
'          </div>' +
'          <pre class="config" id="xray-config">' + escapeHTML(singleXrayConfig) + '</pre>' +
'          <h3 style="font-size:15px;margin:16px 0 8px;color:var(--accent);">Sing-Box / Clash</h3>' +
'          <div class="buttons">' +
'            <button class="btn primary" id="btn-copy-sb-sub">Copy Sub Link</button>' +
'            <button class="btn ghost" id="btn-copy-sb-config">Copy Config</button>' +
'            <button class="btn ghost" id="btn-toggle-sb">View Config</button>' +
'            <button class="btn ghost" id="btn-qr-sb">QR Code</button>' +
'          </div>' +
'          <pre class="config" id="sb-config">' + escapeHTML(singleSingboxConfig) + '</pre>' +
'        </div>' +
'      </div>' +
'      <aside>' +
'        <div class="card">' +
'          <h2>QR Code Scanner</h2>' +
'          <p style="color:var(--muted);margin-bottom:12px;">Scan with your VPN app to import config.</p>' +
'          <div id="qr-display" class="text-center">' +
'            <p style="color:var(--muted);">Click a QR Code button to generate.</p>' +
'          </div>' +
'        </div>' +
'        <div class="card">' +
'          <h2>Account Details</h2>' +
'          <div class="info-item" style="margin-top:12px;">' +
'            <span class="label">UUID</span>' +
'            <span class="value" style="font-family:monospace;font-size:11px;">' + escapeHTML(userID) + '</span>' +
'          </div>' +
'          <div class="info-item" style="margin-top:12px;">' +
'            <span class="label">Created</span>' +
'            <span class="value">' + (userData.created_at ? new Date(userData.created_at).toLocaleDateString() : 'N/A') + '</span>' +
'          </div>' +
(userData.notes ? '<div class="info-item" style="margin-top:12px;"><span class="label">Notes</span><span class="value">' + escapeHTML(userData.notes) + '</span></div>' : '') +
'          <div class="info-item" style="margin-top:12px;">' +
'            <span class="label">IP Limit</span>' +
'            <span class="value">' + (userData.ip_limit === -1 ? 'Unlimited' : userData.ip_limit) + '</span>' +
'          </div>' +
'        </div>' +
'      </aside>' +
'    </div>' +
'    <div class="card">' +
'      <p class="text-center" style="color:var(--muted);">Keep your subscription links private. For support, contact your administrator.</p>' +
'    </div>' +
'  </div>' +
'  <div id="toast"></div>' +
'  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" integrity="sha512-CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==" crossorigin="anonymous" referrerpolicy="no-referrer"><\/script>' +
'  <script nonce="' + nonce + '">' +
'    (function() {' +
'      var CONFIG = {' +
'        uuid: "' + userID + '",' +
'        subXrayUrl: "' + subXrayUrl + '",' +
'        subSbUrl: "' + subSbUrl + '",' +
'        singleXrayConfig: ' + JSON.stringify(singleXrayConfig) + ',' +
'        singleSingboxConfig: ' + JSON.stringify(singleSingboxConfig) + ',' +
'        expirationDateTime: ' + (expirationDateTime ? '"' + expirationDateTime + '"' : 'null') +
'      };' +
'      function showToast(msg, isErr) {' +
'        var t = document.getElementById("toast");' +
'        t.textContent = msg;' +
'        t.className = (isErr ? "error" : "success") + " show";' +
'        setTimeout(function() { t.className = ""; }, 3000);' +
'      }' +
'      function copyText(text, btn) {' +
'        navigator.clipboard.writeText(text).then(function() {' +
'          var orig = btn.textContent;' +
'          btn.textContent = "Copied!";' +
'          showToast("Copied to clipboard!", false);' +
'          setTimeout(function() { btn.textContent = orig; }, 2000);' +
'        }).catch(function() {' +
'          var ta = document.createElement("textarea");' +
'          ta.value = text;' +
'          ta.style.cssText = "position:fixed;top:-9999px;";' +
'          document.body.appendChild(ta);' +
'          ta.select();' +
'          try { document.execCommand("copy"); showToast("Copied!", false); }' +
'          catch(e) { showToast("Copy failed", true); }' +
'          document.body.removeChild(ta);' +
'        });' +
'      }' +
'      function generateQR(text) {' +
'        var container = document.getElementById("qr-display");' +
'        container.innerHTML = "";' +
'        if (!text || text.length === 0) {' +
'          container.innerHTML = "<p style=color:#ef4444>No config data to generate QR code.</p>";' +
'          showToast("No config data", true);' +
'          return;' +
'        }' +
'        var cleanText = text.trim();' +
'        if (cleanText.length > 2953) {' +
'          container.innerHTML = "<p style=color:#ef4444>Config too large for QR code. Please copy the link instead.</p>";' +
'          showToast("Config too large for QR", true);' +
'          return;' +
'        }' +
'        try {' +
'          if (typeof QRCode !== "undefined") {' +
'            var qrDiv = document.createElement("div");' +
'            qrDiv.className = "qr-container";' +
'            new QRCode(qrDiv, {' +
'              text: cleanText,' +
'              width: 256,' +
'              height: 256,' +
'              colorDark: "#000000",' +
'              colorLight: "#ffffff",' +
'              correctLevel: QRCode.CorrectLevel.L' +
'            });' +
'            container.appendChild(qrDiv);' +
'            showToast("QR Code generated!", false);' +
'          } else {' +
'            throw new Error("QRCode library not loaded");' +
'          }' +
'        } catch (e) {' +
'          console.error("QR generation failed:", e);' +
'          var encoded = encodeURIComponent(cleanText);' +
'          var googleUrl = "https://chart.googleapis.com/chart?cht=qr&chl=" + encoded + "&chs=256x256&choe=UTF-8&chld=L|1";' +
'          if (googleUrl.length > 2000) {' +
'            container.innerHTML = "<p style=color:#ef4444>Config too large. Please copy the link instead.</p>";' +
'            showToast("Config too large for QR", true);' +
'            return;' +
'          }' +
'          var wrapper = document.createElement("div");' +
'          wrapper.className = "qr-container";' +
'          var img = document.createElement("img");' +
'          img.src = googleUrl;' +
'          img.alt = "QR Code";' +
'          img.style.cssText = "display:block;width:256px;height:256px;";' +
'          img.onerror = function() {' +
'            container.innerHTML = "<p style=color:#ef4444>QR generation failed. Copy the link instead.</p>";' +
'            showToast("QR generation failed", true);' +
'          };' +
'          img.onload = function() { showToast("QR Code generated!", false); };' +
'          wrapper.appendChild(img);' +
'          container.appendChild(wrapper);' +
'        }' +
'      }' +
'      document.getElementById("btn-copy-xray-sub").addEventListener("click", function() { copyText(CONFIG.subXrayUrl, this); });' +
'      document.getElementById("btn-copy-xray-config").addEventListener("click", function() { copyText(CONFIG.singleXrayConfig, this); });' +
'      document.getElementById("btn-toggle-xray").addEventListener("click", function() { document.getElementById("xray-config").classList.toggle("show"); });' +
'      document.getElementById("btn-qr-xray").addEventListener("click", function() { generateQR(CONFIG.singleXrayConfig); });' +
'      document.getElementById("btn-copy-sb-sub").addEventListener("click", function() { copyText(CONFIG.subSbUrl, this); });' +
'      document.getElementById("btn-copy-sb-config").addEventListener("click", function() { copyText(CONFIG.singleSingboxConfig, this); });' +
'      document.getElementById("btn-toggle-sb").addEventListener("click", function() { document.getElementById("sb-config").classList.toggle("show"); });' +
'      document.getElementById("btn-qr-sb").addEventListener("click", function() { generateQR(CONFIG.singleSingboxConfig); });' +
'      function updateExpiry() {' +
'        if (!CONFIG.expirationDateTime) {' +
'          document.getElementById("expiry-countdown").textContent = "Unlimited";' +
'          var el = document.getElementById("expiry-local");' +
'          if (el) el.textContent = "No expiration set";' +
'          return;' +
'        }' +
'        var exp = new Date(CONFIG.expirationDateTime);' +
'        if (isNaN(exp.getTime())) {' +
'          document.getElementById("expiry-countdown").textContent = "Invalid";' +
'          return;' +
'        }' +
'        var now = new Date();' +
'        var diff = Math.floor((exp - now) / 1000);' +
'        var countdownEl = document.getElementById("expiry-countdown");' +
'        var localEl = document.getElementById("expiry-local");' +
'        if (diff < 0) {' +
'          countdownEl.textContent = "Expired";' +
'          return;' +
'        }' +
'        var d = Math.floor(diff / 86400);' +
'        var h = Math.floor((diff % 86400) / 3600);' +
'        var m = Math.floor((diff % 3600) / 60);' +
'        if (d > 0) countdownEl.textContent = d + "d " + h + "h";' +
'        else if (h > 0) countdownEl.textContent = h + "h " + m + "m";' +
'        else countdownEl.textContent = m + "m";' +
'        if (localEl) localEl.textContent = "Expires: " + exp.toLocaleString();' +
'      }' +
'      updateExpiry();' +
'      setInterval(updateExpiry, 1000);' +
'    })();' +
'  <\/script>' +
'</body>' +
'</html>';
}

async function handleUserPanel(request, userID, hostName, proxyAddress, userData, clientIp) {
  try {
    const subXrayUrl = 'https://' + hostName + '/xray/' + userID;
    const subSbUrl = 'https://' + hostName + '/sb/' + userID;
    
    const singleXrayConfig = buildLink({ 
      core: 'xray', 
      proto: 'tls', 
      userID: userID, 
      hostName: hostName, 
      address: hostName, 
      port: 443, 
      tag: 'Main' 
    });
  
    const singleSingboxConfig = buildLink({ 
      core: 'sb', 
      proto: 'tls', 
      userID: userID, 
      hostName: hostName, 
      address: hostName, 
      port: 443, 
      tag: 'Main' 
    });

    const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
    const expirationDateTime = userData.expiration_date && userData.expiration_time 
      ? userData.expiration_date + 'T' + userData.expiration_time + 'Z'
      : null;

    var usagePercentage = 0;
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
    }

    const requestCf = request.cf || {};
    const clientGeo = {
      city: requestCf.city || '',
      country: requestCf.country || '',
      isp: requestCf.asOrganization || ''
    };

    const proxyHost = proxyAddress.split(':')[0];
    const proxyIP = await resolveProxyIP(proxyHost);
    const proxyGeo = await getGeo(proxyIP) || { city: '', country: '', isp: '' };

    const usageDisplay = formatBytes(userData.traffic_used || 0);
    var trafficLimitStr = 'Unlimited';
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      trafficLimitStr = formatBytes(userData.traffic_limit);
    }

    const nonce = generateNonce();
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, nonce, { img: 'data: https:', connect: 'https:' });
    
    const html = getUserPanelHTML({
      nonce: nonce,
      userID: userID,
      hostName: hostName,
      proxyAddress: proxyAddress,
      proxyIP: proxyIP,
      proxyGeo: proxyGeo,
      clientIp: clientIp,
      clientGeo: clientGeo,
      userData: userData,
      singleXrayConfig: singleXrayConfig,
      singleSingboxConfig: singleSingboxConfig,
      subXrayUrl: subXrayUrl,
      subSbUrl: subSbUrl,
      isUserExpired: isUserExpired,
      usageDisplay: usageDisplay,
      trafficLimitStr: trafficLimitStr,
      usagePercentage: usagePercentage,
      expirationDateTime: expirationDateTime
    });

    return new Response(html, { headers: headers });
  } catch (e) {
    console.error('handleUserPanel error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers: headers });
  }
}

// ============================================================================
// VLESS PROTOCOL HANDLERS
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  var webSocket = null;
  try {
    const clientIp = request.headers.get('CF-Connecting-IP');
    
    if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
      return new Response('Access denied', { status: 403 });
    }

    const webSocketPair = new WebSocketPair();
    const client = webSocketPair[0];
    const webSocket_inner = webSocketPair[1];
    webSocket = webSocket_inner;
    webSocket.accept();

    var address = '';
    var portWithRandomLog = '';
    var sessionUsage = 0;
    var userUUID = '';
    var udpStreamWriter = null;

    function log(info, event) {
      console.log('[' + address + ':' + portWithRandomLog + '] ' + info, event || '');
    }

    function deferredUsageUpdate() {
      if (sessionUsage > 0 && userUUID) {
        const usageToUpdate = sessionUsage;
        const uuidToUpdate = userUUID;
        sessionUsage = 0;
        
        ctx.waitUntil(
          updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
            .catch(function(err) { console.error('Deferred usage update failed for ' + uuidToUpdate + ':', err); })
        );
      }
    }

    const updateInterval = setInterval(deferredUsageUpdate, 10000);

    function finalCleanup() {
      clearInterval(updateInterval);
      deferredUsageUpdate();
    }

    webSocket.addEventListener('close', finalCleanup, { once: true });
    webSocket.addEventListener('error', finalCleanup, { once: true });

    const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
    const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    var remoteSocketWrapper = { value: null };

    readableWebSocketStream
      .pipeTo(
        new WritableStream({
          async write(chunk, controller) {
            sessionUsage += chunk.byteLength;

            if (udpStreamWriter) {
              return udpStreamWriter.write(chunk);
            }

            if (remoteSocketWrapper.value) {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              await writer.write(chunk);
              writer.releaseLock();
              return;
            }

            const headerResult = await ProcessProtocolHeader(chunk, env, ctx);

            if (headerResult.hasError || !headerResult.user) {
              controller.error(new Error('Authentication failed'));
              return;
            }

            userUUID = headerResult.user.uuid;

            if (isExpired(headerResult.user.expiration_date, headerResult.user.expiration_time)) {
              controller.error(new Error('Account expired'));
              return;
            }

            if (headerResult.user.traffic_limit && headerResult.user.traffic_limit > 0) {
              const totalUsage = (headerResult.user.traffic_used || 0) + sessionUsage;
              if (totalUsage >= headerResult.user.traffic_limit) {
                controller.error(new Error('Traffic limit exceeded'));
                return;
              }
            }

            if (headerResult.user.ip_limit && headerResult.user.ip_limit > -1) {
              const ipCountResult = await env.DB.prepare(
                "SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?"
              ).bind(userUUID).first('count');
              const ipCount = ipCountResult || 0;
              
              if (ipCount >= headerResult.user.ip_limit) {
                const existingIp = await env.DB.prepare(
                  "SELECT ip FROM user_ips WHERE uuid = ? AND ip = ?"
                ).bind(userUUID, clientIp).first();
                
                if (!existingIp) {
                  controller.error(new Error('IP limit exceeded'));
                  return;
                }
              }
              
              await env.DB.prepare(
                "INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)"
              ).bind(userUUID, clientIp).run();
            }

            address = headerResult.addressRemote;
            portWithRandomLog = headerResult.portRemote + '--' + Math.random() + (headerResult.isUDP ? ' udp' : ' tcp');
            const vlessResponseHeader = new Uint8Array([headerResult.ProtocolVersion[0], 0]);
            const rawClientData = chunk.slice(headerResult.rawDataIndex);

            if (headerResult.isUDP) {
              if (headerResult.portRemote === 53) {
                const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, function(bytes) {
                  sessionUsage += bytes;
                });
                udpStreamWriter = dnsPipeline.write;
                await udpStreamWriter(rawClientData);
              } else {
                controller.error(new Error('UDP only supported for DNS (port 53)'));
              }
              return;
            }

            HandleTCPOutBound(
              remoteSocketWrapper,
              headerResult.addressType,
              headerResult.addressRemote,
              headerResult.portRemote,
              rawClientData,
              webSocket,
              vlessResponseHeader,
              log,
              config,
              function(bytes) { sessionUsage += bytes; }
            );
          },
          close: function() {
            log('readableWebSocketStream closed');
            finalCleanup();
          },
          abort: function(err) {
            log('readableWebSocketStream aborted', err);
            finalCleanup();
          },
        })
      )
      .catch(function(err) {
        console.error('Pipeline failed:', err.stack || err);
        safeCloseWebSocket(webSocket);
        finalCleanup();
      });

    return new Response(null, { status: 101, webSocket: client });
  } catch (e) {
    console.error('ProtocolOverWSHandler error:', e.message, e.stack);
    if (webSocket) {
      try {
        safeCloseWebSocket(webSocket);
      } catch (closeErr) {
        console.error('Error closing WebSocket:', closeErr);
      }
    }
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers: headers });
  }
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  try {
    if (protocolBuffer.byteLength < 24) {
      return { hasError: true, message: 'invalid data' };
    }
  
    const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
    const version = dataView.getUint8(0);

    var uuid;
    try {
      uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
    } catch (e) {
      return { hasError: true, message: 'invalid UUID format' };
    }

    const userData = await getUserData(env, uuid, ctx);
    if (!userData) {
      return { hasError: true, message: 'invalid user' };
    }

    const payloadStart = 17;
    if (protocolBuffer.byteLength < payloadStart + 1) {
      return { hasError: true, message: 'invalid data length' };
    }

    const optLength = dataView.getUint8(payloadStart);
    const commandIndex = payloadStart + 1 + optLength;
    
    if (protocolBuffer.byteLength < commandIndex + 1) {
      return { hasError: true, message: 'invalid data length (command)' };
    }
    
    const command = dataView.getUint8(commandIndex);
    if (command !== 1 && command !== 2) {
      return { hasError: true, message: 'command ' + command + ' not supported' };
    }

    const portIndex = commandIndex + 1;
    if (protocolBuffer.byteLength < portIndex + 2) {
      return { hasError: true, message: 'invalid data length (port)' };
    }
    
    const portRemote = dataView.getUint16(portIndex, false);

    const addressTypeIndex = portIndex + 2;
    if (protocolBuffer.byteLength < addressTypeIndex + 1) {
      return { hasError: true, message: 'invalid data length (address type)' };
    }
    
    const addressType = dataView.getUint8(addressTypeIndex);

    var addressValue, addressLength, addressValueIndex;

    switch (addressType) {
      case 1:
        addressLength = 4;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (ipv4)' };
        }
        addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
        break;
        
      case 2:
        if (protocolBuffer.byteLength < addressTypeIndex + 2) {
          return { hasError: true, message: 'invalid data length (domain length)' };
        }
        addressLength = dataView.getUint8(addressTypeIndex + 1);
        addressValueIndex = addressTypeIndex + 2;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (domain)' };
        }
        addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
        
      case 3:
        addressLength = 16;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (ipv6)' };
        }
        var ipv6Parts = [];
        for (var i = 0; i < 8; i++) {
          ipv6Parts.push(dataView.getUint16(addressValueIndex + i * 2, false).toString(16));
        }
        addressValue = ipv6Parts.join(':');
        break;
        
      default:
        return { hasError: true, message: 'invalid addressType: ' + addressType };
    }

    const rawDataIndex = addressValueIndex + addressLength;
    if (protocolBuffer.byteLength < rawDataIndex) {
      return { hasError: true, message: 'invalid data length (raw data)' };
    }

    return {
      user: userData,
      hasError: false,
      addressRemote: addressValue,
      addressType: addressType,
      portRemote: portRemote,
      rawDataIndex: rawDataIndex,
      ProtocolVersion: new Uint8Array([version]),
      isUDP: command === 2,
    };
  } catch (e) {
    console.error('ProcessProtocolHeader error:', e.message, e.stack);
    return { hasError: true, message: 'protocol processing error' };
  }
}

async function HandleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, protocolResponseHeader, log, config, trafficCallback) {
  async function connectAndWrite(address, port, socks) {
    var tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log('connected to ' + address + ':' + port);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = config.enableSocks
      ? await connectAndWrite(addressRemote, portRemote, true)
      : await connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false
        );

    tcpSocket.closed
      .catch(function(error) {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(function() {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start: function(controller) {
      webSocketServer.addEventListener('message', function(event) { controller.enqueue(event.data); });
      webSocketServer.addEventListener('close', function() {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', function(err) {
        log('webSocketServer has error');
        controller.error(err);
      });
      const earlyDataResult = base64ToArrayBuffer(earlyDataHeader);
      if (earlyDataResult.error) controller.error(earlyDataResult.error);
      else if (earlyDataResult.earlyData) controller.enqueue(earlyDataResult.earlyData);
    },
    pull: function(_controller) { },
    cancel: function(reason) {
      log('ReadableStream canceled: ' + reason);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  var hasIncomingData = false;
  var headerSent = protocolResponseHeader;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        write: async function(chunk, controller) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
            controller.error(new Error('webSocket not open'));
            return;
          }
          hasIncomingData = true;
          
          if (headerSent) {
            webSocket.send(await new Blob([headerSent, chunk]).arrayBuffer());
            headerSent = null;
          } else {
            webSocket.send(chunk);
          }
          
          if (trafficCallback) {
            trafficCallback(chunk.byteLength);
          }
        },
        close: function() {
          log('remoteSocket closed, hasIncomingData: ' + hasIncomingData);
        },
        abort: function(reason) {
          console.error('remoteSocket abort', reason);
        },
      })
    )
    .catch(function(error) {
      console.error('remoteSocket pipeTo error', error);
      safeCloseWebSocket(webSocket);
    });
  
  if (!hasIncomingData && retry) {
    log('No incoming data, retrying');
    await retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (var i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error: error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error:', error);
  }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
  var isHeaderSent = false;
  const transformStream = new TransformStream({
    transform: function(chunk, controller) {
      for (var index = 0; index < chunk.byteLength;) {
        if (index + 2 > chunk.byteLength) break;
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (index + 2 + udpPacketLength > chunk.byteLength) break;
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        write: async function(chunk) {
          try {
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log('DNS query success, length: ' + udpSize);
              var responseChunk;
              if (isHeaderSent) {
                responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
              } else {
                responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                isHeaderSent = true;
              }
              if (trafficCallback) {
                trafficCallback(responseChunk.byteLength);
              }
              webSocket.send(responseChunk);
            }
          } catch (error) {
            log('DNS query error: ' + error);
          }
        },
      })
    )
    .catch(function(e) {
      log('DNS stream error: ' + e);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: function(chunk) { return writer.write(chunk); },
  };
}

function parseIPv6(ipv6) {
  const buffer = new ArrayBuffer(16);
  const view = new DataView(buffer);
  
  const parts = ipv6.split('::');
  var left = parts[0] ? parts[0].split(':') : [];
  var right = parts[1] ? parts[1].split(':') : [];
  
  if (left.length === 1 && left[0] === '') left = [];
  if (right.length === 1 && right[0] === '') right = [];
  
  const missing = 8 - (left.length + right.length);
  const expansion = [];
  if (missing > 0) {
    for (var i = 0; i < missing; i++) {
      expansion.push('0000');
    }
  }
  
  const hextets = left.concat(expansion).concat(right);
  
  for (var i = 0; i < 8; i++) {
    const val = parseInt(hextets[i] || '0', 16);
    view.setUint16(i * 2, val, false);
  }
  
  return new Uint8Array(buffer);
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  const username = parsedSocks5Address.username;
  const password = parsedSocks5Address.password;
  const hostname = parsedSocks5Address.hostname;
  const port = parsedSocks5Address.port;
  
  var socket;
  var reader;
  var writer;
  var success = false;

  try {
    socket = connect({ hostname: hostname, port: port });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    
    const encoder = new TextEncoder();

    await writer.write(new Uint8Array([5, 2, 0, 2]));
    var readResult = await reader.read();
    var res = readResult.value;
    if (!res || res[0] !== 0x05 || res[1] === 0xff) {
      throw new Error('SOCKS5 handshake failed');
    }

    if (res[1] === 0x02) {
      if (!username || !password) {
        throw new Error('SOCKS5 requires credentials');
      }
      const usernameBytes = encoder.encode(username);
      const passwordBytes = encoder.encode(password);
      const authRequest = new Uint8Array(3 + usernameBytes.length + passwordBytes.length);
      authRequest[0] = 1;
      authRequest[1] = usernameBytes.length;
      authRequest.set(usernameBytes, 2);
      authRequest[2 + usernameBytes.length] = passwordBytes.length;
      authRequest.set(passwordBytes, 3 + usernameBytes.length);
      await writer.write(authRequest);
      readResult = await reader.read();
      res = readResult.value;
      if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
        throw new Error('SOCKS5 auth failed (Code: ' + (res ? res[1] : 'null') + ')');
      }
    }

    var dstAddr;
    switch (addressType) {
      case 1:
        var ipParts = addressRemote.split('.').map(Number);
        dstAddr = new Uint8Array([1, ipParts[0], ipParts[1], ipParts[2], ipParts[3]]);
        break;
      case 2:
        var domainBytes = encoder.encode(addressRemote);
        dstAddr = new Uint8Array(2 + domainBytes.length);
        dstAddr[0] = 3;
        dstAddr[1] = domainBytes.length;
        dstAddr.set(domainBytes, 2);
        break;
      case 3:
        var ipv6Bytes = parseIPv6(addressRemote);
        if (ipv6Bytes.length !== 16) {
          throw new Error('Failed to parse IPv6: ' + addressRemote);
        }
        dstAddr = new Uint8Array(1 + 16);
        dstAddr[0] = 4;
        dstAddr.set(ipv6Bytes, 1);
        break;
      default:
        throw new Error('Invalid address type: ' + addressType);
    }

    const socksRequest = new Uint8Array(4 + dstAddr.length + 2);
    socksRequest[0] = 5;
    socksRequest[1] = 1;
    socksRequest[2] = 0;
    socksRequest.set(dstAddr, 3);
    socksRequest[3 + dstAddr.length] = portRemote >> 8;
    socksRequest[3 + dstAddr.length + 1] = portRemote & 0xff;
    await writer.write(socksRequest);
    
    readResult = await reader.read();
    res = readResult.value;
    if (!res || res[1] !== 0x00) {
      throw new Error('SOCKS5 connection failed (Code: ' + (res ? res[1] : 'null') + ')');
    }

    log('SOCKS5 connection to ' + addressRemote + ':' + portRemote + ' established');
    success = true;
    return socket;

  } catch (err) {
    log('socks5Connect error: ' + err.message, err);
    throw err;
  } finally {
    if (writer) writer.releaseLock();
    if (reader) reader.releaseLock();
    
    if (!success && socket) {
      try {
        socket.abort();
      } catch (e) {
        log('Error aborting SOCKS5 socket', e);
      }
    }
  }
}

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid SOCKS5 address format');
  }
  var authPart = null;
  var hostPart = address;
  if (address.includes('@')) {
    var atIndex = address.indexOf('@');
    authPart = address.substring(0, atIndex);
    hostPart = address.substring(atIndex + 1);
  }
  const lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  var hostname;
  if (hostPart.startsWith('[')) {
    const closingBracketIndex = hostPart.lastIndexOf(']');
    if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
      throw new Error('Invalid IPv6 SOCKS5 address');
    }
    hostname = hostPart.substring(1, closingBracketIndex);
  } else {
    hostname = hostPart.substring(0, lastColonIndex);
  }

  const portStr = hostPart.substring(lastColonIndex + 1);
  const port = parseInt(portStr, 10);
  
  if (!hostname || isNaN(port)) {
    throw new Error('Invalid SOCKS5 address');
  }

  var username, password;
  if (authPart) {
    var colonIndex = authPart.indexOf(':');
    if (colonIndex !== -1) {
      username = authPart.substring(0, colonIndex);
      password = authPart.substring(colonIndex + 1);
    } else {
      username = authPart;
    }
  }
  
  return { username: username, password: password, hostname: hostname, port: port };
}

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      var cfg;
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error('Configuration error: ' + err.message);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service unavailable', { status: 503, headers: headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      if (url.pathname.startsWith('/' + adminPrefix + '/')) {
        return await handleAdminRequest(request, env, ctx, adminPrefix);
      }

      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers: headers });
      }

      if (url.pathname === '/health-check' && request.method === 'GET') {
        await performHealthCheck(env, ctx);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Health check performed', { status: 200, headers: headers });
      }

      if (url.pathname.startsWith('/api/user/')) {
        const uuid = url.pathname.substring('/api/user/'.length);
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        if (request.method !== 'GET') {
          return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers: headers });
        }
        
        if (!isValidUUID(uuid)) {
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers: headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers: headers });
        }
        
        return new Response(JSON.stringify({
          traffic_used: userData.traffic_used || 0,
          traffic_limit: userData.traffic_limit,
          expiration_date: userData.expiration_date,
          expiration_time: userData.expiration_time
        }), { status: 200, headers: headers });
      }

      if (url.pathname === '/favicon.ico') {
        return new Response(null, {
          status: 301,
          headers: { 'Location': 'https://www.google.com/favicon.ico' }
        });
      }

      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured', { status: 503, headers: headers });
        }
        
        const hostHeaders = env.HOST_HEADERS 
          ? env.HOST_HEADERS.split(',').map(function(h) { return h.trim(); }) 
          : ['speed.cloudflare.com', 'www.cloudflare.com'];
        const evasionHost = pick(hostHeaders);
        const newHeaders = new Headers(request.headers);
        newHeaders.set('Host', evasionHost);
        const newRequest = new Request(request, { headers: newHeaders });
        
        const requestConfig = {
          userID: cfg.userID,
          proxyIP: cfg.proxyIP,
          proxyPort: cfg.proxyPort,
          socks5Address: cfg.socks5.address,
          socks5Relay: cfg.socks5.relayMode,
          enableSocks: cfg.socks5.enabled,
          parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
          scamalytics: cfg.scamalytics,
        };
        
        const wsResponse = await ProtocolOverWSHandler(newRequest, requestConfig, env, ctx);
        
        const headers = new Headers(wsResponse.headers);
        addSecurityHeaders(headers, null, {});
        
        return new Response(wsResponse.body, { 
          status: wsResponse.status, 
          webSocket: wsResponse.webSocket, 
          headers: headers 
        });
      }

      async function handleSubscription(core) {
        const rateLimitKey = 'user_path_rate:' + clientIp;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers: headers });
        }

        const uuid = url.pathname.substring(('/' + core + '/').length);
        if (!isValidUUID(uuid)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Invalid UUID', { status: 400, headers: headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers: headers });
        }
        
        if (isExpired(userData.expiration_date, userData.expiration_time)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Account expired', { status: 403, headers: headers });
        }
        
        if (userData.traffic_limit && userData.traffic_limit > 0 && 
            (userData.traffic_used || 0) >= userData.traffic_limit) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Traffic limit exceeded', { status: 403, headers: headers });
        }
        
        return await handleIpSubscription(core, uuid, url.hostname);
      }

      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray');
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb');
      }

      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const rateLimitKey = 'user_path_rate:' + clientIp;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers: headers });
        }

        const userData = await getUserData(env, path, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers: headers });
        }
        
        return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      if (env.ROOT_PROXY_URL) {
        try {
          var proxyUrl;
          try {
            proxyUrl = new URL(env.ROOT_PROXY_URL);
          } catch (urlError) {
            console.error('Invalid ROOT_PROXY_URL: ' + env.ROOT_PROXY_URL, urlError);
            const headers = new Headers();
            addSecurityHeaders(headers, null, {});
            return new Response('Proxy configuration error', { status: 500, headers: headers });
          }

          const targetUrl = new URL(request.url);
          targetUrl.hostname = proxyUrl.hostname;
          targetUrl.protocol = proxyUrl.protocol;
          if (proxyUrl.port) {
            targetUrl.port = proxyUrl.port;
          }
          
          const newRequest = new Request(targetUrl.toString(), {
            method: request.method,
            headers: request.headers,
            body: request.body,
            redirect: 'manual'
          });
          
          newRequest.headers.set('Host', proxyUrl.hostname);
          newRequest.headers.set('X-Forwarded-For', clientIp);
          newRequest.headers.set('X-Forwarded-Proto', targetUrl.protocol.replace(':', ''));
          newRequest.headers.set('X-Real-IP', clientIp);
          
          const response = await fetch(newRequest);
          const mutableHeaders = new Headers(response.headers);
          
          mutableHeaders.delete('content-security-policy-report-only');
          mutableHeaders.delete('x-frame-options');
          
          if (!mutableHeaders.has('Content-Security-Policy')) {
            mutableHeaders.set('Content-Security-Policy', 
              "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *; frame-ancestors 'self';");
          }
          if (!mutableHeaders.has('X-Frame-Options')) {
            mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
          }
          if (!mutableHeaders.has('Strict-Transport-Security')) {
            mutableHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
          }
          
          mutableHeaders.set('alt-svc', 'h3=":443"; ma=0');
          
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: mutableHeaders
          });
        } catch (e) {
          console.error('Reverse Proxy Error: ' + e.message, e.stack);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Proxy error: ' + e.message, { status: 502, headers: headers });
        }
      }

      const masqueradeHtml = '<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>';
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(masqueradeHtml, { headers: headers });
      
    } catch (e) {
      console.error('Fetch handler error:', e.message, e.stack);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Internal Server Error', { status: 500, headers: headers });
    }
  },

  async scheduled(event, env, ctx) {
    try {
      console.log('Running scheduled health check...');
      await performHealthCheck(env, ctx);
      await cleanupOldIps(env, ctx);
      console.log('Scheduled tasks completed successfully');
    } catch (e) {
      console.error('Scheduled task error:', e.message);
    }
  }
};
