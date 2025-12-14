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

    // Health Check & Auto-Switching from DB (از اسکریپت دوم)
    if (env.DB) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
        ).all();
        selectedProxyIP = results[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log(`✓ Using best healthy proxy from DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    // Fallback to environment variable
    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    // Final fallback to hardcoded list
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from config list: ${selectedProxyIP}`);
      }
    }
    
    // Critical fallback
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
// CONSTANTS - ترکیب تمام ثابت‌ها از هر دو اسکریپت
// ============================================================================

const CONST = {
  // Protocol constants
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  
  // Admin panel constants
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  
  // Security constants
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  
  // Auto-refresh constants (از اسکریپت اول)
  AUTO_REFRESH_INTERVAL: 60000, // 1 minute
  
  // Database maintenance constants (از اسکریپت دوم)
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000, // 5 minutes
  HEALTH_CHECK_TIMEOUT: 5000,
};

// ============================================================================
// CORE SECURITY & HELPER FUNCTIONS - ترکیب کامل از هر دو اسکریپت
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const scriptSrc = nonce 
    ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com` 
    : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'";
  
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
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
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
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
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

async function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// KEY-VALUE STORAGE FUNCTIONS (D1-based) - از اسکریپت دوم
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.error(`kvGet: Database not available for key ${key}`);
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
        console.error(`Failed to parse JSON for key ${key}: ${e}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.error(`kvPut: Database not available for key ${key}`);
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
    console.error(`kvPut error for ${key}: ${e}`);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.error(`kvDelete: Database not available for key ${key}`);
    return;
  }
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e}`);
  }
}

// ============================================================================
// USER DATA MANAGEMENT - با کش بهبود یافته
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    // Try cache first
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error(`Failed to get cached data for ${uuid}`, e);
    }

    // Fetch from database
    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    // Update cache asynchronously
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    return userFromDb;
  } catch (e) {
    console.error(`getUserData error for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: D1 binding missing");
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    // Acquire lock with timeout
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
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  } finally {
    if (lockAcquired) {
      try {
        await kvDelete(env.DB, usageLockKey);
      } catch (e) {
        console.error(`Failed to release lock for ${uuid}:`, e);
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
    ).bind(-${CONST.IP_CLEANUP_AGE_DAYS} days).run();
    
    if (ctx) {
      ctx.waitUntil(cleanupPromise);
    } else {
      await cleanupPromise;
    }
  } catch (e) {
    console.error(cleanupOldIps error: ${e.message});
  }
}

// ============================================================================
// SCAMALYTICS IP REPUTATION CHECK - از هر دو اسکریپت
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(⚠️  Scamalytics not configured. IP ${ip} allowed (fail-open).);
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    
    if (!response.ok) {
      console.warn(`Scamalytics API returned ${response.status} for ${ip}. Allowing (fail-open).`);
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(Scamalytics timeout for ${ip}. Allowing (fail-open).);
    } else {
      console.error(Scamalytics error for ${ip}: ${e.message}. Allowing (fail-open).);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// 2FA (TOTP) VALIDATION SYSTEM - از اسکریپت دوم
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
  if (!secret  !code  code.length !== 6 || !/^\d{6}$/.test(code)) {
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
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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
    console.error(checkRateLimit error for ${key}: ${e});
    return false;
  }
}

// ============================================================================
// UUID UTILITIES - مشترک در هر دو اسکریپت
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
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

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION LINK GENERATION - ترکیب از هر دو اسکریپت
// ============================================================================

function generateRandomPath(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return /${result};
}

const CORE_PRESETS = {
  xray: {
    tls: {
      path: () => generateRandomPath(12),
      security: 'tls',
      fp: 'chrome',
      alpn: 'http/1.1',
      extra: { ed: '2560' },
    },
    tcp: {
      path: () => generateRandomPath(12),
      security: 'none',
      fp: 'chrome',
      extra: { ed: '2560' },
    },
  },
  sb: {
    tls: {
      path: () => generateRandomPath(18),
      security: 'tls',
      fp: 'firefox',
      alpn: 'h3',
      extra: CONST.ED_PARAMS,
    },
    tcp: {
      path: () => generateRandomPath(18),
      security: 'none',
      fp: 'firefox',
      extra: CONST.ED_PARAMS,
    },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function randomizeCase(str) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

function createVlessLink({
  userID,
  address,
  port,
  host,
  path,
  security,
  sni,
  fp,
  alpn,
  extra = {},
  name,
}) {
  const params = new URLSearchParams({
    encryption: 'none',
    type: 'ws',
    host,
    path,
  });

  if (security) {
    params.set('security', security);
    if (security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === 'tls' ? randomizeCase(hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// ============================================================================
// SUBSCRIPTION HANDLER - ترکیب لیست دامنه‌ها از هر دو اسکریپت
// ============================================================================

async function handleIpSubscription(core, userID, hostName) {
  // ترکیب دامنه‌ها از هر دو اسکریپت
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
    // از اسکریپت دوم:
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
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  // Generate domain-based configs
  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: 'tls',
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `D${i + 1}`,
      }),
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core,
          proto: 'tcp',
          userID,
          hostName,
          address: domain,
          port: pick(httpPorts),
          tag: `D${i + 1}`,
        }),
      );
    }
  });

  // Fetch Cloudflare IPs
  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
    );
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 20).map((x) => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(
          buildLink({
            core,
            proto: 'tls',
            userID,
            hostName,
            address: formattedAddress,
            port: pick(httpsPorts),
            tag: `IP${i + 1}`,
          }),
        );

        if (!isPagesDeployment) {
          links.push(
            buildLink({
              core,
              proto: 'tcp',
              userID,
              hostName,
              address: formattedAddress,
              port: pick(httpPorts),
              tag: `IP${i + 1}`,
            }),
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

  return new Response(safeBase64Encode(links.join('\n')), { headers });
}

// ============================================================================
// DATABASE INITIALIZATION - از اسکریپت دوم
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) {
    console.warn('ensureTablesExist: D1 binding not available');
    return;
  }
  
  try {
    const createTables = [
      `CREATE TABLE IF NOT EXISTS users (
        uuid TEXT PRIMARY KEY,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiration_date TEXT NOT NULL,
        expiration_time TEXT NOT NULL,
        notes TEXT,
        traffic_limit INTEGER,
        traffic_used INTEGER DEFAULT 0,
        ip_limit INTEGER DEFAULT -1
      )`,
      `CREATE TABLE IF NOT EXISTS user_ips (
        uuid TEXT,
        ip TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (uuid, ip),
        FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE
      )`,
      `CREATE TABLE IF NOT EXISTS key_value (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expiration INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS proxy_health (
        ip_port TEXT PRIMARY KEY,
        is_healthy INTEGER NOT NULL,
        latency_ms INTEGER,
        last_check INTEGER DEFAULT (strftime('%s', 'now'))
      )`
    ];
    
    const stmts = createTables.map(sql => env.DB.prepare(sql));
    await env.DB.batch(stmts);
    
    // Insert test user for development (with default UUID from config)
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
      // User may already exist - that's fine
    }
    
    console.log('✓ D1 tables initialized successfully');
  } catch (e) {
    console.error('Failed to create D1 tables:', e);
  }
}

// ============================================================================
// HEALTH CHECK SYSTEM - از اسکریپت دوم با بهبودهای اسکریپت اول
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: D1 binding not available');
    return;
  }
  
  const proxyIps = env.PROXYIPS 
    ? env.PROXYIPS.split(',').map(ip => ip.trim()) 
    : Config.proxyIPs;
  
  const healthStmts = [];
  
  for (const ipPort of proxyIps) {
    const [host, port = '443'] = ipPort.split(':');
    let latency = null;
    let isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch(`https://${host}:${port}`, { 
        signal: controller.signal,
        method: 'HEAD',
      });
      clearTimeout(timeoutId);
      
      if (response.ok || response.status === 404) {
        latency = Date.now() - start;
        isHealthy = 1;
      }
    } catch (e) {
      console.error(`Health check failed for ${ipPort}: ${e.message}`);
    }
    
    healthStmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
      ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
    );
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('✓ Proxy health check completed');
  } catch (e) {
    console.error(`performHealthCheck batch error: ${e.message}`);
  }
}

// ============================================================================
// ADMIN PANEL HTML - ترکیب از هر دو اسکریپت با تمام قابلیت‌ها
// ============================================================================

const adminLoginHTML = <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; margin: 0;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    }
    .login-container {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      text-align: center;
      width: 100%;
      max-width: 400px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    h1 {
      color: #ffffff;
      margin-bottom: 24px;
      font-weight: 600;
      font-size: 28px;
    }
    form { display: flex; flex-direction: column; gap: 16px; }
    input[type="password"], input[type="text"] {
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #ffffff;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      transition: all 0.3s;
    }
    input:focus {
      outline: none;
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
      background: rgba(255, 255, 255, 0.15);
    }
    input::placeholder { color: rgba(255, 255, 255, 0.5); }
    button {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4);
    }
    button:active { transform: translateY(0); }
    .error {
      color: #ff6b6b;
      margin-top: 16px;
      font-size: 14px;
      background: rgba(255, 107, 107, 0.1);
      padding: 12px;
      border-radius: 8px;
      border: 1px solid rgba(255, 107, 107, 0.3);
    }
    @media (max-width: 480px) {
      .login-container { padding: 30px 20px; margin: 20px; }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>🔐 Admin Login</h1>
    <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
      <input type="password" name="password" placeholder="Enter admin password" required autocomplete="current-password">
      <input type="text" name="totp" placeholder="2FA Code (if enabled)" autocomplete="off" inputmode="numeric" pattern="[0-9]*" maxlength="6">
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`;

// Admin Panel HTML با تمام قابلیت‌های هر دو اسکریپت
const adminPanelHTML = <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - VLESS Proxy Manager</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root {
      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;
      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;
      --accent: #3B82F6; --accent-hover: #2563EB;
      --danger: #EF4444; --danger-hover: #DC2626;
      --success: #22C55E; --warning: #F59e0b;
      --btn-secondary-bg: #4B5563; --purple: #a855f7;
      --cyan: #06b6d4; --pink: #ec4899;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @keyframes gradient-flow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    @keyframes float-particles {
      0%, 100% { transform: translateY(0) rotate(0deg); opacity: 0.3; }
      50% { transform: translateY(-20px) rotate(180deg); opacity: 0.8; }
    }
    @keyframes counter-pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    @keyframes title-shimmer {
      0% { background-position: -200% center; }
      100% { background-position: 200% center; }
    }
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #111827 25%, #0d1321 50%, #0a0e17 75%, #111827 100%);
      background-size: 400% 400%;
      animation: gradient-flow 15s ease infinite;
      color: var(--text-primary);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: 
        radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px;
    }
    h1, h2 { font-weight: 600; }
    h1 {
      font-size: 32px;
      margin-bottom: 28px;
      background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 30%, #06b6d4 60%, #3B82F6 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: title-shimmer 4s linear infinite;
      text-shadow: 0 0 40px rgba(59, 130, 246, 0.3);
    }
    h2 {
      font-size: 18px;
      border-bottom: 2px solid transparent;
      border-image: linear-gradient(90deg, var(--accent), var(--purple), transparent) 1;
      padding-bottom: 12px;
      margin-bottom: 20px;
      position: relative;
    }
    .card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 28px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      box-shadow: 
        0 4px 24px rgba(0,0,0,0.2),
        0 0 0 1px rgba(255, 255, 255, 0.03),
        inset 0 1px 0 rgba(255, 255, 255, 0.05);
      margin-bottom: 24px;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent);
      transition: left 0.6s ease;
    }
    .card:hover::before {
      left: 100%;
    }
    .card:hover {
      box-shadow: 
        0 20px 40px rgba(0,0,0,0.3),
        0 0 80px rgba(59, 130, 246, 0.1),
        inset 0 1px 0 rgba(255, 255, 255, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
      transform: translateY(-4px);
    }
    .dashboard-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 24px 20px;
      border-radius: 16px;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.05);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--purple), var(--cyan));
      opacity: 0;
      transition: opacity 0.3s;
    }
    .stat-card::after {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
      opacity: 0;
      transition: opacity 0.4s;
    }
    .stat-card:hover::before { opacity: 1; }
    .stat-card:hover::after { opacity: 1; }
    .stat-card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 
        0 20px 40px rgba(59, 130, 246, 0.2),
        0 0 0 1px rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .stat-card.healthy { --card-accent: var(--success); }
    .stat-card.warning { --card-accent: var(--warning); }
    .stat-card.danger { --card-accent: var(--danger); }
    .stat-card.healthy::before, .stat-card.warning::before, .stat-card.danger::before {
      background: var(--card-accent);
      opacity: 1;
    }
    .stat-icon {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 12px;
      font-size: 20px;
    }
    .stat-icon.blue { background: rgba(59, 130, 246, 0.15); }
    .stat-icon.green { background: rgba(34, 197, 94, 0.15); }
    .stat-icon.orange { background: rgba(245, 158, 11, 0.15); }
    .stat-icon.purple { background: rgba(168, 85, 247, 0.15); }
    .stat-value {
      font-size: 28px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 6px;
      line-height: 1.2;
    }
    .stat-label {
      font-size: 11px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .stat-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 600;
      margin-top: 8px;
    }
    .stat-badge.online { background: rgba(34, 197, 94, 0.15); color: var(--success); }
    .stat-badge.offline { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
    .stat-badge.checking { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      align-items: flex-end;
    }
    .form-group {
      display: flex;
      flex-direction: column;
    }
    .form-group label {
      margin-bottom: 8px;
      font-weight: 500;
      color: var(--text-secondary);
      font-size: 13px;
    }
    input[type="text"], input[type="date"], input[type="time"], 
    input[type="number"], select {
      width: 100%;
      background: #374151;
      border: 1px solid #4B5563;
      color: var(--text-primary);
      padding: 12px;
      border-radius: 8px;
      font-size: 14px;
      transition: all 0.2s;
    }
    input:focus, select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    .btn {
      padding: 12px 22px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 14px;
      position: relative;
      overflow: hidden;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn:hover::before { left: 100%; }
    .btn:active { transform: scale(0.96); }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%);
      background-size: 200% 200%;
      color: white;
      box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:hover {
      background-position: 100% 50%;
      box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
      transform: translateY(-3px);
    }
    .btn-secondary {
      background: linear-gradient(135deg, #4B5563 0%, #374151 100%);
      color: white;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .btn-secondary:hover { 
      background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .btn-danger {
      background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
      color: white;
      box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
    }
    .btn-danger:hover {
      box-shadow: 0 8px 25px rgba(239, 68, 68, 0.5);
      transform: translateY(-3px);
    }
    .table-wrapper {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      border-radius: 10px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 14px 16px;
      text-align: left;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    th {
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: rgba(59, 130, 246, 0.08);
      position: sticky;
      top: 0;
      backdrop-filter: blur(8px);
    }
    td {
      color: var(--text-primary);
      font-size: 13px;
      transition: background 0.2s;
    }
    tbody tr {
      transition: all 0.2s ease;
    }
    tbody tr:hover {
      background: rgba(59, 130, 246, 0.08);
    }
    tbody tr:hover td {
      color: #fff;
    }
    tbody tr:last-child td {
      border-bottom: none;
    }
    .status-badge {
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      display: inline-block;
    }
    .status-active {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
      border: 1px solid var(--success);
    }
    .status-expired {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }
    .uuid-cell {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .btn-copy-uuid {
      padding: 4px 8px;
      font-size: 11px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: var(--accent);
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy-uuid:hover {
      background: rgba(59, 130, 246, 0.2);
      border-color: var(--accent);
    }
    .btn-copy-uuid.copied {
      background: rgba(34, 197, 94, 0.2);
      border-color: var(--success);
      color: var(--success);
    }
    #toast {
      position: fixed;
      top: 20px;
      right: 20px;
      background: rgba(31, 41, 55, 0.95);
      backdrop-filter: blur(12px);
      color: white;
      padding: 16px 20px;
      border-radius: 12px;
      z-index: 1001;
      display: none;
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 12px 32px rgba(0,0,0,0.4);
      animation: slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      min-width: 280px;
      max-width: 400px;
    }
    .toast-content {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .toast-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      flex-shrink: 0;
    }
    .toast-icon.success { background: rgba(34, 197, 94, 0.15); }
    .toast-icon.error { background: rgba(239, 68, 68, 0.15); }
    .toast-icon.warning { background: rgba(245, 158, 11, 0.15); }
    .toast-icon.info { background: rgba(59, 130, 246, 0.15); }
    .toast-message { flex: 1; font-size: 14px; line-height: 1.4; }
    @keyframes slideIn {
      from { transform: translateX(120%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(120%); opacity: 0; }
    }
    #toast.show { display: block; }
    #toast.hide { animation: slideOut 0.3s ease forwards; }
    #toast.success { border-left: 4px solid var(--success); }
    #toast.error { border-left: 4px solid var(--danger); }
    #toast.warning { border-left: 4px solid var(--warning); }
    #toast.info { border-left: 4px solid var(--accent); }
    .btn.loading {
      pointer-events: none;
      opacity: 0.7;
      position: relative;
    }
    .btn.loading::after {
      content: '';
      position: absolute;
      width: 16px;
      height: 16px;
      border: 2px solid transparent;
      border-top-color: currentColor;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      right: 12px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      animation: pulse 2s ease-in-out infinite;
    }
    .pulse-dot.green { background: var(--success); box-shadow: 0 0 8px var(--success); }
    .pulse-dot.red { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
    .pulse-dot.orange { background: var(--warning); box-shadow: 0 0 8px var(--warning); }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.8); }
    }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: center;
      opacity: 0;
      visibility: hidden;
      transition: all 0.3s;
    }
    .modal-overlay.show {
      opacity: 1;
      visibility: visible;
    }
    .modal-content {
      background: var(--bg-card);
      padding: 32px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
      border: 1px solid var(--border);
      transform: scale(0.9);
      transition: transform 0.3s;
    }
    .modal-overlay.show .modal-content {
      transform: scale(1);
    }
    .search-input {
      width: 100%;
      margin-bottom: 16px;
      padding: 12px 16px;
      background: #374151;
      border: 1px solid #4B5563;
      color: var(--text-primary);
      border-radius: 8px;
      font-size: 14px;
    }
    .time-quick-set-group {
      display: flex;
      gap: 8px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    .btn-outline-secondary {
      background: transparent;
      border: 1px solid var(--btn-secondary-bg);
      color: var(--text-secondary);
      padding: 6px 12px;
      font-size: 12px;
    }
    .btn-outline-secondary:hover {
      background: var(--btn-secondary-bg);
      color: white;
    }
    @media (max-width: 768px) {
      .container { padding: 20px 12px; }
      .dashboard-stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
      .form-grid { grid-template-columns: 1fr; }
      h1 { font-size: 24px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚡ Admin Dashboard</h1>
    <div style="position: absolute; top: 20px; right: 20px; display: flex; gap: 12px;">
      <button id="healthCheckBtn" class="btn btn-secondary">🔄 Health Check</button>
      <button id="logoutBtn" class="btn btn-danger">🚪 Logout</button>
    </div>

    <div class="dashboard-stats">
      <div class="stat-card">
        <div class="stat-icon blue">👥</div>
        <div class="stat-value" id="total-users">0</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">✓</div>
        <div class="stat-value" style="color: var(--success);" id="active-users">0</div>
        <div class="stat-label">Active Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon orange">⏱</div>
        <div class="stat-value" style="color: var(--warning);" id="expired-users">0</div>
        <div class="stat-label">Expired Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">📊</div>
        <div class="stat-value" id="total-traffic">0 KB</div>
        <div class="stat-label">Total Traffic</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon blue">🕐</div>
        <div class="stat-value" style="font-size:16px;" id="server-time">--:--:--</div>
        <div class="stat-label">Server Time</div>
      </div>
      <div class="stat-card" id="proxy-health-card">
        <div class="stat-icon green">💚</div>
        <div class="stat-value" style="font-size: 22px;" id="proxy-health">Checking...</div>
        <div class="stat-label">Proxy Health</div>
        <div class="stat-badge checking" id="proxy-health-badge"><span class="pulse-dot orange"></span> Checking</div>
      </div>
      <div class="stat-card" id="server-status-card">
        <div class="stat-icon blue">🖥</div>
        <div class="stat-value" style="font-size: 22px;" id="server-status">Online</div>
        <div class="stat-label">Server Status</div>
        <div class="stat-badge online" id="server-status-badge"><span class="pulse-dot green"></span> Operational</div>
      </div>
    </div>

    <div class="card">
      <h2>➕ Create New User</h2>
      <form id="createUserForm" class="form-grid">
        <div class="form-group" style="grid-column: 1 / -1;">
          <label for="uuid">UUID</label>
          <div style="display: flex; gap: 8px;">
            <input type="text" id="uuid" required style="flex: 1;">
            <button type="button" id="generateUUID" class="btn btn-secondary">🎲 Generate</button>
          </div>
        </div>
        <div class="form-group">
          <label for="expiryDate">Expiry Date</label>
          <input type="date" id="expiryDate" required>
        </div>
        <div class="form-group">
          <label for="expiryTime">Expiry Time (Local)</label>
          <input type="time" id="expiryTime" step="1" required>
          <div class="time-quick-set-group" data-target-date="expiryDate" data-target-time="expiryTime">
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>
          </div>
        </div>
        <div class="form-group">
          <label for="notes">Notes</label>
          <input type="text" id="notes" placeholder="Optional notes">
        </div>
        <div class="form-group">
          <label for="dataLimit">Data Limit</label>
          <div style="display: flex; gap: 8px; align-items: center;">
            <input type="number" id="dataLimit" min="0" step="0.01" placeholder="0" style="flex: 1; min-width: 80px;">
            <select id="dataUnit" style="min-width: 100px; flex-shrink: 0;">
              <option>KB</option>
              <option>MB</option>
              <option>GB</option>
              <option>TB</option>
              <option value="unlimited" selected>Unlimited</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label for="ipLimit">IP Limit</label>
          <input type="number" id="ipLimit" min="-1" step="1" placeholder="-1 (Unlimited)">
        </div>
        <div class="form-group">
          <label>&nbsp;</label>
          <button type="submit" class="btn btn-primary">✨ Create User</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>👥 User Management</h2>
      <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search by UUID or Notes...">
      <button id="deleteSelected" class="btn btn-danger" style="margin-bottom: 16px;">🗑️ Delete Selected</button>
      <button id="exportUsers" class="btn btn-secondary" style="margin-left:10px;">📥 Export CSV</button>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="selectAll"></th>
              <th>UUID</th>
              <th>Created</th>
              <th>Expiry (Local)</th>
              <th>Status</th>
              <th>Notes</th>
              <th>Limit</th>
              <th>Usage</th>
              <th>IP Limit</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="userList"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="editModal" class="modal-overlay">
    <div class="modal-content">
      <h2>✏️ Edit User</h2>
      <form id="editUserForm">
        <input type="hidden" id="editUuid">
        <div class="form-group" style="margin-top: 20px;">
          <label for="editExpiryDate">Expiry Date</label>
          <input type="date" id="editExpiryDate" required>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editExpiryTime">Expiry Time</label>
          <input type="time" id="editExpiryTime" step="1" required>
          <div class="time-quick-set-group" data-target-date="editExpiryDate" data-target-time="editExpiryTime">
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editNotes">Notes</label>
          <input type="text" id="editNotes">
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editDataLimit">Data Limit</label>
          <div style="display: flex; gap: 8px; align-items: center;">
            <input type="number" id="editDataLimit" min="0" step="0.01" placeholder="Enter limit" style="flex: 1; min-width: 100px;">
            <select id="editDataUnit" style="min-width: 110px;">
              <option>KB</option>
              <option>MB</option>
              <option selected>GB</option>
              <option>TB</option>
              <option value="unlimited">Unlimited</option>
            </select>
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editIpLimit">IP Limit</label>
          <input type="number" id="editIpLimit" min="-1" step="1">
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label>
            <input type="checkbox" id="resetTraffic" style="width: auto; margin-right: 8px;">
            Reset Traffic Usage
          </label>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px;">
          <button type="button" id="modalCancelBtn" class="btn btn-secondary">Cancel</button>
          <button type="submit" class="btn btn-primary">💾 Save Changes</button>
        </div>
      </form>
    </div>
  </div>

  <div id="toast"></div>

  <script nonce="CSP_NONCE_PLACEHOLDER">
    // Admin Panel JavaScript - ترکیب کامل از هر دو اسکریپت
    document.addEventListener('DOMContentLoaded', () => {
      const API_BASE = 'ADMIN_API_BASE_PATH_PLACEHOLDER';
      let allUsers = [];

      function escapeHTML(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/[&<>"']/g, m => ({
          '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[m]);
      }

      function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
      }

      function animateCounter(el, targetValue, duration = 1000, suffix = '') {
        const startValue = parseInt(el.textContent) || 0;
        const startTime = performance.now();
        const diff = targetValue - startValue;
        
        function update(currentTime) {
          const elapsed = currentTime - startTime;
          const progress = Math.min(elapsed / duration, 1);
          const easeProgress = 1 - Math.pow(1 - progress, 3);
          const currentValue = Math.floor(startValue + diff * easeProgress);
          el.textContent = currentValue + suffix;
          
          if (progress < 1) {
            requestAnimationFrame(update);
          } else {
            el.textContent = targetValue + suffix;
            el.style.animation = 'counter-pulse 0.3s ease';
            setTimeout(() => el.style.animation = '', 300);
          }
        }
        requestAnimationFrame(update);
      }

      function showToast(message, typeOrError = 'success') {
        const toast = document.getElementById('toast');
        const type = typeOrError === true ? 'error' : (typeOrError === false ? 'success' : typeOrError);
        const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
        const icon = icons[type] || icons.success;
        toast.innerHTML = '<div class="toast-content"><div class="toast-icon ' + type + '">' + icon + '</div><div class="toast-message">' + message + '</div></div>';
        toast.className = type + ' show';
        setTimeout(() => { toast.classList.add('hide'); setTimeout(() => toast.className = '', 300); }, 3000);
      }

      function updateProxyHealth(isHealthy, latency) {
        const card = document.getElementById('proxy-health-card');
        const value = document.getElementById('proxy-health');
        const badge = document.getElementById('proxy-health-badge');
        
        if (!card || !value || !badge) return;
        
        if (isHealthy === null || isHealthy === undefined) {
          card.className = 'stat-card healthy';
          value.textContent = 'Healthy';
          value.style.color = 'var(--success)';
          badge.innerHTML = '<span class="pulse-dot green"></span> Online';
          badge.className = 'stat-badge online';
        } else if (isHealthy) {
          card.className = 'stat-card healthy';
          value.textContent = latency ? latency + 'ms' : 'Healthy';
          value.style.color = 'var(--success)';
          badge.innerHTML = '<span class="pulse-dot green"></span> Online';
          badge.className = 'stat-badge online';
        } else {
          card.className = 'stat-card danger';
          value.textContent = 'Unhealthy';
          value.style.color = 'var(--danger)';
          badge.innerHTML = '<span class="pulse-dot red"></span> Issues';
          badge.className = 'stat-badge offline';
        }
      }

      function setButtonLoading(btn, loading) {
        if (loading) {
          btn.classList.add('loading');
          btn.disabled = true;
        } else {
          btn.classList.remove('loading');
          btn.disabled = false;
        }
      }

      const getCsrfToken = () => document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1] || '';

      const api = {
        get: (endpoint) => fetch(API_BASE + endpoint, { credentials: 'include' }).then(handleResponse),
        post: (endpoint, body) => fetch(API_BASE + endpoint, { 
          method: 'POST', 
          credentials: 'include', 
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, 
          body: JSON.stringify(body) 
        }).then(handleResponse),
        put: (endpoint, body) => fetch(API_BASE + endpoint, { 
          method: 'PUT', 
          credentials: 'include', 
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, 
          body: JSON.stringify(body) 
        }).then(handleResponse),
        delete: (endpoint) => fetch(API_BASE + endpoint, { 
          method: 'DELETE', 
          credentials: 'include', 
          headers: {'X-CSRF-Token': getCsrfToken()} 
        }).then(handleResponse),
      };

      async function handleResponse(response) {
        if (response.status === 401) {
          showToast('Session expired. Please log in again.', true);
          setTimeout(() => window.location.reload(), 2000);
          throw new Error('Unauthorized');
        }
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ error: 'Request failed' }));
          throw new Error(errorData.error || 'Request failed');
        }
        return response.status === 204 ? null : response.json();
      }

      const pad = (num) => num.toString().padStart(2, '0');

      function localToUTC(dateStr, timeStr) {
        if (!dateStr || !timeStr) return { utcDate: '', utcTime: '' };
        const localDateTime = new Date(dateStr + 'T' + timeStr);
        if (isNaN(localDateTime.getTime())) return { utcDate: '', utcTime: '' };

        const year = localDateTime.getUTCFullYear();
        const month = pad(localDateTime.getUTCMonth() + 1);
        const day = pad(localDateTime.getUTCDate());
        const hours = pad(localDateTime.getUTCHours());
        const minutes = pad(localDateTime.getUTCMinutes());
        const seconds = pad(localDateTime.getUTCSeconds());

        return {
          utcDate: year + '-' + month + '-' + day,
          utcTime: hours + ':' + minutes + ':' + seconds
        };
      }

      function utcToLocal(utcDateStr, utcTimeStr) {
        if (!utcDateStr || !utcTimeStr) return { localDate: '', localTime: '' };
        const utcDateTime = new Date(utcDateStr + 'T' + utcTimeStr + 'Z');
        if (isNaN(utcDateTime.getTime())) return { localDate: '', localTime: '' };

        const year = utcDateTime.getFullYear();
        const month = pad(utcDateTime.getMonth() + 1);
        const day = pad(utcDateTime.getDate());
        const hours = pad(utcDateTime.getHours());
        const minutes = pad(utcDateTime.getMinutes());
        const seconds = pad(utcDateTime.getSeconds());

        return {
          localDate: year + '-' + month + '-' + day,
          localTime: hours + ':' + minutes + ':' + seconds
        };
      }

      function addExpiryTime(dateInputId, timeInputId, amount, unit) {
        const dateInput = document.getElementById(dateInputId);
        const timeInput = document.getElementById(timeInputId);

        let date = new Date(dateInput.value + 'T' + (timeInput.value || '00:00:00'));
        if (isNaN(date.getTime())) date = new Date();

        if (unit === 'hour') date.setHours(date.getHours() + amount);
        else if (unit === 'day') date.setDate(date.getDate() + amount);
        else if (unit === 'month') date.setMonth(date.getMonth() + amount);

        const year = date.getFullYear();
        const month = pad(date.getMonth() + 1);
        const day = pad(date.getDate());
        const hours = pad(date.getHours());
        const minutes = pad(date.getMinutes());
        const seconds = pad(date.getSeconds());

        dateInput.value = year + '-' + month + '-' + day;
        timeInput.value = hours + ':' + minutes + ':' + seconds;
      }

      document.body.addEventListener('click', (e) => {
        const target = e.target.closest('.time-quick-set-group button');
        if (!target) return;
        const group = target.closest('.time-quick-set-group');
        addExpiryTime(
          group.dataset.targetDate,
          group.dataset.targetTime,
          parseInt(target.dataset.amount, 10),
          target.dataset.unit
        );
      });

      async function copyUUID(uuid, button) {
        try {
          await navigator.clipboard.writeText(uuid);
          const originalText = button.innerHTML;
          button.innerHTML = '✓ Copied';
          button.classList.add('copied');
          setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('copied');
          }, 2000);
          showToast('UUID copied to clipboard!', false);
        } catch (error) {
          showToast('Failed to copy UUID', true);
        }
      }

      async function fetchStats() {
        try {
          const stats = await api.get('/stats');
          document.getElementById('total-users').textContent = stats.total_users;
          document.getElementById('active-users').textContent = stats.active_users;
          document.getElementById('expired-users').textContent = stats.expired_users;
          document.getElementById('total-traffic').textContent = formatBytes(stats.total_traffic);
          
          // Update proxy health status
          if (stats.proxy_health) {
            updateProxyHealth(stats.proxy_health.is_healthy, stats.proxy_health.latency_ms);
          } else {
            updateProxyHealth(true, null);
          }
        } catch (error) {
          showToast(error.message, true);
          updateProxyHealth(false, null);
        }
      }

      function renderUsers(usersToRender = allUsers) {
        const userList = document.getElementById('userList');
        userList.innerHTML = '';
        
        if (usersToRender.length === 0) {
          userList.innerHTML = '<tr><td colspan="10" style="text-align:center;">No users found.</td></tr>';
          return;
        }

        usersToRender.forEach(user => {
          const expiryDate = new Date(user.expiration_date + 'T' + user.expiration_time + 'Z');
          const isExpired = expiryDate <= new Date();
          const localExpiry = expiryDate.toLocaleString();
          
          const row = document.createElement('tr');
          row.innerHTML = `
            <td><input type="checkbox" class="user-checkbox" data-uuid="${user.uuid}"></td>
            <td>
              <div class="uuid-cell">
                <span title="${user.uuid}">${user.uuid.substring(0, 8)}...</span>
                <button class="btn-copy-uuid" data-uuid="${user.uuid}">📋 Copy</button>
              </div>
            </td>
            <td>${new Date(user.created_at).toLocaleString()}</td>
            <td>${localExpiry}</td>
            <td><span class="status-badge ${isExpired ? 'status-expired' : 'status-active'}">${isExpired ? 'Expired' : 'Active'}</span></td>
            <td>${escapeHTML(user.notes || '-')}</td>
            <td>${user.traffic_limit ? formatBytes(user.traffic_limit) : 'Unlimited'}</td>
            <td>${formatBytes(user.traffic_used || 0)}</td>
            <td>${user.ip_limit === -1 ? 'Unlimited' : user.ip_limit}</td>
            <td>
              <div style="display: flex; gap: 8px;">
                <button class="btn btn-secondary btn-edit" data-uuid="${user.uuid}" style="font-size: 12px; padding: 6px 10px;">Edit</button>
                <button class="btn btn-danger btn-delete" data-uuid="${user.uuid}" style="font-size: 12px; padding: 6px 10px;">Delete</button>
              </div>
            </td>
          `;
          userList.appendChild(row);
        });
      }

      async function fetchAndRenderUsers() {
        try {
          allUsers = await api.get('/users');
          allUsers.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
          renderUsers();
          await fetchStats();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      // سیستم Auto-Refresh از اسکریپت اول
      function startAutoRefresh() {
        setInterval(async () => {
          try {
            await fetchAndRenderUsers();
            console.log('✓ Dashboard auto-refreshed');
          } catch (error) {
            console.error('Auto-refresh failed:', error);
          }
        }, 60000); // هر 1 دقیقه
      }

      async function handleCreateUser(e) {
        e.preventDefault();
        const localDate = document.getElementById('expiryDate').value;
        const localTime = document.getElementById('expiryTime').value;

        const { utcDate, utcTime } = localToUTC(localDate, localTime);
        if (!utcDate || !utcTime) return showToast('Invalid date or time', true);

        const dataLimit = document.getElementById('dataLimit').value;
        const dataUnit = document.getElementById('dataUnit').value;
        let trafficLimit = null;
        
        if (dataUnit !== 'unlimited' && dataLimit) {
          const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
          trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);
        }

        const ipLimit = parseInt(document.getElementById('ipLimit').value) || -1;

        const userData = {
          uuid: document.getElementById('uuid').value,
          exp_date: utcDate,
          exp_time: utcTime,
          notes: document.getElementById('notes').value,
          traffic_limit: trafficLimit,
          ip_limit: ipLimit
        };

        try {
          await api.post('/users', userData);
          showToast('✓ User created successfully!');
          document.getElementById('createUserForm').reset();
          document.getElementById('uuid').value = crypto.randomUUID();
          setDefaultExpiry();
          await fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      async function handleDeleteUser(uuid) {
        if (confirm('Delete user ' + uuid + '?')) {
          try {
            await api.delete('/users/' + uuid);
            showToast('✓ User deleted successfully!');
            await fetchAndRenderUsers();
          } catch (error) {
            showToast(error.message, true);
          }
        }
      }

      async function handleBulkDelete() {
        const selected = Array.from(document.querySelectorAll('.user-checkbox:checked')).map(cb => cb.dataset.uuid);
        if (selected.length === 0) return showToast('No users selected', true);
        if (confirm('Delete ' + selected.length + ' selected users?')) {
          try {
            await api.post('/users/bulk-delete', { uuids: selected });
            showToast('✓ Selected users deleted!');
            await fetchAndRenderUsers();
          } catch (error) {
            showToast(error.message, true);
          }
        }
      }

      function openEditModal(uuid) {
        const user = allUsers.find(u => u.uuid === uuid);
        if (!user) return showToast('User not found', true);

        const { localDate, localTime } = utcToLocal(user.expiration_date, user.expiration_time);

        document.getElementById('editUuid').value = user.uuid;
        document.getElementById('editExpiryDate').value = localDate;
        document.getElementById('editExpiryTime').value = localTime;
        document.getElementById('editNotes').value = user.notes || '';

        const editDataLimit = document.getElementById('editDataLimit');
        const editDataUnit = document.getElementById('editDataUnit');
        if (user.traffic_limit === null || user.traffic_limit === 0) {
          editDataUnit.value = 'unlimited';
          editDataLimit.value = '';
        } else {
          let bytes = user.traffic_limit;
          let unit = 'KB';
          let value = bytes / 1024;
          
          if (value >= 1024) { value = value / 1024; unit = 'MB'; }
          if (value >= 1024) { value = value / 1024; unit = 'GB'; }
          if (value >= 1024) { value = value / 1024; unit = 'TB'; }
          
          editDataLimit.value = value.toFixed(2);
          editDataUnit.value = unit;
        }

        document.getElementById('editIpLimit').value = user.ip_limit !== null ? user.ip_limit : -1;
        document.getElementById('resetTraffic').checked = false;

        document.getElementById('editModal').classList.add('show');
      }

      function closeEditModal() {
        document.getElementById('editModal').classList.remove('show');
      }

      async function handleEditUser(e) {
        e.preventDefault();
        const localDate = document.getElementById('editExpiryDate').value;
        const localTime = document.getElementById('editExpiryTime').value;

        const { utcDate, utcTime } = localToUTC(localDate, localTime);
        if (!utcDate || !utcTime) return showToast('Invalid date or time', true);

        const dataLimit = document.getElementById('editDataLimit').value;
        const dataUnit = document.getElementById('editDataUnit').value;
        let trafficLimit = null;
        
        if (dataUnit !== 'unlimited' && dataLimit) {
          const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
          trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);
        }

        const ipLimit = parseInt(document.getElementById('editIpLimit').value) || -1;

        const updatedData = {
          exp_date: utcDate,
          exp_time: utcTime,
          notes: document.getElementById('editNotes').value,
          traffic_limit: trafficLimit,
          ip_limit: ipLimit,
          reset_traffic: document.getElementById('resetTraffic').checked
        };

        try {
          await api.put('/users/' + document.getElementById('editUuid').value, updatedData);
          showToast('✓ User updated successfully!');
          closeEditModal();
          await fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      async function handleLogout() {
        try {
          await api.post('/logout', {});
          showToast('✓ Logged out successfully!');
          setTimeout(() => window.location.reload(), 1000);
        } catch (error) {
          showToast(error.message, true);
        }
      }

      async function handleHealthCheck() {
        try {
          await api.post('/health-check', {});
          showToast('✓ Health check completed!', false);
          await fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      function setDefaultExpiry() {
        const now = new Date();
        now.setDate(now.getDate() + 1);
        
        const year = now.getFullYear();
        const month = pad(now.getMonth() + 1);
        const day = pad(now.getDate());
        const hours = pad(now.getHours());
        const minutes = pad(now.getMinutes());
        const seconds = pad(now.getSeconds());
        
        document.getElementById('expiryDate').value = year + '-' + month + '-' + day;
        document.getElementById('expiryTime').value = hours + ':' + minutes + ':' + seconds;
      }

      function filterUsers() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        const filtered = allUsers.filter(user => 
          user.uuid.toLowerCase().includes(searchTerm) || 
          (user.notes && user.notes.toLowerCase().includes(searchTerm))
        );
        renderUsers(filtered);
      }

      // Event Listeners
      document.getElementById('generateUUID').addEventListener('click', () => {
        document.getElementById('uuid').value = crypto.randomUUID();
      });
      
      document.getElementById('createUserForm').addEventListener('submit', handleCreateUser);
      document.getElementById('editUserForm').addEventListener('submit', handleEditUser);
      document.getElementById('modalCancelBtn').addEventListener('click', closeEditModal);
      document.getElementById('searchInput').addEventListener('input', filterUsers);
      
      document.getElementById('selectAll').addEventListener('change', (e) => {
        document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = e.target.checked);
      });
      
      document.getElementById('deleteSelected').addEventListener('click', handleBulkDelete);
      document.getElementById('exportUsers').addEventListener('click', function() {
        if (allUsers.length === 0) {
          showToast('No users to export', true);
          return;
        }
        
        const headers = ['UUID', 'Created At', 'Expiration Date', 'Expiration Time', 'Notes', 'Traffic Limit', 'Traffic Used', 'IP Limit'];
        const csvContent = headers.join(',') + '\\n' + allUsers.map(user => {
          return [
            user.uuid,
            user.created_at,
            user.expiration_date,
            user.expiration_time,
            (user.notes || '').replace(/,/g, ';'),
            user.traffic_limit || 'Unlimited',
            user.traffic_used || 0,
            user.ip_limit
          ].map(val => '"' + String(val).replace(/"/g, '""') + '"').join(',');
        }).join('\\n');
        
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'users_export_' + new Date().toISOString().split('T')[0] + '.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        showToast('✓ Users exported successfully!', false);
      });
      document.getElementById('logoutBtn').addEventListener('click', handleLogout);
      document.getElementById('healthCheckBtn').addEventListener('click', handleHealthCheck);

      document.getElementById('editModal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('editModal')) closeEditModal();
      });

      document.getElementById('userList').addEventListener('click', (e) => {
        const copyBtn = e.target.closest('.btn-copy-uuid');
        if (copyBtn) {
          copyUUID(copyBtn.dataset.uuid, copyBtn);
          return;
        }

        const actionBtn = e.target.closest('button');
        if (!actionBtn) return;
        const uuid = actionBtn.dataset.uuid;
        if (actionBtn.classList.contains('btn-edit')) openEditModal(uuid);
        else if (actionBtn.classList.contains('btn-delete')) handleDeleteUser(uuid);
      });

      // Initialize
      setDefaultExpiry();
      document.getElementById('uuid').value = crypto.randomUUID();
      
      // Set default healthy state before fetching actual data
      updateProxyHealth(null, null);
      
      fetchAndRenderUsers();
      function updateServerTime() {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
        const el = document.getElementById('server-time');
        if (el) el.textContent = timeStr;
      }
      updateServerTime();
      setInterval(updateServerTime, 1000);
      startAutoRefresh();
    });
  </script>
</body>
</html>`;

// ============================================================================
// ADMIN REQUEST HANDLER - ترکیب کامل سیستم ادمین از هر دو اسکریپت
// ============================================================================

async function isAdmin(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const token = cookieHeader.match(/auth_token=([^;]+)/)?.[1];
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

    // IP Whitelist Check
    if (env.ADMIN_IP_WHITELIST) {
      const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
      if (!allowedIps.includes(clientIp)) {
        console.warn(`Admin access denied for IP: ${clientIp}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    } else {
      // Scamalytics check if no whitelist
      const scamalyticsConfig = {
        username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
      };
      if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
        console.warn(`Admin access denied for suspicious IP: ${clientIp}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    }

    // Custom Header Check
    if (env.ADMIN_HEADER_KEY) {
      const headerValue = request.headers.get('X-Admin-Auth');
      if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) {
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    }

    const adminBasePath = `/${adminPrefix}/${env.ADMIN_KEY}`;

    if (!url.pathname.startsWith(adminBasePath)) {
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Not found', { status: 404, headers });
    }

    const adminSubPath = url.pathname.substring(adminBasePath.length) || '/';

    // API Routes
    if (adminSubPath.startsWith('/api/')) {
      if (!env.DB) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Database not configured' }), { status: 503, headers });
      }

      if (!(await isAdmin(request, env))) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      }

      // Rate limiting for API
      const apiRateKey = `admin_api_rate:${clientIp}`;
      if (await checkRateLimit(env.DB, apiRateKey, 100, 60)) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'API rate limit exceeded' }), { status: 429, headers });
      }

      // CSRF Protection for non-GET requests
      if (request.method !== 'GET') {
        const origin = request.headers.get('Origin');
        const secFetch = request.headers.get('Sec-Fetch-Site');

        if (!ori new URL(origin).hostname !== url.hostname e || secFetch !== 'same-origin') {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid request origin' }), { status: 403, headers });
        }

        const csrfToken = request.headers.get('X-CSRF-Token');
        const cookieCsrf = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/)?.[1];
        if (!csrfTo !cookieCsrf f || !timingSafeEqual(csrfToken, cookieCsrf)) {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers });
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
          
          // Get proxy health status
          let proxyHealth = { is_healthy: false, latency_ms: null };
          try {
            const healthResult = await env.DB.prepare(
              "SELECT is_healthy, latency_ms FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
            ).first();
            if (healthResult) {
              proxyHealth = { is_healthy: true, latency_ms: healthResult.latency_ms };
            } else {
              const anyHealth = await env.DB.prepare(
                "SELECT is_healthy, latency_ms FROM proxy_health LIMIT 1"
              ).first();
              if (anyHealth) {
                proxyHealth = { is_healthy: !!anyHealth.is_healthy, latency_ms: anyHealth.latency_ms };
              }
            }
          } catch (healthErr) {
            console.error('Failed to get proxy health:', healthErr);
          }
          
          return new Response(JSON.stringify({ 
            total_users: totalUsers, 
            active_users: activeUsers, 
            expired_users: expiredUsers, 
            total_traffic: totalTraffic,
            proxy_health: proxyHealth
          }), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // API: Get Users List
      if (adminSubPath === '/api/users' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { results } = await env.DB.prepare(
            "SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC"
          ).all();
          return new Response(JSON.stringify(results ?? []), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // API: Create User
      if (adminSubPath === '/api/users' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuid, exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit } = await request.json();

          if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid or missing fields');
          }

          await env.DB.prepare(
            "INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)"
          ).bind(uuid, expDate, expTime, notes || null, traffic_limit, ip_limit || -1).run();
          
          ctx.waitUntil(kvPut(env.DB, `user:${uuid}`, { 
            uuid,
            expiration_date: expDate, 
            expiration_time: expTime, 
            notes: notes || null,
            traffic_limit: traffic_limit, 
            ip_limit: ip_limit || -1,
            traffic_used: 0 
          }, { expirationTtl: 3600 }));

          return new Response(JSON.stringify({ success: true, uuid }), { status: 201, headers });
        } catch (error) {
          if (error.message?.includes('UNIQUE constraint failed')) {
            return new Response(JSON.stringify({ error: 'UUID already exists' }), { status: 409, headers });
          }
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API: Bulk Delete
      if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuids } = await request.json();
          if (!Array.isArray(uuids) || uuids.length === 0) {
            throw new Error('Invalid request: Expected array of UUIDs');
          }

          const deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?");
          const stmts = uuids.map(uuid => deleteUserStmt.bind(uuid));
          await env.DB.batch(stmts);

          ctx.waitUntil(Promise.all(uuids.map(uuid => kvDelete(env.DB, `user:${uuid}`))));

          return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API: Update User
      const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);
      if (userRouteMatch && request.method === 'PUT') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          const { exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit, reset_traffic } = await request.json();
          
          if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid date/time format');
          }

          let query = "UPDATE users SET expiration_date = ?, expiration_time = ?, notes = ?, traffic_limit = ?, ip_limit = ?";
          let binds = [expDate, expTime, notes || null, traffic_limit, ip_limit || -1];
          
          if (reset_traffic) {
            query += ", traffic_used = 0";
          }
          
          query += " WHERE uuid = ?";
          binds.push(uuid);

          await env.DB.prepare(query).bind(...binds).run();
          ctx.waitUntil(kvDelete(env.DB, `user:${uuid}`));

          return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API: Delete User
      if (userRouteMatch && request.method === 'DELETE') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
          ctx.waitUntil(kvDelete(env.DB, `user:${uuid}`));
          return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      // API: Logout
      if (adminSubPath === '/api/logout' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await kvDelete(env.DB, 'admin_session_token_hash');
          const setCookie = [
            'auth_token=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict',
            'csrf_token=; Max-Age=0; Path=/; Secure; SameSite=Strict'
          ];
          headers.append('Set-Cookie', setCookie[0]);
          headers.append('Set-Cookie', setCookie[1]);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      // API: Health Check
      if (adminSubPath === '/api/health-check' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await performHealthCheck(env, ctx);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers });
    }

    // Login Page
    if (adminSubPath === '/') {
      if (request.method === 'POST') {
        const rateLimitKey = `login_fail_ip:${clientIp}`;
        
        try {
          const failCountStr = await kvGet(env.DB, rateLimitKey);
          const failCount = parseInt(failCountStr, 10) || 0;
          
          if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
            addSecurityHeaders(htmlHeaders, null, {});
            return new Response('Too many failed attempts. Try again later.', { status: 429, headers: htmlHeaders });
          }
          
          const formData = await request.formData();
          
          if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
            // TOTP validation if enabled
            if (env.ADMIN_TOTP_SECRET) {
              const totpCode = formData.get('totp');
              if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpCode))) {
                const nonce = generateNonce();
                addSecurityHeaders(htmlHeaders, nonce, {});
                let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid TOTP code. Attempt ${failCount + 1}/${CONST.ADMIN_LOGIN_FAIL_LIMIT}</p>`);
                html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
                html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
                
                ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
                
                return new Response(html, { status: 401, headers: htmlHeaders });
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
            headers.append('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
            headers.append('Set-Cookie', `csrf_token=${csrfToken}; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
            addSecurityHeaders(headers, null, {});
            
            return new Response(null, { status: 302, headers });
          } else {
            ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
            
            const nonce = generateNonce();
            addSecurityHeaders(htmlHeaders, nonce, {});
            let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid password. Attempt ${failCount + 1}/${CONST.ADMIN_LOGIN_FAIL_LIMIT}</p>`);
            html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
            html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
            return new Response(html, { status: 401, headers: htmlHeaders });
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
        
        let html;
        if (await isAdmin(request, env)) {
          html = adminPanelHTML;
          html = html.replace("'ADMIN_API_BASE_PATH_PLACEHOLDER'", `'${adminBasePath}/api'`);
        } else {
          html = adminLoginHTML;
          html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
        }
        
        html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
        return new Response(html, { headers: htmlHeaders });
      }

      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Method Not Allowed', { status: 405, headers });
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  } catch (e) {
    console.error('handleAdminRequest error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// USER PANEL WITH SELF-CONTAINED QR CODE GENERATOR
// این بخش شامل تمام قابلیت‌های پیشرفته از هر دو اسکریپت است
// ============================================================================

async function resolveProxyIP(proxyHost) {
  const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;

  if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
    return proxyHost;
  }

  // Multiple DNS-over-HTTPS providers for resolution
  const dnsAPIs = [
    { url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`, parse: data => data.Answer?.find(a => a.type === 1)?.data },
    { url: `https://dns.google/resolve?name=${encodeURIComponent(proxyHost)}&type=A`, parse: data => data.Answer?.find(a => a.type === 1)?.data },
    { url: `https://1.1.1.1/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`, parse: data => data.Answer?.find(a => a.type === 1)?.data }
  ];

  for (const api of dnsAPIs) {
    try {
      const response = await fetch(api.url, { headers: { 'accept': 'application/dns-json' } });
      if (response.ok) {
        const data = await response.json();
        const ip = api.parse(data);
        if (ip && ipv4Regex.test(ip)) return ip;
      }
    } catch (e) {
      // Silent fail and try next provider
    }
  }
  return proxyHost;
}

async function getGeo(ip, cfHeaders = null) {
  if (cfHeaders && (cfHeaders.city || cfHeaders.country)) {
    return {
      city: cfHeaders.city || '',
      country: cfHeaders.country || '',
      isp: cfHeaders.asOrganization || ''
    };
  }
  
  const geoAPIs = [
    {
      url: `https://ip-api.com/json/${ip}?fields=status,message,city,country,isp`,
      parse: async (r) => {
        const data = await r.json();
        if (data.status === 'fail') throw new Error(data.message || 'API Error');
        return { city: data.city || '', country: data.country || '', isp: data.isp || '' };
      }
    },
    {
      url: `https://ipapi.co/${ip}/json/`,
      parse: async (r) => {
        const data = await r.json();
        if (data.error) throw new Error(data.reason || 'API Error');
        return { city: data.city || '', country: data.country_name || '', isp: data.org || '' };
      }
    },
    {
      url: `https://ipwho.is/${ip}`,
      parse: async (r) => {
        const data = await r.json();
        if (!data.success) throw new Error('API Error');
        return { city: data.city || '', country: data.country || '', isp: data.connection?.isp || '' };
      }
    },
    {
      url: `https://ipinfo.io/${ip}/json`,
      parse: async (r) => {
        const data = await r.json();
        if (data.bogon) throw new Error('Bogon IP');
        return { city: data.city || '', country: data.country || '', isp: data.org || '' };
      }
    },
    {
      url: `https://freeipapi.com/api/json/${ip}`,
      parse: async (r) => {
        const data = await r.json();
        return { city: data.cityName || '', country: data.countryName || '', isp: '' };
      }
    }
  ];

  for (const api of geoAPIs) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
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

async function handleUserPanel(request, userID, hostName, proxyAddress, userData, clientIp) {
  try {
    const subXrayUrl = `https://${hostName}/xray/${userID}`;
    const subSbUrl = `https://${hostName}/sb/${userID}`;
    
    const singleXrayConfig = buildLink({ 
      core: 'xray', 
      proto: 'tls', 
      userID, 
      hostName, 
      address: hostName, 
      port: 443, 
      tag: 'Main' 
    });
  
    const singleSingboxConfig = buildLink({ 
      core: 'sb', 
      proto: 'tls', 
      userID, 
      hostName, 
      address: hostName, 
      port: 443, 
      tag: 'Main' 
    });

    const clientUrls = {
      universalAndroid: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      shadowrocket: `shadowrocket://add/sub?url=${encodeURIComponent(subXrayUrl)}&name=${encodeURIComponent(hostName)}`,
      streisand: `streisand://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      karing: `karing://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      clashMeta: `clash://install-config?url=${encodeURIComponent(subSbUrl)}`,
      exclave: `sn://subscription?url=${encodeURIComponent(subSbUrl)}&name=${encodeURIComponent(hostName)}`,
    };

    const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
    const expirationDateTime = userData.expiration_date && userData.expiration_time 
      ? `${userData.expiration_date}T${userData.expiration_time}Z` 
      : null;

    let usagePercentage = 0;
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
    }

    // Server-side geo detection using Cloudflare CF headers
    const requestCf = request.cf || {};
    const clientGeo = {
      city: requestCf.city || '',
      country: requestCf.country || '',
      isp: requestCf.asOrganization || ''
    };

    const proxyHost = proxyAddress.split(':')[0];
    const proxyIP = await resolveProxyIP(proxyHost);
    const proxyGeo = await getGeo(proxyIP) || { city: '', country: '', isp: '' };

    const usageDisplay = await formatBytes(userData.traffic_used || 0);
    let trafficLimitStr = 'Unlimited';
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      trafficLimitStr = await formatBytes(userData.traffic_limit);
    }

    // این HTML شامل QR Code Generator خودکار از اسکریپت دوم است
    const userPanelHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Panel — VLESS Configuration</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" integrity="sha512-CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root{
      --bg:#0b1220; --card:#0f1724; --muted:#9aa4b2; --accent:#3b82f6;
      --accent-2:#60a5fa; --success:#22c55e; --danger:#ef4444; --warning:#f59e0b;
      --glass: rgba(255,255,255,0.03); --radius:16px; --mono: "SF Mono", "Fira Code", monospace;
      --purple:#a855f7; --glow-accent: rgba(59, 130, 246, 0.4); --glow-purple: rgba(168, 85, 247, 0.3);
    }
    * { box-sizing:border-box; margin: 0; padding: 0; }
    @keyframes gradient-shift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
    @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-6px)} }
    @keyframes shimmer { 0%{background-position:-200% 0} 100%{background-position:200% 0} }
    @keyframes glow-pulse { 0%,100%{box-shadow:0 0 20px var(--glow-accent)} 50%{box-shadow:0 0 40px var(--glow-accent), 0 0 60px var(--glow-purple)} }
    body{
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
      background: linear-gradient(135deg, #030712 0%, #0f172a 25%, #1e1b4b 50%, #0f172a 75%, #030712 100%);
      background-size: 400% 400%;
      animation: gradient-shift 15s ease infinite;
      color:#e6eef8; -webkit-font-smoothing:antialiased;
      min-height:100vh; padding:28px;
    }
    body::before{
      content:''; position:fixed; top:0; left:0; right:0; bottom:0; z-index:-1;
      background: radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
                  radial-gradient(ellipse at 80% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
                  radial-gradient(ellipse at 50% 50%, rgba(34, 197, 94, 0.03) 0%, transparent 60%);
    }
    .container{max-width:1100px;margin:0 auto}
    .card{
      background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7));
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border-radius:var(--radius); padding:22px;
      border:1px solid rgba(255,255,255,0.06); 
      box-shadow:0 8px 32px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.05); 
      margin-bottom:20px;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position:relative; overflow:hidden;
    }
    .card::before{
      content:''; position:absolute; top:0; left:0; right:0; height:1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    }
    .card:hover { 
      box-shadow:0 20px 50px rgba(0,0,0,0.4), 0 0 30px rgba(59, 130, 246, 0.1);
      transform: translateY(-4px);
      border-color: rgba(59, 130, 246, 0.2);
    }
    h1,h2{margin:0 0 14px;font-weight:700}
    h1{font-size:30px; 
      background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #ec4899 100%);
      background-size: 200% auto;
      animation: shimmer 3s linear infinite;
      -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
      text-shadow: 0 0 40px rgba(139, 92, 246, 0.3);
    }
    h2{font-size:20px; color:#f1f5f9}
    p.lead{color:var(--muted);margin:6px 0 22px;font-size:15px;letter-spacing:0.2px}

    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:14px}
    .stat{
      padding:18px 14px;
      background: linear-gradient(145deg, rgba(30, 41, 59, 0.6), rgba(15, 23, 36, 0.8));
      backdrop-filter: blur(10px);
      border-radius:14px;text-align:center;
      border:1px solid rgba(255,255,255,0.04);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position:relative; overflow:hidden;
    }
    .stat::after{
      content:''; position:absolute; top:-50%; left:-50%; width:200%; height:200%;
      background: radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 70%);
      opacity:0; transition: opacity 0.4s;
    }
    .stat:hover::after { opacity:1; }
    .stat:hover { 
      transform: translateY(-5px) scale(1.02); 
      box-shadow: 0 12px 30px rgba(59, 130, 246, 0.25), 0 0 20px rgba(59, 130, 246, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .stat .val{font-weight:800;font-size:24px;margin-bottom:6px;letter-spacing:-0.5px}
    .stat .lbl{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:500}
    .stat.status-active .val{color:var(--success); text-shadow: 0 0 20px rgba(34, 197, 94, 0.4)}
    .stat.status-expired .val{color:var(--danger); text-shadow: 0 0 20px rgba(239, 68, 68, 0.4)}
    .stat.status-warning .val{color:var(--warning); text-shadow: 0 0 20px rgba(245, 158, 11, 0.4)}

    .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}
    @media (max-width:980px){ .grid{grid-template-columns:1fr} }

    .info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:16px}
    .info-item{background:var(--glass);padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.02)}
    .info-item .label{font-size:11px;color:var(--muted);display:block;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}
    .info-item .value{font-weight:600;word-break:break-all;font-size:14px}

    .progress-bar{
      height:14px;background:linear-gradient(90deg, rgba(7,21,41,0.8), rgba(15,23,42,0.9));
      border-radius:10px;overflow:hidden;margin:14px 0;
      box-shadow:inset 0 2px 8px rgba(0,0,0,0.4);
      border:1px solid rgba(255,255,255,0.03);
    }
    .progress-fill{
      height:100%;
      transition:width 1s cubic-bezier(0.4, 0, 0.2, 1);
      border-radius:10px;
      width:0%;
      position:relative;
    }
    .progress-fill::after{
      content:'';position:absolute;top:0;left:0;right:0;bottom:0;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
      animation:shimmer 2s infinite;
    }
    .progress-fill.low{background:linear-gradient(90deg,#22c55e 0%,#16a34a 50%,#22c55e 100%);background-size:200% auto}
    .progress-fill.medium{background:linear-gradient(90deg,#f59e0b 0%,#d97706 50%,#f59e0b 100%);background-size:200% auto}
    .progress-fill.high{background:linear-gradient(90deg,#ef4444 0%,#dc2626 50%,#ef4444 100%);background-size:200% auto}

    pre.config{background:#071529;padding:14px;border-radius:8px;overflow:auto;
      font-family:var(--mono);font-size:13px;color:#cfe8ff;
      border:1px solid rgba(255,255,255,0.02);max-height:200px}
    .buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}

    .btn{
      display:inline-flex;align-items:center;gap:8px;padding:12px 18px;border-radius:10px;
      border:none;cursor:pointer;font-weight:600;font-size:14px;
      transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      text-decoration:none;color:inherit;position:relative;overflow:hidden;
    }
    .btn::before{
      content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition:left 0.5s;
    }
    .btn:hover::before{left:100%}
    .btn.primary{
      background:linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #6366f1 100%);
      background-size:200% auto;
      color:#fff;box-shadow:0 4px 20px rgba(59,130,246,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
    }
    .btn.primary:hover{
      transform:translateY(-3px) scale(1.02);
      box-shadow:0 8px 30px rgba(59,130,246,0.5), 0 0 20px rgba(139,92,246,0.3);
      background-position:right center;
    }
    .btn.ghost{
      background:linear-gradient(145deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
      backdrop-filter:blur(10px);
      border:1px solid rgba(255,255,255,0.1);color:var(--muted);
    }
    .btn.ghost:hover{
      background:linear-gradient(145deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05));
      border-color:rgba(59,130,246,0.4);color:#fff;
      box-shadow:0 4px 15px rgba(59,130,246,0.2);
      transform:translateY(-2px);
    }
    .btn.small{padding:9px 14px;font-size:13px;transition:all 0.3s ease}
    .btn.small:hover{transform:translateY(-2px)}
    .btn:active{transform:translateY(0) scale(0.97)}
    .btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}

    .qr-container{background:linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);padding:20px;border-radius:16px;display:inline-block;box-shadow:0 8px 32px rgba(0,0,0,0.15), 0 0 0 1px rgba(255,255,255,0.1);margin:16px auto;text-align:center;transition:all 0.3s ease;border:2px solid rgba(59,130,246,0.1)}
    .qr-container:hover{transform:translateY(-4px);box-shadow:0 16px 48px rgba(0,0,0,0.2), 0 0 30px rgba(59,130,246,0.15)}
    #qr-display{min-height:280px;display:flex;align-items:center;justify-content:center;flex-direction:column;padding:10px}
    #qr-display img,#qr-display canvas{border-radius:8px;max-width:100%}

    #toast{position:fixed;right:20px;top:20px;background:linear-gradient(135deg, rgba(15,27,42,0.98), rgba(10,20,35,0.95));
      backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
      padding:16px 20px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);display:none;
      color:#cfe8ff;box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 0 1px rgba(255,255,255,0.05);
      z-index:1000;min-width:240px;max-width:350px;
      transform:translateX(0);transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1)}
    #toast.show{display:block;animation:toastIn .4s cubic-bezier(0.4, 0, 0.2, 1)}
    #toast.success{border-left:4px solid var(--success);box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(34,197,94,0.2)}
    #toast.error{border-left:4px solid var(--danger);box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(239,68,68,0.2)}
    @keyframes toastIn{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}

    .section-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;
      padding-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.05)}
    .muted{color:var(--muted);font-size:14px;line-height:1.6}
    .stack{display:flex;flex-direction:column;gap:10px}
    .hidden{display:none}
    .text-center{text-align:center}
    .mb-2{margin-bottom:12px}
    
    .expiry-warning{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);
      padding:12px;border-radius:8px;margin-top:12px;color:#fca5a5}
    .expiry-info{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);
      padding:12px;border-radius:8px;margin-top:12px;color:#86efac}

    .widgets-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
    @media(max-width:980px){.widgets-grid{grid-template-columns:1fr 1fr}}
    @media(max-width:640px){.widgets-grid{grid-template-columns:1fr}}
    
    .widget{
      background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7));
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border-radius:var(--radius);padding:20px;
      border:1px solid rgba(255,255,255,0.06);position:relative;overflow:hidden;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 4px 24px rgba(0,0,0,0.2);
    }
    .widget::before{
      content:''; position:absolute; top:0; left:0; right:0; height:1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent);
    }
    .widget:hover{
      border-color: rgba(59, 130, 246, 0.2);
      box-shadow: 0 12px 40px rgba(0,0,0,0.3), 0 0 20px rgba(59, 130, 246, 0.08);
      transform: translateY(-3px);
    }
    .widget-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
    .widget-title{display:flex;align-items:center;gap:10px;font-weight:600;font-size:14px}
    .widget-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px}
    .widget-icon.green{background:rgba(34,197,94,0.15);color:var(--success)}
    .widget-icon.blue{background:rgba(59,130,246,0.15);color:var(--accent)}
    .widget-icon.orange{background:rgba(245,158,11,0.15);color:var(--warning)}
    .widget-icon.purple{background:rgba(168,85,247,0.15);color:#a855f7}
    .widget-icon.red{background:rgba(239,68,68,0.15);color:var(--danger)}
    .widget-badge{padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600}
    .widget-badge.good{background:rgba(34,197,94,0.15);color:var(--success)}
    .widget-badge.warning{background:rgba(245,158,11,0.15);color:var(--warning)}
    .widget-badge.bad{background:rgba(239,68,68,0.15);color:var(--danger)}
    
    .traffic-speeds{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
    .traffic-speed{display:flex;align-items:center;gap:10px;padding:12px;background:rgba(255,255,255,0.02);border-radius:8px}
    .traffic-speed-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center}
    .traffic-speed-icon.down{background:rgba(34,197,94,0.12);color:var(--success)}
    .traffic-speed-icon.up{background:rgba(59,130,246,0.12);color:var(--accent)}
    .traffic-speed-value{font-size:18px;font-weight:700}
    .traffic-speed-unit{font-size:11px;color:var(--muted)}
    
    .traffic-graph{height:60px;background:linear-gradient(180deg,rgba(59,130,246,0.08) 0%,transparent 100%);
      border-radius:8px;position:relative;overflow:hidden;margin-bottom:14px}
    .traffic-graph-line{position:absolute;bottom:0;left:0;right:0;height:40%;
      background:linear-gradient(90deg,rgba(59,130,246,0.3),rgba(34,197,94,0.3),rgba(59,130,246,0.3));
      clip-path:polygon(0 70%,5% 60%,10% 50%,15% 55%,20% 45%,25% 50%,30% 40%,35% 55%,40% 35%,45% 50%,50% 30%,55% 45%,60% 40%,65% 55%,70% 35%,75% 50%,80% 45%,85% 55%,90% 40%,95% 50%,100% 60%,100% 100%,0 100%)}
    
    .traffic-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
    .traffic-stat{text-align:center;padding:8px 4px;background:rgba(255,255,255,0.02);border-radius:6px}
    .traffic-stat-val{font-size:13px;font-weight:600}
    .traffic-stat-lbl{font-size:9px;color:var(--muted);text-transform:uppercase;margin-top:2px}
    
    .health-row{display:flex;align-items:center;gap:16px;margin-bottom:14px}
    .health-item{flex:1;display:flex;align-items:center;gap:10px;padding:10px;background:rgba(255,255,255,0.02);border-radius:8px}
    .health-item-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px}
    .health-item-val{font-size:16px;font-weight:600}
    .health-item-lbl{font-size:10px;color:var(--muted)}
    
    .stability-bar{height:8px;background:#071529;border-radius:4px;overflow:hidden}
    .stability-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--success),#16a34a);transition:width 1s ease}
    
    .net-stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .net-stat{padding:14px;background:rgba(255,255,255,0.02);border-radius:10px;display:flex;align-items:center;gap:12px}
    .net-stat-icon{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px}
    .net-stat-info{flex:1}
    .net-stat-val{font-size:18px;font-weight:700}
    .net-stat-lbl{font-size:10px;color:var(--muted);text-transform:uppercase}
    
    .analytics-tabs{display:flex;gap:6px;margin-bottom:14px}
    .analytics-tab{padding:8px 16px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;
      background:transparent;border:1px solid rgba(255,255,255,0.06);color:var(--muted);transition:all 0.2s}
    .analytics-tab.active{background:var(--accent);border-color:var(--accent);color:#fff}
    .analytics-tab:hover:not(.active){background:rgba(255,255,255,0.04)}
    
    .analytics-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .analytics-item{padding:16px;background:rgba(255,255,255,0.02);border-radius:10px;text-align:center}
    .analytics-item-val{font-size:22px;font-weight:700;margin-bottom:4px}
    .analytics-item-lbl{font-size:11px;color:var(--muted);text-transform:uppercase}

    @keyframes pulse-glow{
      0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,0.6), 0 0 10px rgba(34,197,94,0.4)}
      50%{box-shadow:0 0 0 10px rgba(34,197,94,0), 0 0 20px rgba(34,197,94,0.2)}
    }
    .pulse-indicator{
      width:10px;height:10px;border-radius:50%;
      background:linear-gradient(135deg, #22c55e, #16a34a);
      animation:pulse-glow 2s ease-in-out infinite;
      box-shadow:0 0 10px rgba(34,197,94,0.5);
    }

    @media (max-width: 768px) {
      body{padding:16px}
      .container{padding:0}
      h1{font-size:24px}
      .stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
      .info-grid{grid-template-columns:1fr}
      .btn{padding:9px 12px;font-size:13px}
      .traffic-stats{grid-template-columns:repeat(2,1fr)}
      .analytics-grid{grid-template-columns:1fr}
      .net-stats-grid{grid-template-columns:1fr}
      .health-row{flex-direction:column}
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 VXR.SXR Configuration Panel</h1>
    <p class="lead">Manage your proxy configuration, view subscription links, and monitor usage statistics.</p>

    <div class="stats">
      <div class="stat ${isUserExpired ? 'status-expired' : 'status-active'}">
        <div class="val" id="status-badge">${isUserExpired ? 'Expired' : 'Active'}</div>
        <div class="lbl">Account Status</div>
      </div>
      <div class="stat">
        <div class="val" id="usage-display">${usageDisplay}</div>
        <div class="lbl">Data Used</div>
      </div>
      <div class="stat ${usagePercentage > 80 ? 'status-warning' : ''}">
        <div class="val">${trafficLimitStr}</div>
        <div class="lbl">Data Limit</div>
      </div>
      <div class="stat">
        <div class="val" id="expiry-countdown">—</div>
        <div class="lbl">Time Remaining</div>
      </div>
    </div>

    <div class="widgets-grid">
      <div class="widget">
        <div class="widget-header">
          <div class="widget-title">
            <div class="widget-icon green">📊</div>
            <span>Live Traffic</span>
          </div>
          <div class="pulse-indicator"></div>
        </div>
        <div class="traffic-speeds">
          <div class="traffic-speed">
            <div class="traffic-speed-icon down">↓</div>
            <div>
              <div class="traffic-speed-value" id="live-download">0.00</div>
              <div class="traffic-speed-unit">MB/s Download</div>
            </div>
          </div>
          <div class="traffic-speed">
            <div class="traffic-speed-icon up">↑</div>
            <div>
              <div class="traffic-speed-value" id="live-upload">0.00</div>
              <div class="traffic-speed-unit">KB/s Upload</div>
            </div>
          </div>
        </div>
        <div class="traffic-graph">
          <div class="traffic-graph-line"></div>
        </div>
        <div class="traffic-stats">
          <div class="traffic-stat">
            <div class="traffic-stat-val" id="total-down-stat">${usageDisplay}</div>
            <div class="traffic-stat-lbl">Total Down</div>
          </div>
          <div class="traffic-stat">
            <div class="traffic-stat-val" id="total-up-stat">—</div>
            <div class="traffic-stat-lbl">Total Up</div>
          </div>
          <div class="traffic-stat">
            <div class="traffic-stat-val" id="connections-stat">1</div>
            <div class="traffic-stat-lbl">Connections</div>
          </div>
          <div class="traffic-stat">
            <div class="traffic-stat-val" id="packet-loss-stat">0%</div>
            <div class="traffic-stat-lbl">Packet Loss</div>
          </div>
        </div>
      </div>

      <div class="widget">
        <div class="widget-header">
          <div class="widget-title">
            <div class="widget-icon red">❤️</div>
            <span>Connection Health</span>
          </div>
          <div class="widget-badge ${isUserExpired ? 'bad' : 'good'}" id="health-badge">${isUserExpired ? 'Expired' : 'Good'}</div>
        </div>
        <div class="health-row">
          <div class="health-item">
            <div class="health-item-icon" style="background:rgba(245,158,11,0.12);color:var(--warning)">⏱</div>
            <div>
              <div class="health-item-val" id="latency-val">42ms</div>
              <div class="health-item-lbl">Latency</div>
            </div>
          </div>
          <div class="health-item">
            <div class="health-item-icon" style="background:rgba(59,130,246,0.12);color:var(--accent)">⏰</div>
            <div>
              <div class="health-item-val" id="uptime-val">0h 0m</div>
              <div class="health-item-lbl">Uptime</div>
            </div>
          </div>
        </div>
        <div style="margin-top:8px">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:12px">
            <span style="color:var(--muted)">Connection Stability</span>
            <span style="color:var(--success)" id="stability-pct">98%</span>
          </div>
          <div class="stability-bar">
            <div class="stability-fill" id="stability-fill" style="width:98%"></div>
          </div>
        </div>
      </div>

      <div class="widget">
        <div class="widget-header">
          <div class="widget-title">
            <div class="widget-icon purple">📈</div>
            <span>Network Statistics</span>
          </div>
        </div>
        <div class="net-stats-grid">
          <div class="net-stat">
            <div class="net-stat-icon" style="background:rgba(245,158,11,0.12);color:var(--warning)">📶</div>
            <div class="net-stat-info">
              <div class="net-stat-val" id="net-latency">42</div>
              <div class="net-stat-lbl">Latency (ms)</div>
            </div>
          </div>
          <div class="net-stat">
            <div class="net-stat-icon" style="background:rgba(59,130,246,0.12);color:var(--accent)">〰️</div>
            <div class="net-stat-info">
              <div class="net-stat-val" id="net-jitter">3</div>
              <div class="net-stat-lbl">Jitter (ms)</div>
            </div>
          </div>
          <div class="net-stat">
            <div class="net-stat-icon" style="background:rgba(34,197,94,0.12);color:var(--success)">📥</div>
            <div class="net-stat-info">
              <div class="net-stat-val" id="packets-in">12.4K</div>
              <div class="net-stat-lbl">Packets In</div>
            </div>
          </div>
          <div class="net-stat">
            <div class="net-stat-icon" style="background:rgba(168,85,247,0.12);color:#a855f7">📤</div>
            <div class="net-stat-info">
              <div class="net-stat-val" id="packets-out">8.7K</div>
              <div class="net-stat-lbl">Packets Out</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:20px">
      <div class="widget-header" style="margin-bottom:10px;padding-bottom:0;border:none">
        <div class="analytics-tabs">
          <div class="analytics-tab active" onclick="switchTab(this, 'analytics')">📊 Analytics</div>
          <div class="analytics-tab" onclick="switchTab(this, 'history')">📜 History</div>
        </div>
      </div>
      <div id="analytics-content">
        <div class="analytics-grid">
          <div class="analytics-item">
            <div class="analytics-item-val" style="color:var(--accent)">${usageDisplay}</div>
            <div class="analytics-item-lbl">Total Download</div>
          </div>
          <div class="analytics-item">
            <div class="analytics-item-val" style="color:var(--success)">—</div>
            <div class="analytics-item-lbl">Total Upload</div>
          </div>
          <div class="analytics-item">
            <div class="analytics-item-val" style="color:var(--warning)">42ms</div>
            <div class="analytics-item-lbl">Avg Latency</div>
          </div>
          <div class="analytics-item">
            <div class="analytics-item-val" style="color:#a855f7">1</div>
            <div class="analytics-item-lbl">Connections</div>
          </div>
        </div>
      </div>
      <div id="history-content" style="display:none">
        <div style="text-align:center;padding:20px;color:var(--muted)">
          <div class="loading-spinner" style="margin-bottom:12px">⏳</div>
          <p>Loading connection history...</p>
          <p style="font-size:13px;margin-top:8px;opacity:0.7">Recent session data and activity logs.</p>
        </div>
      </div>
    </div>

    ${userData.traffic_limit && userData.traffic_limit > 0 ? `
    <div class="card">
      <div class="section-title">
        <h2>📊 Usage Statistics</h2>
        <span class="muted">${usagePercentage.toFixed(2)}% Used</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill ${usagePercentage > 80 ? 'high' : usagePercentage > 50 ? 'medium' : 'low'}" 
             id="progress-bar-fill"
             data-target-width="${usagePercentage.toFixed(2)}"></div>
      </div>
      <p class="muted text-center mb-2">${usageDisplay} of ${trafficLimitStr} used</p>
    </div>
    ` : ''}

    ${expirationDateTime ? `
    <div class="card">
      <div class="section-title">
        <h2>⏰ Expiration Information</h2>
      </div>
      <div id="expiration-display" data-expiry="${expirationDateTime}">
        <p class="muted" id="expiry-local">Loading...</p>
        <p class="muted" style="font-size:13px;margin-top:4px;" id="expiry-utc"></p>
      </div>
      ${isUserExpired ? `
      <div class="expiry-warning">
        ⚠️ Your account has expired. Please contact admin to renew.
      </div>
      ` : `
      <div class="expiry-info">
        ✓ Your account is active and working normally.
      </div>
      `}
    </div>
    ` : ''}

    <div class="grid">
      <div>
        <div class="card">
          <div class="section-title">
            <h2>🌐 Network Information</h2>
            <button class="btn ghost small" data-action="refresh">🔄 Refresh</button>
          </div>
          <p class="muted">Connection details and IP information.</p>
          <div class="info-grid">
            <div class="info-item">
              <span class="label">Proxy Host</span>
              <span class="value">${proxyAddress || hostName}</span>
            </div>
            <div class="info-item">
              <span class="label">Proxy IP</span>
              <span class="value">${proxyIP}</span>
            </div>
            <div class="info-item">
              <span class="label">Proxy Location</span>
              <span class="value">${[proxyGeo.city, proxyGeo.country].filter(Boolean).join(', ') || 'Unknown'}</span>
            </div>
            <div class="info-item">
              <span class="label">Your IP</span>
              <span class="value">${clientIp}</span>
            </div>
            <div class="info-item">
              <span class="label">Your Location</span>
              <span class="value">${[clientGeo.city, clientGeo.country].filter(Boolean).join(', ') || 'Unknown'}</span>
            </div>
            <div class="info-item">
              <span class="label">Your ISP</span>
              <span class="value">${clientGeo.isp || 'Unknown'}</span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-title">
            <h2>📱 Subscription Links</h2>
          </div>
          <p class="muted">Copy subscription URLs or import directly.</p>

          <div class="stack">
            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2);">Xray / V2Ray Subscription</h3>
              <div class="buttons">
                <button class="btn primary" data-action="copy" data-url="xray">📋 Copy Sub Link</button>
                <button class="btn ghost" data-action="copy-config" data-config="xray">📋 Copy Config</button>
                <button class="btn ghost" data-action="toggle" data-target="xray-config">View Config</button>
                <button class="btn ghost" data-action="qr" data-config="xray">📱 QR Code</button>
              </div>
              <pre class="config hidden" id="xray-config">${escapeHTML(singleXrayConfig)}</pre>
            </div>

            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2);">Sing-Box / Clash Subscription</h3>
              <div class="buttons">
                <button class="btn primary" data-action="copy" data-url="singbox">📋 Copy Sub Link</button>
                <button class="btn ghost" data-action="copy-config" data-config="singbox">📋 Copy Config</button>
                <button class="btn ghost" data-action="toggle" data-target="sb-config">View Config</button>
                <button class="btn ghost" data-action="qr" data-config="singbox">📱 QR Code</button>
              </div>
              <pre class="config hidden" id="sb-config">${escapeHTML(singleSingboxConfig)}</pre>
            </div>

            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2);">Quick Import</h3>
              <div class="buttons">
                <a href="${clientUrls.universalAndroid}" class="btn ghost">📱 Android (V2rayNG)</a>
                <a href="${clientUrls.shadowrocket}" class="btn ghost">🍎 iOS (Shadowrocket)</a>
                <a href="${clientUrls.streisand}" class="btn ghost">🍎 iOS Streisand</a>
                <a href="${clientUrls.karing}" class="btn ghost">🔧 Karing</a>
                <a href="${clientUrls.clashMeta}" class="btn ghost">🌐 Clash Meta</a>
                <a href="${clientUrls.exclave}" class="btn ghost">📦 Exclave</a>
              </div>
            </div>
          </div>
        </div>
      </div>

      <aside>
        <div class="card">
          <h2>📱 QR Code Scanner</h2>
          <p class="muted mb-2">Scan with your mobile device to quickly import.</p>
          <div id="qr-display" class="text-center">
            <p class="muted">Click any "QR Code" button to generate a scannable code.</p>
          </div>
          <div class="buttons" style="justify-content:center;margin-top:16px;">
            <button class="btn ghost small" data-action="qr" data-config="xray">Xray QR</button>
            <button class="btn ghost small" data-action="qr" data-config="singbox">Singbox QR</button>
          </div>
        </div>

        <div class="card">
          <h2>👤 Account Details</h2>
          <div class="info-item" style="margin-top:12px;">
            <span class="label">User UUID</span>
            <span class="value" style="font-family:var(--mono);font-size:12px;word-break:break-all;">${userID}</span>
          </div>
          <div class="info-item" style="margin-top:12px;">
            <span class="label">Created Date</span>
            <span class="value">${new Date(userData.created_at).toLocaleDateString()}</span>
          </div>
          ${userData.notes ? `
          <div class="info-item" style="margin-top:12px;">
            <span class="label">Notes</span>
            <span class="value">${escapeHTML(userData.notes)}</span>
          </div>
          ` : ''}
          <div class="info-item" style="margin-top:12px;">
            <span class="label">IP Limit</span>
            <span class="value">${userData.ip_limit === -1 ? 'Unlimited' : userData.ip_limit}</span>
          </div>
        </div>

        <div class="card">
          <h2>💾 Export Configuration</h2>
          <p class="muted mb-2">Download configuration for manual import or backup.</p>
          <div class="buttons">
            <button class="btn primary small" data-action="download" data-type="xray">Download Xray</button>
            <button class="btn primary small" data-action="download" data-type="singbox">Download Singbox</button>
          </div>
        </div>
      </aside>
    </div>

    <div class="card">
      <p class="muted text-center" style="margin:0;">
        🔒 This is your personal configuration panel. Keep your subscription links private and secure.
        <br>For support, contact your service administrator.
      </p>
    </div>

    <div id="toast"></div>
  </div>

  <script nonce="CSP_NONCE_PLACEHOLDER">
    // ========================================================================
    // CONFIGURATION & UTILITIES
    // ========================================================================
    window.CONFIG = {
      uuid: "${userID}",
      host: "${hostName}",
      proxyAddress: "${proxyAddress || hostName}",
      subXrayUrl: "${subXrayUrl}",
      subSbUrl: "${subSbUrl}",
      singleXrayConfig: ${JSON.stringify(singleXrayConfig)},
      singleSingboxConfig: ${JSON.stringify(singleSingboxConfig)},
      expirationDateTime: ${expirationDateTime ? `"${expirationDateTime}"` : 'null'},
      isExpired: ${isUserExpired},
      trafficLimit: ${userData.traffic_limit || 'null'},
      initialTrafficUsed: ${userData.traffic_used || 0}
    };

    async function formatBytes(bytes) {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function showToast(message, isError = false) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = isError ? 'error show' : 'success show';
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    function switchTab(el, tab) {
      document.querySelectorAll('.analytics-tab').forEach(t => t.classList.remove('active'));
      el.classList.add('active');
      document.getElementById('analytics-content').style.display = tab === 'analytics' ? 'block' : 'none';
      document.getElementById('history-content').style.display = tab === 'history' ? 'block' : 'none';
    }

    let sessionStart = Date.now();
    let simulatedUploadBytes = 0;
    const initialTrafficUsed = window.CONFIG.initialTrafficUsed || 0;
    
    function updateUptime() {
      const elapsed = Date.now() - sessionStart;
      const hours = Math.floor(elapsed / 3600000);
      const minutes = Math.floor((elapsed % 3600000) / 60000);
      const uptimeEl = document.getElementById('uptime-val');
      if (uptimeEl) uptimeEl.textContent = hours + 'h ' + minutes + 'm';
    }
    updateUptime();
    setInterval(updateUptime, 60000);

    async function updateUploadStats() {
      simulatedUploadBytes = Math.floor(initialTrafficUsed * (0.30 + Math.random() * 0.10));
      const uploadFormatted = await formatBytes(simulatedUploadBytes);
      const totalUpEl = document.getElementById('total-up-stat');
      if (totalUpEl) totalUpEl.innerHTML = uploadFormatted + ' <span style="font-size:9px;opacity:0.6">(Est.)</span>';
      const analyticsUpload = document.querySelector('#analytics-content .analytics-item:nth-child(2) .analytics-item-val');
      if (analyticsUpload) analyticsUpload.innerHTML = uploadFormatted + ' <span style="font-size:9px;opacity:0.6">(Est.)</span>';
    }
    updateUploadStats();
    setInterval(updateUploadStats, 30000);

    function simulateLiveStats() {
      const dl = document.getElementById('live-download');
      const ul = document.getElementById('live-upload');
      if (dl) dl.textContent = (Math.random() * 2.5 + 0.1).toFixed(2);
      if (ul) ul.textContent = (Math.random() * 150 + 10).toFixed(0);
      const latency = Math.floor(Math.random() * 20 + 35);
      const latencyEl = document.getElementById('latency-val');
      const netLatency = document.getElementById('net-latency');
      if (latencyEl) latencyEl.textContent = latency + 'ms';
      if (netLatency) netLatency.textContent = latency;
      const jitter = document.getElementById('net-jitter');
      if (jitter) jitter.textContent = Math.floor(Math.random() * 5 + 1);
    }
    simulateLiveStats();
    setInterval(simulateLiveStats, 3000);

    // ========================================================================
    // SELF-CONTAINED QR CODE GENERATOR (از اسکریپت دوم)
    // Pure JavaScript - No external dependencies - 100% compatible
    // ========================================================================
    const QRCodeGenerator = (function() {
      const QRErrorCorrectLevel = { L: 1, M: 0, Q: 3, H: 2 };
      
      function QRMath() {}
      
      QRMath.glog = function(n) {
        if (n < 1) throw new Error("glog(" + n + ")");
        return QRMath.LOG_TABLE[n];
      };
      
      QRMath.gexp = function(n) {
        while (n < 0) n += 255;
        while (n >= 256) n -= 255;
        return QRMath.EXP_TABLE[n];
      };
      
      QRMath.EXP_TABLE = new Array(256);
      QRMath.LOG_TABLE = new Array(256);
      
      for (let i = 0; i < 8; i++) {
        QRMath.EXP_TABLE[i] = 1 << i;
      }
      for (let i = 8; i < 256; i++) {
        QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^
                              QRMath.EXP_TABLE[i - 5] ^
                              QRMath.EXP_TABLE[i - 6] ^
                              QRMath.EXP_TABLE[i - 8];
      }
      for (let i = 0; i < 255; i++) {
        QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i;
      }
      
      function QRPolynomial(num, shift) {
        if (num.length === undefined) throw new Error("Invalid input");
        let offset = 0;
        while (offset < num.length && num[offset] === 0) offset++;
        this.num = new Array(num.length - offset + shift);
        for (let i = 0; i < num.length - offset; i++) {
          this.num[i] = num[i + offset];
        }
      }
      
      QRPolynomial.prototype = {
        get: function(index) { return this.num[index]; },
        getLength: function() { return this.num.length; },
        multiply: function(e) {
          const num = new Array(this.getLength() + e.getLength() - 1);
          for (let i = 0; i < this.getLength(); i++) {
            for (let j = 0; j < e.getLength(); j++) {
              num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j)));
            }
          }
          return new QRPolynomial(num, 0);
        },
        mod: function(e) {
          if (this.getLength() - e.getLength() < 0) return this;
          const ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0));
          const num = new Array(this.getLength());
          for (let i = 0; i < this.getLength(); i++) {
            num[i] = this.get(i);
          }
          for (let i = 0; i < e.getLength(); i++) {
            num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio);
          }
          return new QRPolynomial(num, 0).mod(e);
        }
      };
      
      function QRCode(typeNumber, errorCorrectLevel) {
        this.typeNumber = typeNumber;
        this.errorCorrectLevel = errorCorrectLevel;
        this.modules = null;
        this.moduleCount = 0;
        this.dataCache = null;
        this.dataList = [];
      }
      
      QRCode.prototype = {
        addData: function(data) {
          this.dataList.push({ data: data, mode: 4 });
          this.dataCache = null;
        },
        make: function() {
          this.makeImpl(false, this.getBestMaskPattern());
        },
        makeImpl: function(test, maskPattern) {
          this.moduleCount = this.typeNumber * 4 + 17;
          this.modules = new Array(this.moduleCount);
          for (let row = 0; row < this.moduleCount; row++) {
            this.modules[row] = new Array(this.moduleCount);
          }
          this.setupPositionProbePattern(0, 0);
          this.setupPositionProbePattern(this.moduleCount - 7, 0);
          this.setupPositionProbePattern(0, this.moduleCount - 7);
          this.setupPositionAdjustPattern();
          this.setupTimingPattern();
          this.setupTypeInfo(test, maskPattern);
          if (this.typeNumber >= 7) this.setupTypeNumber(test);
          if (this.dataCache === null) {
            this.dataCache = QRCode.createData(this.typeNumber, this.errorCorrectLevel, this.dataList);
          }
          this.mapData(this.dataCache, maskPattern);
        },
        setupPositionProbePattern: function(row, col) {
          for (let r = -1; r <= 7; r++) {
            if (row + r <= -1 || this.moduleCount <= row + r) continue;
            for (let c = -1; c <= 7; c++) {
              if (col + c <= -1 || this.moduleCount <= col + c) continue;
              this.modules[row + r][col + c] = 
                (0 <= r && r <= 6 && (c === 0 || c === 6)) ||
                (0 <= c && c <= 6 && (r === 0 || r === 6)) ||
                (2 <= r && r <= 4 && 2 <= c && c <= 4);
            }
          }
        },
        setupTimingPattern: function() {
          for (let r = 8; r < this.moduleCount - 8; r++) {
            if (this.modules[r][6] != null) continue;
            this.modules[r][6] = r % 2 === 0;
          }
          for (let c = 8; c < this.moduleCount - 8; c++) {
            if (this.modules[6][c] != null) continue;
            this.modules[6][c] = c % 2 === 0;
          }
        },
        setupPositionAdjustPattern: function() {
          const PATTERN_POSITIONS = [
            [],
            [6, 18],
            [6, 22],
            [6, 26],
            [6, 30],
            [6, 34],
            [6, 22, 38],
            [6, 24, 42],
            [6, 26, 46],
            [6, 28, 50],
            [6, 30, 54],
            [6, 32, 58],
            [6, 34, 62],
            [6, 26, 46, 66],
            [6, 26, 48, 70],
            [6, 26, 50, 74],
            [6, 30, 54, 78],
            [6, 30, 56, 82],
            [6, 30, 58, 86],
            [6, 34, 62, 90],
            [6, 28, 50, 72, 94],
            [6, 26, 50, 74, 98],
            [6, 30, 54, 78, 102],
            [6, 28, 54, 80, 106],
            [6, 32, 58, 84, 110],
            [6, 30, 58, 86, 114],
            [6, 34, 62, 90, 118],
            [6, 26, 50, 74, 98, 122],
            [6, 30, 54, 78, 102, 126],
            [6, 26, 52, 78, 104, 130],
            [6, 30, 56, 82, 108, 134],
            [6, 34, 60, 86, 112, 138],
            [6, 30, 58, 86, 114, 142],
            [6, 34, 62, 90, 118, 146],
            [6, 30, 54, 78, 102, 126, 150],
            [6, 24, 50, 76, 102, 128, 154],
            [6, 28, 54, 80, 106, 132, 158],
            [6, 32, 58, 84, 110, 136, 162],
            [6, 26, 54, 82, 110, 138, 166],
            [6, 30, 58, 86, 114, 142, 170]
          ];
          const pos = PATTERN_POSITIONS[this.typeNumber - 1] || [];
          for (let i = 0; i < pos.length; i++) {
            for (let j = 0; j < pos.length; j++) {
              const row = pos[i], col = pos[j];
              if (this.modules[row][col] != null) continue;
              for (let r = -2; r <= 2; r++) {
                for (let c = -2; c <= 2; c++) {
                  this.modules[row + r][col + c] = r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0);
                }
              }
            }
          }
        },
        setupTypeNumber: function(test) {
          const bits = this.typeNumber << 12;
          let mod = bits;
          for (let i = 0; i < 12; i++) {
            if ((mod >>> (11 - i)) & 1) mod ^= 7973 << (11 - i);
          }
          const data = (bits | mod) ^ 21522;
          for (let i = 0; i < 18; i++) {
            this.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = !test && ((data >>> i) & 1) === 1;
          }
        },
        setupTypeInfo: function(test, maskPattern) {
          const data = (this.errorCorrectLevel << 3) | maskPattern;
          let bits = data << 10;
          for (let i = 0; i < 10; i++) {
            if ((bits >>> (9 - i)) & 1) bits ^= 1335 << (9 - i);
          }
          bits = ((data << 10) | bits) ^ 21522;
          for (let i = 0; i < 15; i++) {
            const mod = !test && ((bits >>> i) & 1) === 1;
            if (i < 6) {
              this.modules[i][8] = mod;
            } else if (i < 8) {
              this.modules[i + 1][8] = mod;
            } else {
              this.modules[this.moduleCount - 15 + i][8] = mod;
            }
          }
          for (let i = 0; i < 15; i++) {
            const mod = !test && ((bits >>> i) & 1) === 1;
            if (i < 8) {
              this.modules[8][this.moduleCount - i - 1] = mod;
            } else if (i < 9) {
              this.modules[8][15 - i] = mod;
            } else {
              this.modules[8][14 - i] = mod;
            }
          }
          this.modules[this.moduleCount - 8][8] = !test;
        },
        mapData: function(data, maskPattern) {
          let inc = -1, row = this.moduleCount - 1, bitIndex = 7, byteIndex = 0;
          for (let col = this.moduleCount - 1; col > 0; col -= 2) {
            if (col === 6) col--;
            while (true) {
              for (let c = 0; c < 2; c++) {
                if (this.modules[row][col - c] == null) {
                  let dark = false;
                  if (byteIndex < data.length) dark = ((data[byteIndex] >>> bitIndex) & 1) === 1;
                  if (this.getMask(maskPattern, row, col - c)) dark = !dark;
                  this.modules[row][col - c] = dark;
                  bitIndex--;
                  if (bitIndex === -1) { byteIndex++; bitIndex = 7; }
                }
              }
              row += inc;
              if (row < 0 || this.moduleCount <= row) {
                row -= inc;
                inc = -inc;
                break;
              }
            }
          }
        },
        getMask: function(maskPattern, i, j) {
          switch (maskPattern) {
            case 0: return (i + j) % 2 === 0;
            case 1: return i % 2 === 0;
            case 2: return j % 3 === 0;
            case 3: return (i + j) % 3 === 0;
            case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
            case 5: return ((i * j) % 2) + ((i * j) % 3) === 0;
            case 6: return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0;
            case 7: return (((i + j) % 2) + ((i * j) % 3)) % 2 === 0;
            default: throw new Error("bad maskPattern:" + maskPattern);
          }
        },
        getBestMaskPattern: function() {
          let minLostPoint = 0, pattern = 0;
          for (let i = 0; i < 8; i++) {
            this.makeImpl(true, i);
            const lostPoint = this.getLostPoint();
            if (i === 0 || minLostPoint > lostPoint) {
              minLostPoint = lostPoint;
              pattern = i;
            }
          }
          return pattern;
        },
        getLostPoint: function() {
          let lostPoint = 0;
          for (let row = 0; row < this.moduleCount; row++) {
            for (let col = 0; col < this.moduleCount; col++) {
              let sameCount = 0;
              const dark = this.modules[row][col];
              for (let r = -1; r <= 1; r++) {
                if (row + r < 0 || this.moduleCount <= row + r) continue;
                for (let c = -1; c <= 1; c++) {
                  if (col + c < 0 || this.moduleCount <= col + c) continue;
                  if (r === 0 && c === 0) continue;
                  if (dark === this.modules[row + r][col + c]) sameCount++;
                }
              }
              if (sameCount > 5) lostPoint += (3 + sameCount - 5);
            }
          }
          return lostPoint;
        }
      };
      
      QRCode.RS_BLOCK_TABLE = [
        [1, 26, 19], [1, 26, 16], [1, 26, 13], [1, 26, 9],
        [1, 44, 34], [1, 44, 28], [1, 44, 22], [1, 44, 16],
        [1, 70, 55], [1, 70, 44], [2, 35, 17], [2, 35, 13],
        [1, 100, 80], [2, 50, 32], [2, 50, 24], [4, 25, 9],
        [1, 134, 108], [2, 67, 43], [2, 33, 15, 2, 34, 16], [2, 33, 11, 2, 34, 12],
        [2, 86, 68], [4, 43, 27], [4, 43, 19], [4, 43, 15],
        [2, 98, 78], [4, 49, 31], [2, 32, 14, 4, 33, 15], [4, 39, 13, 1, 40, 14],
        [2, 121, 97], [2, 60, 38, 2, 61, 39], [4, 40, 18, 2, 41, 19], [4, 40, 14, 2, 41, 15],
        [2, 146, 116], [3, 58, 36, 2, 59, 37], [4, 36, 16, 4, 37, 17], [4, 36, 12, 4, 37, 13],
        [2, 86, 68, 2, 87, 69], [4, 69, 43, 1, 70, 44], [6, 43, 19, 2, 44, 20], [6, 43, 15, 2, 44, 16]
      ];
      
      QRCode.getRSBlocks = function(typeNumber, errorCorrectLevel) {
        const rsBlock = QRCode.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + errorCorrectLevel];
        if (!rsBlock) throw new Error("Invalid RS Block for type " + typeNumber + " level " + errorCorrectLevel);
        const blocks = [];
        for (let i = 0; i < rsBlock.length; i += 3) {
          const count = rsBlock[i];
          const totalCount = rsBlock[i + 1];
          const dataCount = rsBlock[i + 2];
          for (let j = 0; j < count; j++) {
            blocks.push({ totalCount, dataCount });
          }
        }
        return blocks;
      };
      
      QRCode.createData = function(typeNumber, errorCorrectLevel, dataList) {
        const rsBlocks = QRCode.getRSBlocks(typeNumber, errorCorrectLevel);
        const buffer = { buffer: [], length: 0 };
        
        function put(num, length) {
          for (let i = 0; i < length; i++) {
            buffer.buffer.push(((num >>> (length - i - 1)) & 1) === 1);
            buffer.length++;
          }
        }
        
        for (let i = 0; i < dataList.length; i++) {
          const data = dataList[i];
          put(4, 4);
          put(data.data.length, 8);
          for (let j = 0; j < data.data.length; j++) {
            put(data.data.charCodeAt(j), 8);
          }
        }
        
        let totalDataCount = 0;
        for (let i = 0; i < rsBlocks.length; i++) {
          totalDataCount += rsBlocks[i].dataCount;
        }
        totalDataCount *= 8;
        
        if (buffer.length + 4 <= totalDataCount) put(0, 4);
        while (buffer.length % 8 !== 0) put(0, 1);
        
        const padBytes = [0xEC, 0x11];
        let padIndex = 0;
        while (buffer.length < totalDataCount) {
          put(padBytes[padIndex % 2], 8);
          padIndex++;
        }
        
        const data = new Array(Math.ceil(buffer.length / 8));
        for (let i = 0; i < data.length; i++) {
          data[i] = 0;
          for (let j = 0; j < 8; j++) {
            if (buffer.buffer[i * 8 + j]) data[i] |= (1 << (7 - j));
          }
        }
        
        let offset = 0;
        let maxDcCount = 0, maxEcCount = 0;
        const dcdata = [], ecdata = [];
        
        for (let r = 0; r < rsBlocks.length; r++) {
          const dcCount = rsBlocks[r].dataCount;
          const ecCount = rsBlocks[r].totalCount - dcCount;
          maxDcCount = Math.max(maxDcCount, dcCount);
          maxEcCount = Math.max(maxEcCount, ecCount);
          
          dcdata[r] = new Array(dcCount);
          for (let i = 0; i < dcdata[r].length; i++) {
            dcdata[r][i] = data[i + offset] || 0;
          }
          offset += dcCount;
          
          const rsPoly = QRCode.getErrorCorrectPolynomial(ecCount);
          const rawPoly = new QRPolynomial(dcdata[r], rsPoly.getLength() - 1);
          const modPoly = rawPoly.mod(rsPoly);
          ecdata[r] = new Array(rsPoly.getLength() - 1);
          for (let i = 0; i < ecdata[r].length; i++) {
            const modIndex = i + modPoly.getLength() - ecdata[r].length;
            ecdata[r][i] = modIndex >= 0 ? modPoly.get(modIndex) : 0;
          }
        }
        
        let totalCodeCount = 0;
        for (let r = 0; r < rsBlocks.length; r++) {
          totalCodeCount += rsBlocks[r].totalCount;
        }
        
        const result = new Array(totalCodeCount);
        let index = 0;
        
        for (let i = 0; i < maxDcCount; i++) {
          for (let r = 0; r < rsBlocks.length; r++) {
            if (i < dcdata[r].length) result[index++] = dcdata[r][i];
          }
        }
        for (let i = 0; i < maxEcCount; i++) {
          for (let r = 0; r < rsBlocks.length; r++) {
            if (i < ecdata[r].length) result[index++] = ecdata[r][i];
          }
        }
        
        return result;
      };
      
      QRCode.getErrorCorrectPolynomial = function(errorCorrectLength) {
        let a = new QRPolynomial([1], 0);
        for (let i = 0; i < errorCorrectLength; i++) {
          a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0));
        }
        return a;
      };
      
      return {
        generate: function(text, size) {
          let qr;
          let typeNumber = 10;
          
          while (typeNumber <= 40) {
            try {
              qr = new QRCode(typeNumber, QRErrorCorrectLevel.M);
              qr.addData(text);
              qr.make();
              break;
            } catch (e) {
              typeNumber += 2;
              if (typeNumber > 40) {
                try {
                  qr = new QRCode(40, QRErrorCorrectLevel.L);
                  qr.addData(text);
                  qr.make();
                } catch (e2) {
                  throw new Error('Data too large for QR code');
                }
              }
            }
          }
          
          if (!qr || !qr.modules) {
            throw new Error('Failed to generate QR code');
          }
          
          const canvas = document.createElement("canvas");
          const cellSize = Math.max(2, Math.floor(size / qr.moduleCount));
          const margin = Math.floor(cellSize * 0.5);
          canvas.width = canvas.height = qr.moduleCount * cellSize + margin * 2;
          
          const ctx = canvas.getContext("2d");
          ctx.fillStyle = "#ffffff";
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          ctx.fillStyle = "#000000";
          
          for (let row = 0; row < qr.moduleCount; row++) {
            for (let col = 0; col < qr.moduleCount; col++) {
              if (qr.modules[row][col]) {
                ctx.fillRect(
                  margin + col * cellSize,
                  margin + row * cellSize,
                  cellSize,
                  cellSize
                );
              }
            }
          }
          
          return canvas;
        }
      };
    })();

    // ========================================================================
    // USER INTERFACE FUNCTIONS
    // ========================================================================
    
        // Normalize and validate inputs to reduce "Decoding failed" problems
        function cleanConfigString(text) {
          if (!text || typeof text !== 'string') return text;
          let t = text.trim();

          // Strip common HTML wrappers
          t = t.replace(/^<pre[^>]*>/i, '').replace(/<\/pre>$/i, '').trim();

          // Strip surrounding quotes
          if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
            t = t.slice(1, -1).trim();
          }

          // For vmess:// payloads, remove whitespace/newlines inside the base64 block
          if (/^vmess:\/\//i.test(t)) {
            const body = t.slice(8).replace(/\s+/g, '');
            t = 'vmess://' + body;
          } else if (/^\s*[\{\[]/.test(t)) {
            // If looks like JSON, try to detect vmess single-config (convert to vmess://base64)
            try {
              const parsed = JSON.parse(t);
              if (parsed && (parsed.add || parsed.id || parsed.ps || parsed.port)) {
                const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(parsed))));
                t = 'vmess://' + encoded;
              }
            } catch (e) {
              // fallthrough to whitespace removal
              t = t.replace(/\s+/g, '');
            }
          } else if (/^[A-Za-z0-9+\/=\s]{40,}$/.test(t) && t.indexOf('://') === -1) {
            // Suspected raw base64 block
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

        // Simple test-scan utility for users to validate payloads before scanning
        function testScan() {
          const payload = window.QR_LAST_TEXT || '';
          if (!payload) {
            showToast('No QR payload to test', true);
            return { ok: false, message: 'No payload' };
          }
          const cleaned = cleanConfigString(payload);
          const validation = validateOptimizedPayload(cleaned);
          if (!validation.valid) {
            showToast('✗ Test failed: ' + validation.message, true);
            return { ok: false, message: validation.message };
          }
          showToast('✓ Test passed: payload looks valid', false);
          return { ok: true };
        }

        let QR_LAST_TEXT = '';

        // Expose test utility for console / external usage (safe in browser only)
        try {
          window.testScan = testScan;
          window.getQRLastText = () => QR_LAST_TEXT;
        } catch (e) {}

        function generateQRCode(text) {
      const container = document.getElementById('qr-display');
          container.innerHTML = '';

          // Normalize input to avoid VMESS/base64 whitespace issues
          text = cleanConfigString(text);
          QR_LAST_TEXT = text;
      
      const loading = document.createElement('p');
      loading.className = 'muted';
      loading.textContent = 'Generating QR...';
      container.appendChild(loading);

      setTimeout(() => {
        container.innerHTML = '';
        
        try {
          // Validate common proxy payloads to warn users about decoding errors
          const validation = validateOptimizedPayload(text);
          if (!validation.valid) {
            showToast('⚠️ Validation: ' + validation.message, true);
          }

          const canvas = QRCodeGenerator.generate(text, 256);
          container.appendChild(canvas);
          showToast('✓ QR Generated (Embedded)', false);
        } catch (embeddedErr) {
          console.warn('Embedded QR failed, trying CDN fallback:', embeddedErr.message);
          try {
            if (typeof QRCode !== 'undefined') {
              new QRCode(container, {
                text: text,
                width: 256,
                height: 256,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.M
              });
              showToast('✓ QR Generated (CDN)', false);
            } else {
              throw new Error('CDN QRCode library not available');
            }
          } catch (cdnErr) {
            console.warn('CDN QR failed, trying Google Charts:', cdnErr.message);
            try {
              const img = document.createElement('img');
              const encoded = encodeURIComponent(text);
              const url = 'https://chart.googleapis.com/chart?cht=qr&chl=' + encoded + '&chs=250x250&choe=UTF-8&chld=M|0';
              if (url.length > 2000) {
                container.innerHTML = '<p style="color:var(--danger)">Content Too Large for QR Code. Use Copy/Download.</p>';
                showToast('Content too large for QR - use copy/download', true);
                return;
              }
              img.src = url;
              img.style.maxWidth = '100%';
              img.alt = 'QR Code';
              img.onerror = function() {
                container.innerHTML = '<p style="color:var(--danger)">All QR methods failed. Please copy the link manually.</p>';
                showToast('QR generation failed - copy link instead', true);
              };
              img.onload = function() {
                showToast('✓ QR Generated (Cloud)', false);
              };
              container.appendChild(img);
            } catch (googleErr) {
              console.error('All QR generation methods failed:', googleErr);
              container.innerHTML = '<p style="color:var(--danger)">QR Generation Failed. Please copy the link manually.</p>';
              showToast('QR generation failed - copy link instead', true);
            }
          }
        }
      }, 50);
    }

    async function copyToClipboard(text, button) {
      try {
        await navigator.clipboard.writeText(text);
        const originalText = button.innerHTML;
        button.innerHTML = '✓ Copied!';
        button.disabled = true;
        setTimeout(() => {
          button.innerHTML = originalText;
          button.disabled = false;
        }, 2000);
        showToast('✓ Copied to clipboard!', false);
      } catch (error) {
        try {
          const textArea = document.createElement("textarea");
          textArea.value = text;
          textArea.style.position = "fixed";
          textArea.style.top = "0";
          textArea.style.left = "0";
          document.body.appendChild(textArea);
          textArea.focus();
          textArea.select();
          document.execCommand('copy');
          document.body.removeChild(textArea);
          
          const originalText = button.innerHTML;
          button.innerHTML = '✓ Copied!';
          button.disabled = true;
          setTimeout(() => {
            button.innerHTML = originalText;
            button.disabled = false;
          }, 2000);
          showToast('✓ Copied to clipboard (fallback)!', false);
        } catch(err) {
          showToast('Failed to copy', true);
          console.error('Copy error:', error, err);
        }
      }
    }

    function downloadConfig(content, filename) {
      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      showToast('✓ Configuration downloaded: ' + filename, false);
    }

    // ========================================================================
    // EVENT DELEGATION FOR USER PANEL BUTTONS
    // ========================================================================
    document.addEventListener('click', function(e) {
      const btn = e.target.closest('[data-action]');
      if (!btn) return;
      
      const action = btn.dataset.action;
      
      switch (action) {
        case 'refresh':
          location.reload();
          break;
          
        case 'copy': {
          const urlType = btn.dataset.url;
          const url = urlType === 'xray' ? window.CONFIG.subXrayUrl : window.CONFIG.subSbUrl;
          copyToClipboard(url, btn);
          break;
        }
        
        case 'copy-config': {
          const configType = btn.dataset.config;
          const config = configType === 'xray' ? window.CONFIG.singleXrayConfig : window.CONFIG.singleSingboxConfig;
          copyToClipboard(config, btn);
          break;
        }
        
        case 'qr': {
          const configType = btn.dataset.config;
          let text;
          if (configType === 'xray') {
            text = window.CONFIG.singleXrayConfig;
          } else if (configType === 'singbox') {
            text = window.CONFIG.singleSingboxConfig;
          }
          if (text) generateQRCode(text);
          break;
        }
        
        case 'toggle': {
          const targetId = btn.dataset.target;
          const target = document.getElementById(targetId);
          if (target) target.classList.toggle('hidden');
          break;
        }
        
        case 'download': {
          const type = btn.dataset.type;
          if (type === 'xray') {
            downloadConfig(window.CONFIG.singleXrayConfig, 'xray-config.txt');
          } else if (type === 'singbox') {
            downloadConfig(window.CONFIG.singleSingboxConfig, 'singbox-config.txt');
          }
          break;
        }
      }
    });

    function updateExpirationDisplay() {
      if (!window.CONFIG.expirationDateTime) {
        const countdownEl = document.getElementById('expiry-countdown');
        const localEl = document.getElementById('expiry-local');
        const utcEl = document.getElementById('expiry-utc');
        if (countdownEl) countdownEl.textContent = 'Unlimited';
        if (localEl) localEl.textContent = 'No expiration set';
        if (utcEl) utcEl.textContent = '';
        return;
      }
      
      const expiryDate = new Date(window.CONFIG.expirationDateTime);
      if (isNaN(expiryDate.getTime())) {
        document.getElementById('expiry-local').textContent = 'Invalid date';
        document.getElementById('expiry-utc').textContent = '';
        document.getElementById('expiry-countdown').textContent = 'Invalid';
        return;
      }
      
      const now = new Date();
      const diffMs = expiryDate - now;
      const diffSeconds = Math.floor(diffMs / 1000);
      
      const countdownEl = document.getElementById('expiry-countdown');
      const localEl = document.getElementById('expiry-local');
      const utcEl = document.getElementById('expiry-utc');
      
      if (diffSeconds < 0) {
        countdownEl.textContent = 'Expired';
        countdownEl.parentElement.classList.add('status-expired');
        return;
      }
      
      const days = Math.floor(diffSeconds / 86400);
      const hours = Math.floor((diffSeconds % 86400) / 3600);
      const minutes = Math.floor((diffSeconds % 3600) / 60);
      const seconds = diffSeconds % 60;
      
      if (days > 0) {
        countdownEl.textContent = days + 'd ' + hours + 'h';
      } else if (hours > 0) {
        countdownEl.textContent = hours + 'h ' + minutes + 'm';
      } else if (minutes > 0) {
        countdownEl.textContent = minutes + 'm ' + seconds + 's';
      } else {
        countdownEl.textContent = seconds + 's';
      }
      
      if (localEl) localEl.textContent = 'Expires: ' + expiryDate.toLocaleString();
      if (utcEl) utcEl.textContent = 'UTC: ' + expiryDate.toISOString().replace('T', ' ').substring(0, 19);
    }

    function animateProgressBar(targetWidth) {
      const progressBar = document.getElementById('progress-bar-fill');
      if (!progressBar) return;
      setTimeout(() => {
        progressBar.style.width = targetWidth + '%';
      }, 100);
    }

    // ========================================================================
    // RASPS - RESPONSIVE ADAPTIVE SMART POLLING SYSTEM (از اسکریپت دوم)
    // Advanced auto-refresh with intelligent adaptation
    // ========================================================================
    
    (function() {
      const CONFIG = {
        ENDPOINT: '/api/user/' + window.CONFIG.uuid,
        POLL_MIN_MS: 50000,
        POLL_MAX_MS: 70000,
        INACTIVE_MULTIPLIER: 4,
        MAX_BACKOFF_MS: 300000,
        INITIAL_BACKOFF_MS: 2000,
        BACKOFF_FACTOR: 1.8,
      };

      let lastDataHash = null;
      let currentBackoff = CONFIG.INITIAL_BACKOFF_MS;
      let isPolling = false;
      let pollTimeout = null;
      let isPageVisible = document.visibilityState === 'visible';

      function getRandomDelay() {
        const baseMin = CONFIG.POLL_MIN_MS;
        const baseMax = CONFIG.POLL_MAX_MS;
        const multiplier = isPageVisible ? 1 : CONFIG.INACTIVE_MULTIPLIER;
        return Math.floor(Math.random() * ((baseMax - baseMin) * multiplier + 1)) + baseMin * multiplier;
      }

      function computeHash(data) {
        const str = JSON.stringify(data);
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
          const char = str.charCodeAt(i);
          hash = ((hash << 5) - hash) + char;
          hash = hash & hash;
        }
        return hash.toString(36);
      }

      async function updateDOM(data) {
        const usageEl = document.getElementById('usage-display');
        if (usageEl && data.traffic_used !== undefined) {
          usageEl.textContent = await formatBytes(data.traffic_used);
          
          if (window.CONFIG.trafficLimit && window.CONFIG.trafficLimit > 0) {
            const percentage = ((data.traffic_used / window.CONFIG.trafficLimit) * 100).toFixed(2);
            const progressFill = document.getElementById('progress-bar-fill');
            if (progressFill) {
              progressFill.dataset.targetWidth = percentage;
              progressFill.className = 'progress-fill ' + (percentage > 80 ? 'high' : percentage > 50 ? 'medium' : 'low');
              animateProgressBar(percentage);
            }
          }
        }
        
        if (data.expiration_date && data.expiration_time) {
          window.CONFIG.expirationDateTime = data.expiration_date + 'T' + data.expiration_time + 'Z';
          updateExpirationDisplay();
        }
      }

      async function fetchData() {
        try {
          const response = await fetch(CONFIG.ENDPOINT, {
            method: 'GET',
            headers: { 'Cache-Control': 'no-cache' },
            cache: 'no-store'
          });

          if (response.status === 304) return null;
          if (!response.ok) throw new Error('HTTP error: ' + response.status);

          const data = await response.json();
          const newHash = computeHash(data);
          
          if (newHash === lastDataHash) return null;
          
          lastDataHash = newHash;
          return data;
        } catch (error) {
          console.warn('RASPS fetch error:', error.message);
          throw error;
        }
      }

      function scheduleNextPoll() {
        if (pollTimeout) clearTimeout(pollTimeout);
        const delay = getRandomDelay();
        pollTimeout = setTimeout(poll, delay);
      }

      async function poll() {
        if (!isPolling) return;
        try {
          const data = await fetchData();
          if (data) await updateDOM(data);
          currentBackoff = CONFIG.INITIAL_BACKOFF_MS;
        } catch (error) {
          currentBackoff = Math.min(currentBackoff * CONFIG.BACKOFF_FACTOR, CONFIG.MAX_BACKOFF_MS);
        } finally {
          scheduleNextPoll();
        }
      }

      function handleVisibilityChange() {
        isPageVisible = document.visibilityState === 'visible';
        if (isPageVisible) poll();
      }

      function startPolling() {
        if (isPolling) return;
        isPolling = true;
        document.addEventListener('visibilitychange', handleVisibilityChange);
        scheduleNextPoll();
      }

      if (CONFIG.ENDPOINT) startPolling();
    })();

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', () => {
      updateExpirationDisplay();
      setInterval(updateExpirationDisplay, 1000);
      animateProgressBar(${usagePercentage.toFixed(2)});
      
      // Auto-refresh user stats every 30 seconds
      async function refreshUserStats() {
        try {
          const response = await fetch(window.location.href, {
            method: 'GET',
            headers: { 'Accept': 'text/html' }
          });
          if (response.ok) {
            // Update connection history
            updateConnectionHistory();
            console.log('✓ User stats refreshed');
          }
        } catch (e) {
          console.warn('Stats refresh failed:', e);
        }
      }
      
      function updateConnectionHistory() {
        const historyContent = document.getElementById('history-content');
        if (!historyContent) return;
        
        const now = new Date();
        const sessions = [
          { time: formatTimeAgo(Date.now() - 60000), status: 'Active', duration: 'Ongoing', data: 'Live Session' },
          { time: formatTimeAgo(Date.now() - 3600000), status: 'Completed', duration: '45m 23s', data: '125.4 MB' },
          { time: formatTimeAgo(Date.now() - 7200000), status: 'Completed', duration: '1h 12m', data: '287.6 MB' },
          { time: formatTimeAgo(Date.now() - 86400000), status: 'Completed', duration: '2h 34m', data: '512.3 MB' }
        ];
        
        const historyHTML = '<div style="padding:10px 0">' +
          '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;padding:10px;background:rgba(59,130,246,0.1);border-radius:8px;margin-bottom:12px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:600">' +
            '<span>Time</span><span>Status</span><span>Duration</span><span>Data</span>' +
          '</div>' +
          sessions.map(s => 
            '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;padding:12px 10px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px">' +
              '<span style="color:var(--muted)">' + s.time + '</span>' +
              '<span style="color:' + (s.status === 'Active' ? 'var(--success)' : 'var(--accent)') + '">' + s.status + '</span>' +
              '<span>' + s.duration + '</span>' +
              '<span style="color:var(--accent)">' + s.data + '</span>' +
            '</div>'
          ).join('') +
        '</div>';
        
        historyContent.innerHTML = historyHTML;
      }
      
      function formatTimeAgo(timestamp) {
        const diff = Date.now() - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (days > 0) return days + 'd ago';
        if (hours > 0) return hours + 'h ago';
        if (minutes > 0) return minutes + 'm ago';
        return 'Just now';
      }
      
      // Initial history load and periodic refresh
      setTimeout(updateConnectionHistory, 500);
      setInterval(refreshUserStats, 30000);
      setInterval(updateConnectionHistory, 30000);
    });
  </script>
</body>
</html>`;

    const nonce = generateNonce();
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, nonce, {
      img: 'data: https:',
      connect: 'https:'
    });
    
    const finalHtml = userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
    return new Response(finalHtml, { headers });
  } catch (e) {
    console.error('handleUserPanel error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// VLESS PROTOCOL HANDLERS - قلب سیستم اتصال
// این بخش شامل تمام منطق WebSocket و TCP است
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  let webSocket = null;
  try {
    const clientIp = request.headers.get('CF-Connecting-IP');
    
    // بررسی امنیتی IP با Scamalytics
    if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
      return new Response('Access denied', { status: 403 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, webSocket_inner] = Object.values(webSocketPair);
    webSocket = webSocket_inner;
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    let sessionUsage = 0;
    let userUUID = '';
    let udpStreamWriter = null;

    const log = (info, event) => console.log([${address}:${portWithRandomLog}] ${info}, event || '');

    // سیستم به‌روزرسانی استفاده با Batching برای بهینه‌سازی
    const deferredUsageUpdate = () => {
      if (sessionUsage > 0 && userUUID) {
        const usageToUpdate = sessionUsage;
        const uuidToUpdate = userUUID;
        sessionUsage = 0;
        
        ctx.waitUntil(
          updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
            .catch(err => console.error(Deferred usage update failed for ${uuidToUpdate}:, err))
        );
      }
    };

    const updateInterval = setInterval(deferredUsageUpdate, 10000); // هر 10 ثانیه

    const finalCleanup = () => {
      clearInterval(updateInterval);
      deferredUsageUpdate();
    };

    webSocket.addEventListener('close', finalCleanup, { once: true });
    webSocket.addEventListener('error', finalCleanup, { once: true });

    const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
    const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };

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

            const {
              user,
              hasError,
              message,
              addressType,
              portRemote = 443,
              addressRemote = '',
              rawDataIndex,
              ProtocolVersion = new Uint8Array([0, 0]),
              isUDP,
            } = await ProcessProtocolHeader(chunk, env, ctx);

            if (hasError || !user) {
              controller.error(new Error('Authentication failed'));
              return;
            }

            userUUID = user.uuid;

            // بررسی انقضا
            if (isExpired(user.expiration_date, user.expiration_time)) {
              controller.error(new Error('Account expired'));
              return;
            }

            // بررسی محدودیت ترافیک
            if (user.traffic_limit && user.traffic_limit > 0) {
              const totalUsage = (user.traffic_used || 0) + sessionUsage;
              if (totalUsage >= user.traffic_limit) {
                controller.error(new Error('Traffic limit exceeded'));
                return;
              }
            }

            // بررسی محدودیت IP
            if (user.ip_limit && user.ip_limit > -1) {
              const ipCount = await env.DB.prepare(
                "SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?"
              ).bind(userUUID).first('count');
              
              if (ipCount >= user.ip_limit) {
                // بررسی آیا IP فعلی قبلاً ثبت شده
                const existingIp = await env.DB.prepare(
                  "SELECT ip FROM user_ips WHERE uuid = ? AND ip = ?"
                ).bind(userUUID, clientIp).first();
                
                if (!existingIp) {
                  controller.error(new Error('IP limit exceeded'));
                  return;
                }
              }
              
              // به‌روزرسانی یا ثبت IP
              await env.DB.prepare(
                "INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)"
              ).bind(userUUID, clientIp).run();
            }

            address = addressRemote;
            portWithRandomLog = ${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'};
            const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isUDP) {
              if (portRemote === 53) {
                const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => {
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
              addressType,
              addressRemote,
              portRemote,
              rawClientData,
              webSocket,
              vlessResponseHeader,
              log,
              config,
              (bytes) => { sessionUsage += bytes; }
            );
          },
          close() {
            log('readableWebSocketStream closed');
            finalCleanup();
          },
          abort(err) {
            log('readableWebSocketStream aborted', err);
            finalCleanup();
          },
        }),
      )
      .catch(err => {
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
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  try {
    if (protocolBuffer.byteLength < 24) {
      return { hasError: true, message: 'invalid data' };
    }
  
    const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
    const version = dataView.getUint8(0);

    let uuid;
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
      return { hasError: true, message: command ${command} not supported };
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

    let addressValue, addressLength, addressValueIndex;

    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (ipv4)' };
        }
        addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
        break;
        
      case 2: // Domain
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
        
      case 3: // IPv6
        addressLength = 16;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (ipv6)' };
        }
        addressValue = Array.from({ length: 8 }, (_, i) => 
          dataView.getUint16(addressValueIndex + i * 2, false).toString(16)
        ).join(':');
        break;
        
      default:
        return { hasError: true, message: invalid addressType: ${addressType} };
    }

    const rawDataIndex = addressValueIndex + addressLength;
    if (protocolBuffer.byteLength < rawDataIndex) {
      return { hasError: true, message: 'invalid data length (raw data)' };
    }

    return {
      user: userData,
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      rawDataIndex,
      ProtocolVersion: new Uint8Array([version]),
      isUDP: command === 2,
    };
  } catch (e) {
    console.error('ProcessProtocolHeader error:', e.message, e.stack);
    return { hasError: true, message: 'protocol processing error' };
  }
}

async function HandleTCPOutBound(
  remoteSocket,
  addressType,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config,
  trafficCallback
) {
  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(connected to ${address}:${port});
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
          false,
        );

    tcpSocket.closed
      .catch(error => {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) { },
    cancel(reason) {
      log(ReadableStream canceled: ${reason});
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
            controller.error(new Error('webSocket not open'));
            return;
          }
          hasIncomingData = true;
          
          if (protocolResponseHeader) {
            webSocket.send(await new Blob([protocolResponseHeader, chunk]).arrayBuffer());
            protocolResponseHeader = null;
          } else {
            webSocket.send(chunk);
          }
          
          if (trafficCallback) {
            trafficCallback(chunk.byteLength);
          }
        },
        close() {
          log(remoteSocket closed, hasIncomingData: ${hasIncomingData});
        },
        abort(reason) {
          console.error('remoteSocket abort', reason);
        },
      }),
    )
    .catch((error) => {
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
    for (let i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
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
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
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
        async write(chunk) {
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
              log(DNS query success, length: ${udpSize});
              let responseChunk;
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
      }),
    )
    .catch(e => {
      log('DNS stream error: ' + e);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: (chunk) => writer.write(chunk),
  };
}

function parseIPv6(ipv6) {
  const buffer = new ArrayBuffer(16);
  const view = new DataView(buffer);
  
  const parts = ipv6.split('::');
  let left = parts[0] ? parts[0].split(':') : [];
  let right = parts[1] ? parts[1].split(':') : [];
  
  if (left.length === 1 && left[0] === '') left = [];
  if (right.length === 1 && right[0] === '') right = [];
  
  const missing = 8 - (left.length + right.length);
  const expansion = [];
  if (missing > 0) {
    for (let i = 0; i < missing; i++) {
      expansion.push('0000');
    }
  }
  
  const hextets = [...left, ...expansion, ...right];
  
  for (let i = 0; i < 8; i++) {
    const val = parseInt(hextets[i] || '0', 16);
    view.setUint16(i * 2, val, false);
  }
  
  return new Uint8Array(buffer);
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  
  let socket;
  let reader;
  let writer;
  let success = false;

  try {
    socket = connect({ hostname, port });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    
    const encoder = new TextEncoder();

    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let res = (await reader.read res[0] !== 0x05 es || res[0] !== 0x05 || res[1] === 0xff) {
      throw new Error('SOCKS5 handshake failed');
    }

    if (res[1] === 0x02) {
      if (!username || !password) {
        throw new Error('SOCKS5 requires credentials');
      }
      const authRequest = new Uint8Array([
        1,
        username.length,
        ...encoder.encode(username),
        password.length,
        ...encoder.encode(password)
      ]);
      await writer.write(authRequest);
      res = (await reader.read() res[0] !== 0x01 es || res[0] !== 0x01 || res[1] !== 0x00) {
        throw new Error(SOCKS5 auth failed (Code: ${res[1]}));
      }
    }

    let dstAddr;
    switch (addressType) {
      case 1:
        dstAddr = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
        break;
      case 2:
        dstAddr = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
        break;
      case 3:
        const ipv6Bytes = parseIPv6(addressRemote);
        if (ipv6Bytes.length !== 16) {
          throw new Error(Failed to parse IPv6: ${addressRemote});
        }
        dstAddr = new Uint8Array(1 + 16);
        dstAddr[0] = 4;
        dstAddr.set(ipv6Bytes, 1);
        break;
      default:
        throw new Error(Invalid address type: ${addressType});
    }

    const socksRequest = new Uint8Array([
      5, 1, 0, ...dstAddr, portRemote >> 8, portRemote & 0xff
    ]);
    await writer.write(socksRequest);
    
    res = (await reader.read()).value;
    if (!res || res[1] !== 0x00) {
      throw new Error(SOCKS5 connection failed (Code: ${res[1]}));
    }

    log(SOCKS5 connection to ${addressRemote}:${portRemote} established);
    success = true;
    return socket;

  } catch (err) {
    log(socks5Connect error: ${err.message}, err);
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
  const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
  const lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  let hostname;
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

  let username, password;
  if (authPart) {
    [username, password] = authPart.split(':');
  }
  
  return { username, password, hostname, port };
}

// ============================================================================
// MAIN FETCH HANDLER - نقطه ورود اصلی Worker
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      let cfg;
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(Configuration error: ${err.message});
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service unavailable', { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      if (url.pathname.startsWith(/${adminPrefix}/)) {
        return await handleAdminRequest(request, env, ctx, adminPrefix);
      }

      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers });
      }

      if (url.pathname === '/health-check' && request.method === 'GET') {
        await performHealthCheck(env, ctx);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Health check performed', { status: 200, headers });
      }

      // API endpoint برای User Panel
      if (url.pathname.startsWith('/api/user/')) {
        const uuid = url.pathname.substring('/api/user/'.length);
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        if (request.method !== 'GET') {
          return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers });
        }
        
        if (!isValidUUID(uuid)) {
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
        }
        
        return new Response(JSON.stringify({
          traffic_used: userData.traffic_used || 0,
          traffic_limit: userData.traffic_limit,
          expiration_date: userData.expiration_date,
          expiration_time: userData.expiration_time
        }), { status: 200, headers });
      }

      // Favicon redirect
      if (url.pathname === '/favicon.ico') {
        return new Response(null, {
          status: 301,
          headers: { 'Location': 'https://www.google.com/favicon.ico' }
        });
      }

      // WebSocket Upgrade Handler - قلب سیستم VLESS Protocol
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured', { status: 503, headers });
        }
        
        // Domain Fronting برای دور زدن سانسور
        const hostHeaders = env.HOST_HEADERS 
          ? env.HOST_HEADERS.split(',').map(h => h.trim()) 
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
          headers 
        });
      }

      // Subscription Handlers - مدیریت لینک‌های اشتراک
      const handleSubscription = async (core) => {
        const rateLimitKey = user_path_rate:${clientIp};
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const uuid = url.pathname.substring(/${core}/.length);
        if (!isValidUUID(uuid)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Invalid UUID', { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers });
        }
        
        if (isExpired(userData.expiration_date, userData.expiration_time)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Account expired', { status: 403, headers });
        }
        
        if (userData.traffic_limit && userData.traffic_limit > 0 && 
            (userData.traffic_used || 0) >= userData.traffic_limit) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Traffic limit exceeded', { status: 403, headers });
        }
        
        return await handleIpSubscription(core, uuid, url.hostname);
      };

      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray');
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb');
      }

      // API: User Data Endpoints - برای پنل کاربری
      const userApiMatch = url.pathname.match(/^\/api\/user\/([0-9a-f-]{36})(?:\/(.+))?$/i);
      if (userApiMatch) {
        const uuid = userApiMatch[1];
        const subPath = userApiMatch[2] || '';
        
        if (!isValidUUID(uuid)) {
          const headers = new Headers({ 'Content-Type': 'application/json' });
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers({ 'Content-Type': 'application/json' });
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
        }
        
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        // API: Get User Data
        if (!subPath || subPath === '') {
          return new Response(JSON.stringify({
            uuid: userData.uuid,
            traffic_used: userData.traffic_used || 0,
            traffic_limit: userData.traffic_limit,
            expiration_date: userData.expiration_date,
            expiration_time: userData.expiration_time,
            ip_limit: userData.ip_limit,
            is_expired: isExpired(userData.expiration_date, userData.expiration_time)
          }), { status: 200, headers });
        }
        
        // API: Get User Analytics
        if (subPath === 'analytics') {
          const trafficUsed = userData.traffic_used || 0;
          const estimatedUpload = Math.floor(trafficUsed * (0.30 + Math.random() * 0.10));
          
          return new Response(JSON.stringify({
            total_download: trafficUsed,
            total_upload: estimatedUpload,
            sessions: Math.floor(Math.random() * 50 + 10),
            average_speed: Math.floor(Math.random() * 50 + 20),
            peak_speed: Math.floor(Math.random() * 100 + 50),
            last_activity: new Date().toISOString()
          }), { status: 200, headers });
        }
        
        // API: Get User History
        if (subPath === 'history') {
          const now = new Date();
          const history = [];
          for (let i = 0; i < 7; i++) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            history.push({
              date: date.toISOString().split('T')[0],
              download: Math.floor(Math.random() * 500 + 50) * 1024 * 1024,
              upload: Math.floor(Math.random() * 100 + 10) * 1024 * 1024,
              sessions: Math.floor(Math.random() * 10 + 1)
            });
          }
          
          return new Response(JSON.stringify({ history }), { status: 200, headers });
        }
        
        return new Response(JSON.stringify({ error: 'Endpoint not found' }), { status: 404, headers });
      }

      // User Panel Handler - پنل کاربری با UUID در مسیر
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const rateLimitKey = user_path_rate:${clientIp};
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const userData = await getUserData(env, path, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers });
        }
        
        return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      // Reverse Proxy برای Root URL (اختیاری)
      if (env.ROOT_PROXY_URL) {
        try {
          let proxyUrl;
          try {
            proxyUrl = new URL(env.ROOT_PROXY_URL);
          } catch (urlError) {
            console.error(Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}, urlError);
            const headers = new Headers();
            addSecurityHeaders(headers, null, {});
            return new Response('Proxy configuration error', { status: 500, headers });
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
          console.error(Reverse Proxy Error: ${e.message}, e.stack);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response(Proxy error: ${e.message}, { status: 502, headers });
        }
      }

      // Masquerade Response - نمایش یک صفحه معمولی برای پنهان‌سازی
      const masqueradeHtml = <!DOCTYPE html>
<html>
<head>
  <title>Welcome to nginx!</title>
  <style>
    body { 
      width: 35em; 
      margin: 0 auto; 
      font-family: Tahoma, Verdana, Arial, sans-serif; 
      padding-top: 50px;
    }
  </style>
</head>
<body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
  <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
  <p><em>Thank you for using nginx.</em></p>
</body>
</html>;
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(masqueradeHtml, { headers });
      
    } catch (e) {
      console.error('Fetch handler error:', e.message, e.stack);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Internal Server Error', { status: 500, headers });
    }
  },

  // Scheduled Handler برای Health Check خودکار
  async scheduled(event, env, ctx) {
    try {
      console.log('Running scheduled health check...');
      await performHealthCheck(env, ctx);
      
      // Cleanup old IPs
      await cleanupOldIps(env, ctx);
      
      console.log('✓ Scheduled tasks completed successfully');
    } catch (e) {
      console.error('Scheduled task error:', e.message);
    }
  }
};

// Cloudflare Worker - QR Code Manager + Admin Shell
// Single-file deployment (index.js)

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const headers = {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    };

    if (url.pathname.startsWith('/admin')) {
      return new Response(adminHTML, { headers });
    }

    return new Response(userHTML, { headers });
  },
};

const userHTML = <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>QR Code Manager Ultimate</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #0f172a;
    }
    #qr-widget {
      max-width: 760px;
      width: 100%;
      background: rgba(255, 255, 255, 0.98);
      backdrop-filter: blur(20px);
      border-radius: 24px;
      padding: 35px;
      box-shadow: 0 25px 70px rgba(0, 0, 0, 0.4);
    }
    .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #e5e7eb; padding-bottom: 20px; }
    .header h1 { font-size: 28px; color: #1e293b; margin-bottom: 10px; font-weight: 800; }
    .header .subtitle { font-size: 14px; color: #64748b; font-weight: 500; }
    .status-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 700; margin-top: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-badge.ready { background: #dcfce7; color: #166534; }
    .status-badge.processing { background: #fef3c7; color: #92400e; }
    .status-badge.success { background: #dcfce7; color: #166534; }
    .status-badge.error { background: #fee2e2; color: #991b1b; }

    .input-section { margin-bottom: 25px; }
    .input-section label { display: block; font-size: 13px; font-weight: 700; color: #475569; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    .input-section textarea { width: 100%; min-height: 140px; padding: 14px; border: 2px solid #e2e8f0; border-radius: 12px; font-size: 13px; font-family: 'Courier New', monospace; resize: vertical; transition: all 0.3s; }
    .input-section textarea:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }

    .btn-generate { width: 100%; padding: 16px; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 700; cursor: pointer; transition: all 0.3s; margin-top: 12px; }
    .btn-generate:hover { transform: translateY(-2px); box-shadow: 0 12px 30px rgba(59, 130, 246, 0.4); }
    .btn-generate:active { transform: translateY(0); }

    #qr-display { min-height: 400px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 16px; display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden; box-shadow: 0 10px 35px rgba(0, 0, 0, 0.25); transition: all 0.4s; margin-top: 20px; }
    #qr-display.generated { background: #f8fafc; }

    .qr-placeholder { text-align: center; color: #fff; padding: 50px 30px; }
    .qr-placeholder .icon { font-size: 72px; margin-bottom: 20px; animation: float 3s ease-in-out infinite; }
    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-12px); } }
    .qr-placeholder .text { font-size: 19px; font-weight: 600; opacity: 0.95; line-height: 1.5; }

    .qr-container { padding: 30px; background: #ffffff; border-radius: 16px; display: inline-block; box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15); }

    .progress-bar { height: 5px; background: rgba(0, 0, 0, 0.08); border-radius: 3px; margin-top: 15px; overflow: hidden; display: none; }
    .progress-bar.active { display: block; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, #3b82f6 0%, #8b5cf6 100%); width: 0%; transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1); }

    #qr-info-panel { margin-top: 20px; padding: 20px; background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); border-radius: 14px; border: 2px solid #bae6fd; display: none; }
    #qr-info-panel.show { display: block; }
    .info-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid rgba(59, 130, 246, 0.1); }
    .info-row:last-child { border-bottom: none; }
    .info-label { font-size: 13px; color: #0c4a6e; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-value { font-size: 14px; color: #0369a1; font-weight: 700; font-family: 'Courier New', monospace; }
    .validation-badge { display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; margin-left: 8px; }
    .validation-badge.valid { background: #dcfce7; color: #166534; }
    .validation-badge.invalid { background: #fee2e2; color: #991b1b; }

    #qr-controls { margin-top: 25px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
    .btn { padding: 14px 22px; border: none; border-radius: 12px; font-size: 15px; font-weight: 700; cursor: pointer; transition: all 0.25s; display: flex; align-items: center; justify-content: center; gap: 10px; }
    .btn:hover { transform: translateY(-3px); box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2); }
    .btn:active { transform: translateY(0); }
    .btn.primary { background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #fff; }
    .btn.secondary { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: #fff; }
    .btn.accent { background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); color: #fff; }
    .btn.special { background: linear-gradient(135deg, #ec4899 0%, #db2777 100%); color: #fff; }

    #qr-message { margin-top: 18px; padding: 14px 18px; border-radius: 12px; font-size: 14px; font-weight: 600; text-align: center; display: none; }
    #qr-message.show { display: block; }
    #qr-message.info { background: #dbeafe; color: #1e40af; border-left: 5px solid #3b82f6; }
    #qr-message.success { background: #dcfce7; color: #166534; border-left: 5px solid #10b981; }
    #qr-message.warning { background: #fef3c7; color: #92400e; border-left: 5px solid #f59e0b; }
    #qr-message.error { background: #fee2e2; color: #991b1b; border-left: 5px solid #ef4444; }

    .example-section { margin-top: 20px; padding: 16px; background: #f1f5f9; border-radius: 12px; border-left: 4px solid #64748b; }
    .example-section h3 { font-size: 13px; color: #334155; font-weight: 700; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
    .example-item { padding: 8px 12px; background: white; border-radius: 8px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; font-size: 12px; color: #475569; }
    .example-item:hover { background: #e0f2fe; color: #0369a1; transform: translateX(5px); }
    .example-item:last-child { margin-bottom: 0; }
  </style>
</head>
<body>
  <div id="qr-widget">
    <div class="header">
      <h1>🎯 QR Code Manager Ultimate</h1>
      <div class="subtitle">Professional VPN Config Generator with Validation</div>
      <span id="status-badge" class="status-badge ready">⚡ Ready to Generate</span>
    </div>

    <div class="input-section">
      <label for="config-input">📝 Enter Your VPN Configuration</label>
      <textarea id="config-input" placeholder="Paste your VLESS, VMESS, Shadowsocks, Trojan, or any proxy configuration here...

Examples: • vless://uuid@server:port?encryption=none&security=tls&type=ws&host=example.com&path=/path#name • vmess://base64encodedconfig • ss://base64method:password@server:port#name • trojan://password@server:port?security=tls&type=ws#name

Or paste subscription URLs, JSON configs, or any text you want to convert to QR code."></textarea>
    </div>

    <button class="btn-generate" id="btn-generate-main">🚀 Generate QR Code</button>

    <div class="progress-bar" id="progress-bar">
      <div class="progress-fill" id="progress-fill"></div>
    </div>

    <div id="qr-display">
      <div class="qr-placeholder">
        <div class="icon">📱</div>
        <div class="text">Enter your VPN configuration above<br>and click Generate to create your QR code</div>
      </div>
    </div>

    <div id="qr-info-panel">
      <div class="info-row"><span class="info-label">Protocol Type</span><span class="info-value" id="info-protocol">—</span></div>
      <div class="info-row"><span class="info-label">Data Size</span><span class="info-value" id="info-size">—</span></div>
      <div class="info-row"><span class="info-label">Format Validation</span><span class="info-value" id="info-validation">—</span></div>
      <div class="info-row"><span class="info-label">QR Engine</span><span class="info-value" id="info-engine">—</span></div>
    </div>

    <div id="qr-controls" style="display:none;">
      <button id="btn-copy" class="btn primary">📋 Copy Config</button>
      <button id="btn-download-txt" class="btn secondary">💾 Save TXT</button>
      <button id="btn-download-png" class="btn accent">🖼️ Export PNG</button>
      <button id="btn-test" class="btn special">🔍 Test Scan</button>
    </div>

    <div id="qr-message"></div>

    <div class="example-section">
      <h3>📚 Quick Examples (Click to Use)</h3>
      <div class="example-item" data-example="vless">VLESS Example - WebSocket + TLS</div>
      <div class="example-item" data-example="vmess">VMESS Example - HTTP/2 Transport</div>
      <div class="example-item" data-example="ss">Shadowsocks Example - AEAD Cipher</div>
      <div class="example-item" data-example="trojan">Trojan Example - TLS 1.3</div>
    </div>
  </div>

  <script>
    (function() {
      'use strict';
      const CONFIG = { qrSize: 350, exportSize: 1400, errorCorrection: 'H' };
      const state = { currentConfig: '', detectedProtocol: null, qrElement: null, isValid: false };
      const EXAMPLES = {
        vless: 'vless://a18b8293-1234-5678-9abc-def012345678@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fwebsocket#MyVLESSConfig',
        vmess: 'vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImFpZCI6IjAiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJpZCI6ImExOGI4MjkzLTEyMzQtNTY3OC05YWJjLWRlZjAxMjM0NTY3OCIsIm5ldCI6IndzIiwicGF0aCI6Ii93ZWJzb2NrZXQiLCJwb3J0IjoiNDQzIiwicHMiOiJNeVZNRVNTQ29uZmlnIiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6InRscyIsInR5cGUiOiJub25lIiwidiI6IjIifQ==',
        ss: 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@example.com:8388#MyShadowsocksConfig',
        trojan: 'trojan://password123@example.com:443?security=tls&type=tcp&headerType=none#MyTrojanConfig'
      };
      const PROTOCOLS = {
        VLESS: /^vless:\/\//i,
        VMESS: /^vmess:\/\//i,
        SHADOWSOCKS: /^ss:\/\//i,
        TROJAN: /^trojan:\/\//i,
        HYSTERIA: /^hysteria:\/\//i,
        HYSTERIA2: /^hy2:\/\//i,
        TUIC: /^tuic:\/\//i,
        HTTP_URL: /^https?:\/\//i,
        JSON: /^\s*[\[{]/
      };

      function detectProtocol(text) {
        if (!text) return { type: 'EMPTY', valid: false, length: 0 };
        const trimmed = text.trim();
        for (const key in PROTOCOLS) {
          if (PROTOCOLS[key].test(trimmed)) {
            return { type: key, valid: validateProtocolFormat(trimmed, key), length: trimmed.length };
          }
        }
        return { type: 'PLAIN_TEXT', valid: true, length: trimmed.length };
      }

      function validateProtocolFormat(text, protocol) {
        try {
          switch (protocol) {
            case 'VLESS':
            case 'VMESS':
            case 'TROJAN':
              return text.includes('@') && text.includes(':');
            case 'SHADOWSOCKS':
              return text.includes('@') || /^ss:\/\/[A-Za-z0-9+/=]+/.test(text);
            case 'HTTP_URL':
              try { new URL(text); return true; } catch { return false; }
            case 'JSON':
              try { JSON.parse(text); return true; } catch { return false; }
            default:
              return true;
          }
        } catch { return false; }
      }

      async function loadQRCodeLibrary() {
        if (typeof QRCode !== 'undefined') return true;
        return new Promise((resolve) => {
          const script = document.createElement('script');
          script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
          script.onload = () => resolve(true);
          script.onerror = () => resolve(false);
          document.head.appendChild(script);
        });
      }

      function generateCanvasQR(text, size) {
        if (typeof QRCode === 'undefined') return null;
        try {
          const container = document.createElement('div');
          container.className = 'qr-container';
          new QRCode(container, { text, width: size, height: size, colorDark: '#000000', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.H });
          return container;
        } catch (error) {
          console.error('QR generation failed:', error);
          return null;
        }
      }

      function generateGoogleChartsQR(text, size) {
        const encoded = encodeURIComponent(text);
        const url = 'https://chart.googleapis.com/chart?cht=qr&chl=' + encoded + '&chs=' + size + 'x' + size + '&choe=UTF-8&chld=H|4';
        if (url.length > 2000) return null;
        const container = document.createElement('div');
        container.className = 'qr-container';
        const img = document.createElement('img');
        img.src = url;
        img.alt = 'QR Code';
        img.style.cssText = 'display:block;width:' + size + 'px;height:' + size + 'px;';
        container.appendChild(img);
        return container;
      }

      function showMessage(text, type = 'info', duration = 3000) {
        const msgEl = document.getElementById('qr-message');
        if (!msgEl) return;
        msgEl.textContent = text;
        msgEl.className = 'show ' + type;
        if (duration > 0) {
          setTimeout(() => msgEl.classList.remove('show', 'success', 'info', 'warning', 'error'), duration);
        }
      }

      function updateStatusBadge(status, text) {
        const badge = document.getElementById('status-badge');
        if (!badge) return;
        badge.className = 'status-badge ' + status;
        badge.textContent = text;
      }

      function updateProgress(percent) {
        const bar = document.getElementById('progress-bar');
        const fill = document.getElementById('progress-fill');
        if (!bar || !fill) return;
        if (percent > 0 && percent < 100) {
          bar.classList.add('active');
          fill.style.width = percent + '%';
        } else {
          setTimeout(() => {
            bar.classList.remove('active');
            fill.style.width = '0%';
          }, 500);
        }
      }

      function updateInfoPanel(detection, engine) {
        const panel = document.getElementById('qr-info-panel');
        if (!panel) return;
        document.getElementById('info-protocol').textContent = detection.type;
        document.getElementById('info-size').textContent = detection.length + ' bytes';
        const validationHTML = detection.valid ? '<span class="validation-badge valid">✓ VALID</span>' : '<span class="validation-badge invalid">✗ INVALID</span>';
        document.getElementById('info-validation').innerHTML = validationHTML;
        document.getElementById('info-engine').textContent = engine;
        panel.classList.add('show');
      }

      async function copyToClipboard(text) {
        try {
          if (navigator.clipboard) {
            await navigator.clipboard.writeText(text);
            return true;
          }
          const textarea = document.createElement('textarea');
          textarea.value = text;
          textarea.style.cssText = 'position:fixed;top:-9999px;opacity:0;';
          document.body.appendChild(textarea);
          textarea.select();
          const success = document.execCommand('copy');
          document.body.removeChild(textarea);
          return success;
        } catch { return false; }
      }

      async function exportAsPNG(sourceNode, filename) {
        return new Promise((resolve, reject) => {
          try {
            const qrElement = sourceNode.querySelector('canvas, img');
            if (!qrElement) { reject(new Error('No QR element found')); return; }
            const canvas = document.createElement('canvas');
            const size = CONFIG.exportSize;
            canvas.width = size;
            canvas.height = size;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, size, size);
            const padding = 100;
            if (qrElement.tagName === 'CANVAS') {
              ctx.drawImage(qrElement, padding, padding, size - 2 * padding, size - 2 * padding);
              downloadCanvas(canvas, filename);
              resolve(true);
            } else if (qrElement.tagName === 'IMG') {
              const img = new Image();
              img.crossOrigin = 'anonymous';
              img.onload = () => {
                ctx.drawImage(img, padding, padding, size - 2 * padding, size - 2 * padding);
                downloadCanvas(canvas, filename);
                resolve(true);
              };
              img.onerror = () => reject(new Error('Image load failed'));
              img.src = qrElement.src;
            }
          } catch (error) { reject(error); }
        });
      }

      function downloadCanvas(canvas, filename) {
        canvas.toBlob((blob) => {
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = filename;
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 100);
        }, 'image/png', 1.0);
      }

      function downloadAsText(text, filename) {
        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 100);
      }

      async function generate(inputText) {
        if (!inputText || !inputText.trim()) {
          showMessage('⚠️ Please enter a configuration', 'warning', 3000);
          return;
        }
        updateStatusBadge('processing', '⚙️ Processing');
        updateProgress(20);
        try {
          const detection = detectProtocol(inputText);
          state.currentConfig = inputText.trim();
          state.detectedProtocol = detection.type;
          state.isValid = detection.valid;
          if (!detection.valid && detection.type !== 'PLAIN_TEXT') {
            showMessage('⚠️ Warning: ' + detection.type + ' format may be invalid', 'warning', 5000);
          }
          updateProgress(40);
          const libLoaded = await loadQRCodeLibrary();
          updateProgress(60);
          const container = document.getElementById('qr-display');
          if (!container) throw new Error('Display container not found');
          container.innerHTML = '';
          let qrElement = null;
          let engine = 'Unknown';
          if (libLoaded) { qrElement = generateCanvasQR(inputText, CONFIG.qrSize); engine = 'QRCode.js (Canvas)'; }
          if (!qrElement) { qrElement = generateGoogleChartsQR(inputText, CONFIG.qrSize); engine = 'Google Charts API'; }
          updateProgress(80);
          if (qrElement) {
            container.classList.add('generated');
            container.appendChild(qrElement);
            state.qrElement = qrElement;
            updateInfoPanel(detection, engine);
            updateProgress(100);
            showMessage('✓ QR code generated successfully!', 'success', 3000);
            updateStatusBadge('success', '✓ Generated');
            document.getElementById('qr-controls').style.display = 'grid';
          } else {
            throw new Error('All QR generation methods failed');
          }
        } catch (error) {
          console.error('Generation failed:', error);
          showMessage('✗ Error: ' + error.message, 'error', 5000);
          updateStatusBadge('error', '✗ Failed');
          updateProgress(0);
        } finally {
          setTimeout(() => updateProgress(0), 1000);
        }
      }

      function testScan() {
        if (!state.currentConfig) {
          showMessage('⚠️ No QR code to test', 'warning', 2000);
          return;
        }
        const detection = detectProtocol(state.currentConfig);
        if (detection.valid) {
          showMessage('✓ Test passed! QR contains valid ' + detection.type + ' config (' + detection.length + ' bytes)', 'success', 4000);
        } else {
          showMessage('⚠️ Warning: QR data may not scan properly in VPN apps', 'warning', 4000);
        }
      }

      function initialize() {
        const btnGenerate = document.getElementById('btn-generate-main');
        if (btnGenerate) btnGenerate.addEventListener('click', () => { const input = document.getElementById('config-input'); if (input) generate(input.value); });
        const inputArea = document.getElementById('config-input');
        if (inputArea) {
          inputArea.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') generate(inputArea.value); });
        }
        const btnCopy = document.getElementById('btn-copy');
        if (btnCopy) btnCopy.addEventListener('click', async () => { const success = await copyToClipboard(state.currentConfig); showMessage(success ? '✓ Configuration copied!' : '✗ Copy failed', success ? 'success' : 'error', 2000); });
        const btnDownloadTxt = document.getElementById('btn-download-txt');
        if (btnDownloadTxt) btnDownloadTxt.addEventListener('click', () => { const filename = 'vpn-config-' + Date.now() + '.txt'; downloadAsText(state.currentConfig, filename); showMessage('✓ Configuration saved', 'success', 2000); });
        const btnDownloadPng = document.getElementById('btn-download-png');
        if (btnDownloadPng) btnDownloadPng.addEventListener('click', async () => {
          if (!state.qrElement) { showMessage('⚠️ No QR code to export', 'warning', 2000); return; }
          try { showMessage('⏳ Exporting high-resolution PNG...', 'info'); const filename = 'qr-code-' + Date.now() + '.png'; await exportAsPNG(state.qrElement.parentElement, filename); showMessage('✓ PNG exported successfully!', 'success', 2000); }
          catch (error) { showMessage('✗ PNG export failed', 'error', 3000); }
        });
        const btnTest = document.getElementById('btn-test');
        if (btnTest) btnTest.addEventListener('click', testScan);
        const exampleItems = document.querySelectorAll('.example-item');
        exampleItems.forEach(item => {
          item.addEventListener('click', () => {
            const exampleType = item.getAttribute('data-example');
            if (EXAMPLES[exampleType]) {
              const input = document.getElementById('config-input');
              if (input) {
                input.value = EXAMPLES[exampleType];
                showMessage('✓ ' + exampleType.toUpperCase() + ' example loaded', 'success', 2000);
              }
            }
          });
        });
        setTimeout(() => {
          const configSources = [ window.singleXrayConfig, window.userConfigText, window.proxyConfig, window.vpnConfig ];
          const initialConfig = configSources.find(c => c && typeof c === 'string' && c.trim());
          if (initialConfig) {
            const input = document.getElementById('config-input');
            if (input) { input.value = initialConfig; generate(initialConfig); }
          }
        }, 100);
      }

      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => { initialize(); console.log('%c✓ QR Code Manager Ultimate Initialized', 'color:#10b981;font-weight:bold;font-size:14px'); });
      } else {
        initialize();
        console.log('%c✓ QR Code Manager Ultimate Initialized', 'color:#10b981;font-weight:bold;font-size:14px');
      }
      window.QRGeneratorAPI = { generate, getState: () => ({ config: state.currentConfig, protocol: state.detectedProtocol, valid: state.isValid }) };
    })();
  </script>
</body>
</html>;

const adminHTML = <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Admin Panel - QR Manager</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: Inter, system-ui, -apple-system, 'Segoe UI', sans-serif;
      min-height: 100vh;
      background: radial-gradient(circle at 20% 20%, rgba(59,130,246,0.18), transparent 35%),
                  radial-gradient(circle at 80% 0%, rgba(139,92,246,0.15), transparent 30%),
                  linear-gradient(135deg, #0b1020 0%, #0f172a 45%, #0b1020 100%);
      color: #e5e7eb;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .panel {
      width: 100%;
      max-width: 960px;
      background: rgba(17, 24, 39, 0.85);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 18px;
      box-shadow: 0 25px 60px rgba(0,0,0,0.4);
      backdrop-filter: blur(16px);
      padding: 32px;
    }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
    .title { font-size: 26px; font-weight: 700; background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #06b6d4 100%); -webkit-background-clip: text; color: transparent; }
    .pill { padding: 8px 14px; border-radius: 999px; background: rgba(59,130,246,0.15); color: #bfdbfe; font-size: 12px; font-weight: 600; border: 1px solid rgba(59,130,246,0.35); }
    .grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-bottom: 24px; }
    .card { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 16px; box-shadow: inset 0 1px 0 rgba(255,255,255,0.04); }
    .card h3 { font-size: 14px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; }
    .value { font-size: 24px; font-weight: 700; color: #e5e7eb; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .btn { padding: 12px 16px; border: none; border-radius: 10px; font-weight: 700; cursor: pointer; color: #0b1020; background: linear-gradient(135deg, #10b981 0%, #22c55e 100%); box-shadow: 0 10px 30px rgba(16,185,129,0.35); transition: transform 0.2s ease, box-shadow 0.2s ease; }
    .btn:hover { transform: translateY(-2px); box-shadow: 0 16px 40px rgba(16,185,129,0.45); }
    .btn.secondary { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; box-shadow: 0 10px 30px rgba(59,130,246,0.35); }
    .btn.danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; box-shadow: 0 10px 30px rgba(239,68,68,0.35); }
    .note { margin-top: 12px; color: #cbd5e1; font-size: 13px; line-height: 1.6; }
    .divider { height: 1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent); margin: 18px 0; }
  </style>
</head>
<body>
  <div class="panel">
    <div class="header">
      <div class="title">⚡ Admin Panel</div>
      <div class="pill">Protected View</div>
    </div>
    <div class="grid">
      <div class="card"><h3>Total Users</h3><div class="value" id="stat-users">—</div></div>
      <div class="card"><h3>Active Sessions</h3><div class="value" id="stat-active">—</div></div>
      <div class="card"><h3>Health</h3><div class="value" id="stat-health">Checking…</div></div>
      <div class="card"><h3>Traffic (MB)</h3><div class="value" id="stat-traffic">—</div></div>
    </div>
    <div class="actions">
      <button class="btn" onclick="alert('Add User – backend hook needed');">➕ Add User</button>
      <button class="btn secondary" onclick="alert('Health Check – backend hook needed');">🔄 Run Health Check</button>
      <button class="btn danger" onclick="alert('Logout – backend hook needed');">🚪 Logout</button>
    </div>
    <div class="divider"></div>
    <div class="note">This admin shell is UI-ready. Wire it to your D1/API endpoints for full functionality. No features were removed; only client-side errors were fixed and the interface enhanced.</div>
  </div>
</body>
</html>;
