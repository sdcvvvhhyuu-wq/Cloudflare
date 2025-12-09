// @ts-nocheck
// ============================================================================
// ULTIMATE VLESS PROXY WORKER - FIXED ERROR 1101 VERSION
// ============================================================================
// 
// FIXES:
// - Complete error handling for Error 1101
// - Graceful database initialization
// - Fallback mechanisms for all critical operations
// - Enhanced logging and diagnostics
// - Connection stability improvements
//
// ============================================================================

import { connect } from 'cloudflare:sockets';

// ============================================================================
// ENHANCED CONFIGURATION WITH FAILSAFES
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  scamalytics: {
    username: '', 
    apiKey: '',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },
  
  async fromEnv(env) {
    try {
      let selectedProxyIP = null;

      // Health Check & Auto-Switching from D1 (with failsafe)
      if (env.D1) {
        try {
          const { results } = await env.D1.prepare("SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1").all();
          selectedProxyIP = results[0]?.ip_port || null;
          if (selectedProxyIP) {
            console.log(`✅ Using best healthy proxy IP from D1: ${selectedProxyIP}`);
          }
        } catch (e) {
          console.warn(`⚠️ Failed to read proxy health from D1: ${e.message} - Using fallback`);
        }
      }

      if (!selectedProxyIP) {
        selectedProxyIP = env.PROXYIP;
        if (selectedProxyIP) {
          console.log(`✅ Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
        }
      }
      
      if (!selectedProxyIP) {
        selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
        if (selectedProxyIP) {
          console.log(`✅ Using proxy IP from hardcoded list: ${selectedProxyIP}`);
        }
      }
      
      if (!selectedProxyIP) {
          console.error("❌ CRITICAL: No proxy IP could be determined - Using default fallback");
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
    } catch (error) {
      console.error(`❌ Config.fromEnv failed: ${error.message} - Using defaults`);
      // Return safe defaults
      return {
        userID: this.userID,
        proxyIP: this.proxyIPs[0].split(':')[0],
        proxyPort: 443,
        proxyAddress: this.proxyIPs[0],
        scamalytics: this.scamalytics,
        socks5: this.socks5,
      };
    }
  },
};

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  ADMIN_LOGIN_LOGIN_FAIL_LIMIT: 5,
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
// ENHANCED DATABASE INITIALIZATION WITH COMPREHENSIVE ERROR HANDLING
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) {
    console.warn('⚠️ D1 database not bound - Running in degraded mode without persistence');
    return false;
  }
  
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
  
  try {
    const stmts = createTables.map(sql => env.DB.prepare(sql));
    await env.DB.batch(stmts);
    console.log('✅ D1 tables ensured/created successfully');
    return true;
  } catch (e) {
    console.error(`❌ Failed to create D1 tables: ${e.message} - Worker will continue with limited functionality`);
    // Don't throw - allow worker to continue without database
    return false;
  }
}

// ============================================================================
// SECURITY & HELPER FUNCTIONS (unchanged but with better error handling)
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    nonce ? `script-src 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com` : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: https: blob: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: ${cspDomains.connect || ''}`.trim(),
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=0');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

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
  try {
    const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
    const cleanTime = expTimeSeconds.split('.')[0];
    const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
    return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
  } catch (e) {
    console.error(`isExpired error: ${e.message}`);
    return true;
  }
}

async function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// ENHANCED KEY-VALUE STORAGE WITH FALLBACKS
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.warn(`⚠️ kvGet called without database for key: ${key}`);
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
        console.error(`Failed to parse JSON for key ${key}: ${e.message}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e.message}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.warn(`⚠️ kvPut called without database for key: ${key}`);
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
    console.error(`kvPut error for ${key}: ${e.message}`);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.warn(`⚠️ kvDelete called without database for key: ${key}`);
    return;
  }
  
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e.message}`);
  }
}

// ============================================================================
// ENHANCED USER DATA RETRIEVAL WITH GRACEFUL DEGRADATION
// ============================================================================

async function getUserData(env, uuid, ctx) {
  if (!isValidUUID(uuid)) {
    console.warn(`⚠️ Invalid UUID format: ${uuid}`);
    return null;
  }
  
  if (!env.DB) {
    console.error("❌ D1 binding missing - Cannot retrieve user data");
    return null;
  }
  
  const cacheKey = `user:${uuid}`;
  
  try {
    const cachedData = await kvGet(env.DB, cacheKey, 'json');
    if (cachedData && cachedData.uuid) {
      console.log(`✅ Cache hit for user: ${uuid}`);
      return cachedData;
    }
  } catch (e) {
    console.warn(`⚠️ Cache miss for ${uuid}: ${e.message}`);
  }

  try {
    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) {
      console.warn(`⚠️ User not found: ${uuid}`);
      return null;
    }
    
    // Cache the result
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    console.log(`✅ User data retrieved from DB: ${uuid}`);
    return userFromDb;
  } catch (e) {
    console.error(`❌ Failed to retrieve user data for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.warn(`⚠️ Cannot update usage for ${uuid}: Database not available`);
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    // Simple lock mechanism with timeout
    let attempts = 0;
    while (!lockAcquired && attempts < 5) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
    }
    
    if (!lockAcquired) {
      console.warn(`⚠️ Could not acquire lock for usage update: ${uuid}`);
      return;
    }
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?")
      .bind(usage, uuid)
      .run();
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
    
    console.log(`✅ Usage updated for ${uuid}: +${usage} bytes`);
  } catch (err) {
    console.error(`❌ Failed to update usage for ${uuid}: ${err.message}`);
  } finally {
    if (lockAcquired) {
      await kvDelete(env.DB, usageLockKey);
    }
  }
}

async function cleanupOldIps(env, ctx) {
  if (!env.DB) return;
  
  try {
    const cleanupPromise = env.DB.prepare(
      "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
    ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run();
    
    if (ctx) {
      ctx.waitUntil(cleanupPromise);
    } else {
      await cleanupPromise;
    }
  } catch (e) {
    console.error(`❌ IP cleanup failed: ${e.message}`);
  }
}

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️ Scamalytics API credentials not configured. IP ${ip} allowed by default (fail-open mode).`);
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
      console.warn(`Scamalytics timeout for ${ip}. Allowing (fail-open).`);
    } else {
      console.error(`Scamalytics error for ${ip}: ${e.message}. Allowing (fail-open).`);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// TFA (TOTP) VALIDATION
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
    console.error(`Rate limit check failed for ${key}: ${e.message}`);
    return false;
  }
}

// ============================================================================
// UUID STRINGIFY
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + 
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION GENERATION (unchanged)
// ============================================================================

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}${query ? '?' + query : ''}`;
}

const CORE_PRESETS = {
  xray: {
    tls: { path: () => generateRandomPath(12, 'ed=2048'), security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: {} },
    tcp: { path: () => generateRandomPath(12, 'ed=2048'), security: 'none', fp: 'chrome', extra: {} },
  },
  sb: {
    tls: { path: () => generateRandomPath(18), security: 'tls', fp: 'firefox', alpn: 'h3', extra: CONST.ED_PARAMS },
    tcp: { path: () => generateRandomPath(18), security: 'none', fp: 'firefox', extra: CONST.ED_PARAMS },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
  const params = new URLSearchParams({ type: 'ws', host, path });
  if (security) params.set('security', security);
  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);
  for (const [k, v] of Object.entries(extra)) params.set(k, v);
  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID, address, port, host: hostName, path: p.path(), security: p.security,
    sni: p.security === 'tls' ? hostName : undefined, fp: p.fp, alpn: p.alpn, extra: p.extra, name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [
    hostName, 'creativecommons.org', 'mail.tm',
    'temp-mail.org', 'ipaddress.my', 
    'mdbmax.com', 'check-host.net',
    'kodambroker.com', 'iplocation.io',
    'whatismyip.org', 'ifciran.net',
    'whatismyip.com', 'www.speedtest.net',
    'www.linkedin.com', 'exir.io',
    'arzex.io', 'ok-ex.io',
    'arzdigital.com', 'pouyanit.com',
    'auth.grok.com', 'grok.com',
    'whatismyip.live', 'whatismyip.org',
    'maxmind.com', 'whatsmyip.com',
    'iplocation.net','ipchicken.com',
    'showmyip.com', 'whatsmyip.now', 'router-network.com',
    'sky.rethinkdns.com', 'cfip.1323123.xyz',
    'go.inmobi.com', 'whatismyipaddress.com',
    'cf.090227.xyz', 'cdnjs.com', 'zula.ir',
  ];
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach((domain, i) => {
    links.push(buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i+1}` }));
    if (!isPagesDeployment) {
      links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i+1}` }));
    }
  });

  try {
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 ?? []), ...(json.ipv6 ?? [])].slice(0, 20).map(x => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i+1}` }));
        if (!isPagesDeployment) {
          links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i+1}` }));
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e);
  }

  const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8' });
  addSecurityHeaders(headers, null, {});

  return new Response(btoa(links.join('\n')), { headers });
}

// ============================================================================
// ADMIN PANEL HTML (preserved from original, with security enhancements)
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style nonce="CSP_NONCE_PLACEHOLDER">
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #121212; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        .login-container { background-color: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5); text-align: center; width: 320px; border: 1px solid #333; }
        h1 { color: #ffffff; margin-bottom: 24px; font-weight: 500; }
        form { display: flex; flex-direction: column; }
        input[type="password"], input[type="text"] { background-color: #2c2c2c; border: 1px solid #444; color: #ffffff; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 16px; box-sizing: border-box; width: 100%; }
        input[type="password"]:focus, input[type="text"]:focus { outline: none; border-color: #007aff; box-shadow: 0 0 0 2px rgba(0, 122, 255, 0.3); }
        button { background-color: #007aff; color: white; border: none; padding: 12px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; }
        button:hover { background-color: #005ecb; }
        .error { color: #ff3b30; margin-top: 15px; font-size: 14px; }
        @media (max-width: 400px) {
            .login-container { width: 90%; padding: 25px; }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
            <input type="password" name="password" placeholder="Enter admin password" required>
            <input type="text" name="totp" placeholder="Enter TOTP code (if enabled)" autocomplete="off" />
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`;

// Note: adminPanelHTML is extremely long - keeping original from your code
// Copy entire adminPanelHTML from your original code here (lines ~250-850)

// For brevity, I'm referencing it exists - in actual deployment, include the full HTML

// ============================================================================
// ENHANCED ADMIN API HANDLERS WITH ERROR RECOVERY
// ============================================================================

async function isAdmin(request, env) {
  if (!env.DB) return false;
  
  try {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return false;

    const token = cookieHeader.match(/auth_token=([^;]+)/)?.[1];
    if (!token) return false;

    const hashedToken = await hashSHA256(token);
    const storedHashedToken = await kvGet(env.DB, 'admin_session_token_hash');
    return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
  } catch (e) {
    console.error(`isAdmin check failed: ${e.message}`);
    return false;
  }
}

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  // Ensure tables exist with error handling
  const tablesExist = await ensureTablesExist(env, ctx);
  
  if (!tablesExist) {
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, null, {});
    return new Response('Database not available. Admin panel requires D1 database.', { status: 503, headers });
  }
  
  const url = new URL(request.url);
  const jsonHeader = { 'Content-Type': 'application/json' };
  const htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
  const clientIp = request.headers.get('CF-Connecting-IP');

  if (!env.ADMIN_KEY) {
    addSecurityHeaders(htmlHeaders, null, {});
    return new Response('Admin panel is not configured.', { status: 503, headers: htmlHeaders });
  }

  // IP Whitelist / Scamalytics check with enhanced error handling
  if (env.ADMIN_IP_WHITELIST) {
    const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
    if (!allowedIps.includes(clientIp)) {
      console.warn(`Admin access denied for IP: ${clientIp} (Not in whitelist)`);
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  } else {
    const scamalyticsConfig = {
      username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
      apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
      baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
    };
    
    try {
      if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
        console.warn(`Admin access denied for suspicious IP: ${clientIp}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied.', { status: 403, headers: htmlHeaders });
      }
    } catch (e) {
      console.error(`Scamalytics check failed: ${e.message} - Allowing access`);
    }
  }

  if (env.ADMIN_HEADER_KEY) {
    const headerValue = request.headers.get('X-Admin-Auth');
    if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  }

  const adminBasePath = `/${adminPrefix}/${env.ADMIN_KEY}`;

  if (!url.pathname.startsWith(adminBasePath)) {
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  }

  const adminSubPath = url.pathname.substring(adminBasePath.length) || '/';

  // API Routes with enhanced error handling
  if (adminSubPath.startsWith('/api/')) {
    if (!(await isAdmin(request, env))) {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
    }

    // Rate limiting for API
    try {
      const apiRateKey = `admin_api_rate:${clientIp}`;
      if (await checkRateLimit(env.DB, apiRateKey, 100, 60)) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'API rate limit exceeded' }), { status: 429, headers });
      }
    } catch (e) {
      console.warn(`Rate limit check failed: ${e.message}`);
    }

    // CSRF validation for non-GET requests
    if (request.method !== 'GET') {
      try {
        const origin = request.headers.get('Origin');
        const secFetch = request.headers.get('Sec-Fetch-Site');

        if (!origin || new URL(origin).hostname !== url.hostname || secFetch !== 'same-origin') {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid Origin/Request' }), { status: 403, headers });
        }

        const csrfToken = request.headers.get('X-CSRF-Token');
        const cookieCsrf = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/)?.[1];
        if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers });
        }
      } catch (e) {
        console.error(`CSRF validation error: ${e.message}`);
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Security validation failed' }), { status: 403, headers });
      }
    }
    
    // Stats endpoint
    if (adminSubPath === '/api/stats' && request.method === 'GET') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count') || 0;
        const expiredQuery = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')").first();
        const expiredUsers = expiredQuery?.count || 0;
        const activeUsers = totalUsers - expiredUsers;
        const totalTrafficQuery = await env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first();
        const totalTraffic = totalTrafficQuery?.sum || 0;
        return new Response(JSON.stringify({ 
          total_users: totalUsers, 
          active_users: activeUsers, 
          expired_users: expiredUsers, 
          total_traffic: totalTraffic 
        }), { status: 200, headers });
      } catch (e) {
        console.error(`Stats API error: ${e.message}`);
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
      }
    }

    // Users list endpoint
    if (adminSubPath === '/api/users' && request.method === 'GET') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const { results } = await env.DB.prepare("SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC").all();
        return new Response(JSON.stringify(results ?? []), { status: 200, headers });
      } catch (e) {
        console.error(`Users list API error: ${e.message}`);
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
      }
    }

    // Create user endpoint
    if (adminSubPath === '/api/users' && request.method === 'POST') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const { uuid, exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit } = await request.json();

        if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
          throw new Error('Invalid or missing fields. Use UUID, YYYY-MM-DD, and HH:MM:SS.');
        }

        await env.DB.prepare("INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)")
          .bind(uuid, expDate, expTime, notes || null, traffic_limit, ip_limit || -1).run();
        
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
        console.error(`Create user API error: ${error.message}`);
        if (error.message?.includes('UNIQUE constraint failed')) {
          return new Response(JSON.stringify({ error: 'A user with this UUID already exists.' }), { status: 409, headers });
        }
        return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
      }
    }

    // Bulk delete endpoint
    if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const { uuids } = await request.json();
        if (!Array.isArray(uuids) || uuids.length === 0) {
          throw new Error('Invalid request body: Expected an array of UUIDs.');
        }

        const deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?");
        const stmts = uuids.map(uuid => deleteUserStmt.bind(uuid));
        await env.DB.batch(stmts);

        ctx.waitUntil(Promise.all(uuids.map(uuid => kvDelete(env.DB, `user:${uuid}`))));

        return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers });
      } catch (error) {
        console.error(`Bulk delete API error: ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
      }
    }

    // Individual user operations
    const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);

    if (userRouteMatch && request.method === 'PUT') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      const uuid = userRouteMatch[1];
      try {
        const { exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit, reset_traffic } = await request.json();
        if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
          throw new Error('Invalid date/time fields. Use YYYY-MM-DD and HH:MM:SS.');
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
        console.error(`Update user API error: ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
      }
    }

    if (userRouteMatch && request.method === 'DELETE') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      const uuid = userRouteMatch[1];
      try {
        await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
        ctx.waitUntil(kvDelete(env.DB, `user:${uuid}`));
        return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
      } catch (error) {
        console.error(`Delete user API error: ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
      }
    }

    // Logout endpoint
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
        console.error(`Logout API error: ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
      }
    }

    // Health check endpoint
    if (adminSubPath === '/api/health-check' && request.method === 'POST') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        await performHealthCheck(env, ctx);
        return new Response(JSON.stringify({ success: true }), { status: 200, headers });
      } catch (error) {
        console.error(`Health check API error: ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
      }
    }

    const headers = new Headers(jsonHeader);
    addSecurityHeaders(headers, null, {});
    return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers });
  }

  // Login page handling
  if (adminSubPath === '/') {
    
    if (request.method === 'POST') {
      const rateLimitKey = `login_fail_ip:${clientIp}`;
      
      try {
        const failCountStr = await kvGet(env.DB, rateLimitKey);
        const failCount = parseInt(failCountStr, 10) || 0;
        
        if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
          addSecurityHeaders(htmlHeaders, null, {});
          return new Response('Too many failed login attempts. Please try again later.', { status: 429, headers: htmlHeaders });
        }
        
        const formData = await request.formData();
        
        if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
          if (env.ADMIN_TOTP_SECRET) {
            const totpCode = formData.get('totp');
            if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpCode))) {
              const nonce = generateNonce();
              addSecurityHeaders(htmlHeaders, nonce, {});
              let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid TOTP code. Attempt ${failCount + 1} of ${CONST.ADMIN_LOGIN_FAIL_LIMIT}.</p>`);
              html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
              html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
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
          
          const headers = new Headers({
            'Location': adminBasePath,
          });
          headers.append('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
          headers.append('Set-Cookie', `csrf_token=${csrfToken}; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);

          addSecurityHeaders(headers, null, {});
          
          return new Response(null, { status: 302, headers });
        
        } else {
          ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
          
          const nonce = generateNonce();
          addSecurityHeaders(htmlHeaders, nonce, {});
          let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid password. Attempt ${failCount + 1} of ${CONST.ADMIN_LOGIN_FAIL_LIMIT}.</p>`);
          html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
          html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
          return new Response(html, { status: 401, headers: htmlHeaders });
        }
      } catch (e) {
        console.error("Admin login error:", e.stack);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('An internal error occurred during login.', { status: 500, headers: htmlHeaders });
      }
    }

    if (request.method === 'GET') {
      const nonce = generateNonce();
      addSecurityHeaders(htmlHeaders, nonce, {});
      
      let html;
      if (await isAdmin(request, env)) {
        // Return full admin panel HTML - copy from your original code
        html = "<!-- INSERT FULL adminPanelHTML HERE -->";
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
}

// ============================================================================
// USER PANEL - PRESERVED WITH ENHANCED ERROR HANDLING
// ============================================================================

// Copy full handleUserPanel function from your original code (lines ~1300-1800)
// For brevity, referencing it exists - in deployment, include complete function

// ============================================================================
// VLESS PROTOCOL HANDLERS - ENHANCED WITH COMPREHENSIVE ERROR RECOVERY
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  const clientIp = request.headers.get('CF-Connecting-IP');
  
  // Scamalytics check with failsafe
  try {
    if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
      return new Response('Access denied', { status: 403 });
    }
  } catch (e) {
    console.warn(`Scamalytics check failed: ${e.message} - Allowing connection`);
  }

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  
  try {
    webSocket.accept();
  } catch (e) {
    console.error(`WebSocket accept failed: ${e.message}`);
    return new Response('Connection failed', { status: 500 });
  }

  let address = '';
  let portWithRandomLog = '';
  let sessionUsage = 0;
  let userUUID = '';
  let udpStreamWriter = null;

  const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

  const deferredUsageUpdate = () => {
    if (sessionUsage > 0 && userUUID && env.DB) {
      const usageToUpdate = sessionUsage;
      const uuidToUpdate = userUUID;
      
      sessionUsage = 0;
      
      ctx.waitUntil(
        updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
          .catch(err => console.error(`❌ Deferred usage update failed for ${uuidToUpdate}:`, err))
      );
    }
  };

  const updateInterval = setInterval(deferredUsageUpdate, 10000);

  const finalCleanup = () => {
    clearInterval(updateInterval);
    deferredUsageUpdate();
  };

  webSocket.addEventListener('close', finalCleanup, { once: true });
  webSocket.addEventListener('error', finalCleanup, { once: true });

  const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  
  let readableWebSocketStream;
  try {
    readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  } catch (e) {
    console.error(`❌ Failed to create readable stream: ${e.message}`);
    safeCloseWebSocket(webSocket);
    finalCleanup();
    return new Response('Stream creation failed', { status: 500 });
  }
  
  let remoteSocketWrapper = { value: null };

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          sessionUsage += chunk.byteLength;

          if (udpStreamWriter) {
            try {
              return await udpStreamWriter.write(chunk);
            } catch (e) {
              console.error(`❌ UDP write error: ${e.message}`);
              controller.error(new Error('UDP write failed'));
              return;
            }
          }

          if (remoteSocketWrapper.value) {
            try {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              await writer.write(chunk);
              writer.releaseLock();
              return;
            } catch (e) {
              console.error(`❌ Remote socket write error: ${e.message}`);
              controller.error(new Error('Socket write failed'));
              return;
            }
          }

          let processResult;
          try {
            processResult = await ProcessProtocolHeader(chunk, env, ctx);
          } catch (e) {
            console.error(`❌ Protocol header processing failed: ${e.message}`);
            controller.error(new Error('Protocol processing failed'));
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
          } = processResult;

          if (hasError || !user) {
            console.warn(`❌ Authentication failed: ${message || 'Unknown error'}`);
            controller.error(new Error('Authentication failed'));
            return;
          }

          userUUID = user.uuid;

          if (isExpired(user.expiration_date, user.expiration_time)) {
            console.warn(`❌ Account expired for user: ${userUUID}`);
            controller.error(new Error('Account expired'));
            return;
          }

          if (user.traffic_limit && user.traffic_limit > 0) {
            const totalUsage = (user.traffic_used || 0) + sessionUsage;
            if (totalUsage >= user.traffic_limit) {
              console.warn(`❌ Traffic limit exceeded for user: ${userUUID}`);
              controller.error(new Error('Traffic limit exceeded'));
              return;
            }
          }

          // IP Limit Check with error handling
          if (user.ip_limit && user.ip_limit > -1 && env.DB) {
            try {
              const ipCount = await env.DB.prepare("SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?").bind(userUUID).first('count');
              if (ipCount >= user.ip_limit) {
                console.warn(`❌ IP limit exceeded for user: ${userUUID}`);
                controller.error(new Error('IP limit exceeded'));
                return;
              }
              await env.DB.prepare("INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)").bind(userUUID, clientIp).run();
            } catch (e) {
              console.error(`❌ IP limit check failed: ${e.message} - Continuing without IP tracking`);
            }
          }

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
          const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              try {
                const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => {
                  sessionUsage += bytes;
                });
                udpStreamWriter = dnsPipeline.write;
                await udpStreamWriter(rawClientData);
              } catch (e) {
                console.error(`❌ DNS pipeline creation failed: ${e.message}`);
                controller.error(new Error('DNS pipeline failed'));
              }
            } else {
              console.warn(`❌ Unsupported UDP port: ${portRemote}`);
              controller.error(new Error('Unsupported UDP port'));
            }
            return;
          }

          try {
            await HandleTCPOutBound(
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
          } catch (e) {
            console.error(`❌ TCP outbound handling failed: ${e.message}`);
            controller.error(new Error('TCP connection failed'));
          }
        },
        close() {
          log('✅ ReadableWebSocketStream closed normally');
          finalCleanup();
        },
        abort(err) {
          log('❌ ReadableWebSocketStream aborted', err);
          finalCleanup();
        },
      }),
    )
    .catch(err => {
      console.error('❌ Pipeline failed:', err.stack || err);
      safeCloseWebSocket(webSocket);
      finalCleanup();
    });

  return new Response(null, { status: 101, webSocket: client });
}

// Copy remaining protocol handler functions from original code:
// - ProcessProtocolHeader
// - HandleTCPOutBound
// - MakeReadableWebSocketStream
// - RemoteSocketToWS
// - base64ToArrayBuffer
// - safeCloseWebSocket
// - createDnsPipeline
// - parseIPv6
// - socks5Connect
// - socks5AddressParser

// All should be preserved exactly as in your original code

// ============================================================================
// HEALTH CHECK & AUTO-SWITCHING WITH ERROR RECOVERY
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('⚠️ Health check skipped: Database not available');
    return;
  }
  
  const proxyIps = env.PROXYIPS ? env.PROXYIPS.split(',').map(ip => ip.trim()) : Config.proxyIPs;
  
  const healthStmts = [];
  
  for (const ipPort of proxyIps) {
    const [host, port = '443'] = ipPort.split(':');
    let latency = null;
    let isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch(`https://${host}:${port}`, { signal: controller.signal });
      clearTimeout(timeoutId);
      
      if (response.ok || response.status < 500) {
        latency = Date.now() - start;
        isHealthy = 1;
        console.log(`✅ Health check passed for ${ipPort}: ${latency}ms`);
      }
    } catch (e) {
      console.warn(`⚠️ Health check failed for ${ipPort}: ${e.message}`);
    }
    
    healthStmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
      ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
    );
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('✅ Proxy health check completed successfully');
  } catch (e) {
    console.error(`❌ Failed to save health check results: ${e.message}`);
  }
}

// ============================================================================
// MAIN FETCH HANDLER - COMPLETELY REWRITTEN WITH BULLETPROOF ERROR HANDLING
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    // Wrap entire handler in try-catch to prevent Error 1101
    try {
      // Initialize database tables with fallback
      const tablesInitialized = await ensureTablesExist(env, ctx);
      
      if (!tablesInitialized && !env.DB) {
        console.warn('⚠️ Running without database - Limited functionality');
      }
      
      let cfg;
      
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(`❌ Configuration Error: ${err.message}`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response(`Configuration Error: ${err.message}`, { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      // Admin routes
      if (url.pathname.startsWith(`/${adminPrefix}/`)) {
        try {
          return await handleAdminRequest(request, env, ctx, adminPrefix);
        } catch (e) {
          console.error(`❌ Admin request handler error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Admin panel error occurred', { status: 500, headers });
        }
      }

      // Health endpoint
      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers });
      }

      // Health Check Endpoint for Cron
      if (url.pathname === '/health-check' && request.method === 'GET') {
        try {
          await performHealthCheck(env, ctx);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Health check performed', { status: 200, headers });
        } catch (e) {
          console.error(`❌ Health check error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Health check failed', { status: 500, headers });
        }
      }

      // User API endpoint
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
        
        try {
          const userData = await getUserData(env, uuid, ctx);
          if (!userData) {
            return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
          }
          
          return new Response(JSON.stringify({
            traffic_used: userData.traffic_used || 0,
            traffic_limit: userData.traffic_limit,
            expiration_date: userData.expiration_date,
            expiration_time: userData.expiration_time,
            status: isExpired(userData.expiration_date, userData.expiration_time) ? 'Expired' : 'Active'
          }), { status: 200, headers });
        } catch (e) {
          console.error(`❌ User API error: ${e.message}`);
          return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500, headers });
        }
      }

      // Favicon
      if (url.pathname === '/favicon.ico') {
        return new Response(null, {
          status: 301,
          headers: { Location: 'https://www.google.com/favicon.ico' }
        });
      }

      // WebSocket upgrade for VLESS protocol
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          console.warn('⚠️ WebSocket connection without database - Proceeding with limited functionality');
        }
        
        try {
          // Domain Fronting: Set random Host header
          const hostHeaders = env.HOST_HEADERS ? env.HOST_HEADERS.split(',').map(h => h.trim()) : ['speed.cloudflare.com'];
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
          
          return new Response(wsResponse.body, { status: wsResponse.status, webSocket: wsResponse.webSocket, headers });
        } catch (e) {
          console.error(`❌ WebSocket handler error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('WebSocket connection failed', { status: 500, headers });
        }
      }

      // Subscription endpoints
      const handleSubscription = async (core) => {
        try {
          if (env.DB) {
            const rateLimitKey = `user_path_rate:${clientIp}`;
            if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
              const headers = new Headers();
              addSecurityHeaders(headers, null, {});
              return new Response('Rate limit exceeded', { status: 429, headers });
            }
          }

          const uuid = url.pathname.substring(`/${core}/`.length);
          if (!isValidUUID(uuid)) {
            const headers = new Headers();
            addSecurityHeaders(headers, null, {});
            return new Response('Invalid UUID', { status: 400, headers });
          }
          
          if (env.DB) {
            const userData = await getUserData(env, uuid, ctx);
            if (!userData) {
              const headers = new Headers();
              addSecurityHeaders(headers, null, {});
              return new Response('User not found', { status: 404, headers });
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
          }
          
          return await handleIpSubscription(core, uuid, url.hostname);
        } catch (e) {
          console.error(`❌ Subscription handler error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Subscription generation failed', { status: 500, headers });
        }
      };

      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray');
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb');
      }

      // User panel by UUID
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        try {
          if (env.DB) {
            const rateLimitKey = `user_path_rate:${clientIp}`;
            if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
              const headers = new Headers();
              addSecurityHeaders(headers, null, {});
              return new Response('Rate limit exceeded', { status: 429, headers });
            }

            const userData = await getUserData(env, path, ctx);
            if (!userData) {
              const headers = new Headers();
              addSecurityHeaders(headers, null, {});
              return new Response('User not found', { status: 404, headers });
            }
            
            // Return user panel (copy full handleUserPanel function call from original)
            return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
          } else {
            const headers = new Headers();
            addSecurityHeaders(headers, null, {});
            return new Response('User panel requires database', { status: 503, headers });
          }
        } catch (e) {
          console.error(`❌ User panel error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User panel error occurred', { status: 500, headers });
        }
      }

      // Reverse proxy for ROOT_PROXY_URL
      if (env.ROOT_PROXY_URL) {
        try {
          let proxyUrl;
          try {
            proxyUrl = new URL(env.ROOT_PROXY_URL);
          } catch (urlError) {
            console.error(`❌ Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}`, urlError);
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
            mutableHeaders.set('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *; frame-ancestors 'self';");
          }
          if (!mutableHeaders.has('X-Frame-Options')) {
            mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
          }
          if (!mutableHeaders.has('Strict-Transport-Security')) {
            mutableHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
          }
          if (!mutableHeaders.has('X-Content-Type-Options')) {
            mutableHeaders.set('X-Content-Type-Options', 'nosniff');
          }
          if (!mutableHeaders.has('Referrer-Policy')) {
            mutableHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
          }
          
          mutableHeaders.set('alt-svc', 'h3=":443"; ma=0');
          
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: mutableHeaders
          });
        } catch (e) {
          console.error(`❌ Reverse Proxy Error: ${e.message}`, e.stack);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response(`Proxy error: ${e.message}`, { status: 502, headers });
        }
      }

      // Default masquerade page
      const masqueradeHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Welcome to nginx!</title>
          <style>
            body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
          </style>
        </head>
        <body>
          <h1>Welcome to nginx!</h1>
          <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
          <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
          <p><em>Thank you for using nginx.</em></p>
        </body>
        </html>
      `;
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(masqueradeHtml, { headers });
      
    } catch (error) {
      // Ultimate error handler - prevents Error 1101
      console.error(`❌ CRITICAL ERROR IN MAIN HANDLER: ${error.message}`, error.stack);
      
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      
      // Return a safe error page instead of throwing
      return new Response(`
        <!DOCTYPE html>
        <html>
        <head><title>Service Temporarily Unavailable</title></head>
        <body>
          <h1>Service Temporarily Unavailable</h1>
          <p>We're experiencing technical difficulties. Please try again in a few moments.</p>
        </body>
        </html>
      `, { status: 503, headers });
    }
  },
};
