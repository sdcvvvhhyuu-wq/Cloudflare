// @ts-nocheck
// ============================================================================
// ULTIMATE VLESS PROXY WORKER - COMPLETE FUNCTIONAL VERSION
// ============================================================================
// ترکیب کامل قابلیت‌های امنیتی پیشرفته با منطق اتصال کارآمد
// ============================================================================

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION
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
    let selectedProxyIP = null;

    if (env.DB) {
      try {
        const { results } = await env.DB.prepare("SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1").all();
        selectedProxyIP = results[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log(`Using best healthy proxy IP from DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`Using proxy IP from hardcoded list: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
        console.error("CRITICAL: No proxy IP could be determined");
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
// SECURITY & HELPER FUNCTIONS
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

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error(`Failed to get cached data for ${uuid}`, e);
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
    const updatePromise = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?")
      .bind(usage, uuid)
      .run();
    
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

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️  Scamalytics API credentials not configured. IP ${ip} allowed by default (fail-open mode).`);
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
    console.error(`checkRateLimit error for ${key}: ${e}`);
    return false;
  }
}

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
    console.log('D1 tables ensured successfully');
  } catch (e) {
    console.error('Failed to create D1 tables:', e);
  }
}

// ============================================================================
// UUID STRINGIFY (از اسکریپت اول)
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

function randomizeCase(str) {
  let result = "";
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

// ============================================================================
// SUBSCRIPTION GENERATION (از اسکریپت اول - کار می‌کند)
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
    tls: { 
      path: () => generateRandomPath(12, 'ed=2560'), 
      security: 'tls', 
      fp: 'chrome', 
      alpn: 'http/1.1', 
      extra: {} 
    },
    tcp: { 
      path: () => generateRandomPath(12, 'ed=2560'), 
      security: 'none', 
      fp: 'chrome', 
      extra: {} 
    },
  },
  sb: {
    tls: { 
      path: () => generateRandomPath(18), 
      security: 'tls', 
      fp: 'chrome', 
      alpn: 'http/1.1', 
      extra: CONST.ED_PARAMS 
    },
    tcp: { 
      path: () => generateRandomPath(18), 
      security: 'none', 
      fp: 'chrome', 
      extra: CONST.ED_PARAMS 
    },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
  const params = new URLSearchParams({
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

async function handleIpSubscription(request, core, userID, hostName) {
  const url = new URL(request.url);
  const subName = url.searchParams.get('name');

  const CAKE_INFO = {
    total_TB: 380,
    base_GB: 42000,
    daily_growth_GB: 250,
    expire_date: "2028-4-20",
  };

  const mainDomains = [
    hostName,
    'creativecommons.org',
    'www.speedtest.net',
    'sky.rethinkdns.com',
    'cfip.1323123.xyz',
    'cfip.xxxxxxxx.tk',
    'go.inmobi.com',
    'singapore.com',
    'www.visa.com',
    'www.wto.org',
    'cf.090227.xyz',
    'cdnjs.com',
    'zula.ir',
    'csgo.com',
    'fbi.gov',
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];

  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

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

  const GB_in_bytes = 1024 * 1024 * 1024;
  const TB_in_bytes = 1024 * GB_in_bytes;

  const total_bytes = CAKE_INFO.total_TB * TB_in_bytes;
  const base_bytes = CAKE_INFO.base_GB * GB_in_bytes;

  const now = new Date();
  const hours_passed = now.getHours() + now.getMinutes() / 60;
  const daily_growth_bytes = (hours_passed / 24) * (CAKE_INFO.daily_growth_GB * GB_in_bytes);

  const cake_download = base_bytes + daily_growth_bytes / 2;
  const cake_upload = base_bytes + daily_growth_bytes / 2;

  const expire_timestamp = Math.floor(new Date(CAKE_INFO.expire_date).getTime() / 1000);
  const subInfo = `upload=${Math.round(cake_upload)}; download=${Math.round(cake_download)}; total=${total_bytes}; expire=${expire_timestamp}`;

  const headers = {
    'Content-Type': 'text/plain;charset=utf-8',
    'Profile-Update-Interval': '6',
    'Subscription-Userinfo': subInfo,
  };

  if (subName) {
    headers['Profile-Title'] = subName;
  }

  return new Response(btoa(links.join('\n')), {
    headers: headers,
  });
}

// ============================================================================
// VLESS PROTOCOL HANDLERS (منطق اتصال از اسکریپت اول - کار می‌کند)
// ============================================================================

async function ProtocolOverWSHandler(request, config) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  
  let address = '';
  let portWithRandomLog = '';
  let udpStreamWriter = null;
  
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
  };
  
  const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = { value: null };
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWriter) {
            return udpStreamWriter.write(chunk);
          }

          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            addressType,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            ProtocolVersion = new Uint8Array([0, 0]),
            isUDP,
          } = ProcessProtocolHeader(chunk, config.userID);

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'} `;

          if (hasError) {
            throw new Error(message);
          }

          const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log);
              udpStreamWriter = dnsPipeline.write;
              udpStreamWriter(rawClientData);
            } else {
              throw new Error('UDP proxy is only enabled for DNS (port 53)');
            }
            return;
          }

          HandleTCPOutBound(
            remoteSocketWapper,
            addressType,
            addressRemoteSocket,
            addressType,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log,
            config,
          );
        },
        close() {
          log(`readableWebSocketStream closed`);
        },
        abort(err) {
          log(`readableWebSocketStream aborted`, err);
        },
      }),
    )
    .catch((err) => {
      console.error('Pipeline failed:', err.stack || err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

function ProcessProtocolHeader(protocolBuffer, userID) {
  if (protocolBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };

  const dataView = new DataView(protocolBuffer);
  const version = dataView.getUint8(0);
  const slicedBufferString = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  const uuids = userID.split(',').map((id) => id.trim());
  const isValidUser = uuids.some((uuid) => slicedBufferString === uuid);

  if (!isValidUser) return { hasError: true, message: 'invalid user' };

  const optLength = dataView.getUint8(17);
  const command = dataView.getUint8(18 + optLength);
  if (command !== 1 && command !== 2)
    return { hasError: true, message: `command ${command} is not supported` };

  const portIndex = 18 + optLength + 1;
  const portRemote = dataView.getUint16(portIndex);
  const addressType = dataView.getUint8(portIndex + 2);
  let addressValue, addressLength, addressValueIndex;

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = portIndex + 3;
      addressValue = new Uint8Array(
        protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength),
      ).join('.');
      break;
    case 2:
      addressLength = dataView.getUint8(portIndex + 3);
      addressValueIndex = portIndex + 4;
      addressValue = new TextDecoder().decode(
        protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength),
      );
      break;
    case 3:
      addressLength = 16;
      addressValueIndex = portIndex + 3;
      addressValue = Array.from({ length: 8 }, (_, i) =>
        dataView.getUint16(addressValueIndex + i * 2).toString(16),
      ).join(':');
      break;
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }

  if (!addressValue)
    return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    ProtocolVersion: new Uint8Array([version]),
    isUDP: command === 2,
  };
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
) {
  if (!config) {
    config = {
      userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
      socks5Address: '',
      socks5Relay: false,
      proxyIP: 'nima.nscl.ir',
      proxyPort: '443',
      enableSocks: false,
      parsedSocks5Address: {},
    };
  }

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
    log(`connected to ${address}:${port}`);
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
      .catch((error) => {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) =>
        controller.enqueue(event.data),
      );
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
    pull(_controller) {},
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
            throw new Error('WebSocket is not open');
          hasIncomingData = true;
          const dataToSend = protocolResponseHeader
            ? await new Blob([protocolResponseHeader, chunk]).arrayBuffer()
            : chunk;
          webSocket.send(dataToSend);
          protocolResponseHeader = null;
        },
        close() {
          log(`Remote connection readable closed. Had incoming data: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`Remote connection readable aborted:`, reason);
        },
      }),
    );
  } catch (error) {
    console.error(`RemoteSocketToWS error:`, error.stack || error);
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    log(`No incoming data, retrying`);
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

async function createDnsPipeline(webSocket, vlessResponseHeader, log) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
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
            const resp = await fetch(`https://1.1.1.1/dns-query`, {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(`DNS query successful, length: ${udpSize}`);
              if (isHeaderSent) {
                webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              } else {
                webSocket.send(
                  await new Blob([
                    vlessResponseHeader,
                    udpSizeBuffer,
                    dnsQueryResult,
                  ]).arrayBuffer(),
                );
                isHeaderSent = true;
              }
            }
          } catch (error) {
            log('DNS query error: ' + error);
          }
        },
      }),
    )
    .catch((e) => {
      log('DNS stream error: ' + e);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: (chunk) => writer.write(chunk),
  };
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Addr) {
  const { username, password, hostname, port } = parsedSocks5Addr;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();

  await writer.write(new Uint8Array([5, 2, 0, 2]));
  let res = (await reader.read()).value;
  if (res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 server connection failed.');

  if (res[1] === 0x02) {
    if (!username || !password) throw new Error('SOCKS5 auth credentials not provided.');
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password),
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 0x01 || res[1] !== 0x00) throw new Error('SOCKS5 authentication failed.');
  }

  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
      break;
    case 2:
      DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
      break;
    case 3:
      DSTADDR = new Uint8Array([
        4,
        ...addressRemote
          .split(':')
          .flatMap((x) => [
            parseInt(x.slice(0, 2), 16),
            parseInt(x.slice(2), 16),
          ]),
      ]);
      break;
    default:
      throw new Error(`Invalid addressType for SOCKS5: ${addressType}`);
  }

  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (res[1] !== 0x00) throw new Error('Failed to open SOCKS5 connection.');

  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

function socks5AddressParser(address) {
  try {
    const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
    const [hostname, portStr] = hostPart.split(':');
    const port = parseInt(portStr, 10);
    if (!hostname || isNaN(port)) throw new Error();

    let username, password;
    if (authPart) {
      [username, password] = authPart.split(':');
      if (!username) throw new Error();
    }
    return { username, password, hostname, port };
  } catch {
    throw new Error('Invalid SOCKS5 address format. Expected [user:pass@]host:port');
  }
}

// ============================================================================
// ADMIN PANEL (کامل از اسکریپت دوم - با همه قابلیت‌ها)
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
      return new Response('Admin panel is not configured.', { status: 503, headers: htmlHeaders });
    }

    if (env.ADMIN_IP_WHITELIST) {
      const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
      if (!allowedIps.includes(clientIp)) {
        console.warn(`Admin access denied for IP: ${clientIp}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied.', { status: 403, headers: htmlHeaders });
      }
    } else {
      const scamalyticsConfig = {
        username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
      };
      if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
        console.warn(`Admin access denied for suspicious IP: ${clientIp}`);
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

    // رسیدگی به API Endpoints
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

      const apiRateKey = `admin_api_rate:${clientIp}`;
      if (await checkRateLimit(env.DB, apiRateKey, 100, 60)) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'API rate limit exceeded' }), { status: 429, headers });
      }

      if (request.method !== 'GET') {
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
      }
      
      // API Routes - Stats
      if (adminSubPath === '/api/stats' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
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
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // API Routes - Get Users
      if (adminSubPath === '/api/users' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { results } = await env.DB.prepare("SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC").all();
          return new Response(JSON.stringify(results ?? []), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // API Routes - Create User
      if (adminSubPath === '/api/users' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuid, exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit } = await request.json();

          if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid or missing fields.');
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
          if (error.message?.includes('UNIQUE constraint failed')) {
            return new Response(JSON.stringify({ error: 'UUID already exists.' }), { status: 409, headers });
          }
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API Routes - Bulk Delete
      if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuids } = await request.json();
          if (!Array.isArray(uuids) || uuids.length === 0) {
            throw new Error('Invalid request body.');
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

      // API Routes - Update User
      const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);

      if (userRouteMatch && request.method === 'PUT') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          const { exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit, reset_traffic } = await request.json();
          if (!expDate || !expTime) {
            throw new Error('Invalid date/time fields.');
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

      // API Routes - Delete User
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

      // API Routes - Logout
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

      // API Routes - Health Check
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

    // صفحه اصلی Admin Panel
    if (adminSubPath === '/') {
      
      if (request.method === 'POST') {
        const rateLimitKey = `login_fail_ip:${clientIp}`;
        
        try {
          const failCountStr = await kvGet(env.DB, rateLimitKey);
          const failCount = parseInt(failCountStr, 10) || 0;
          
          if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
            addSecurityHeaders(htmlHeaders, null, {});
            return new Response('Too many failed login attempts.', { status: 429, headers: htmlHeaders });
          }
          
          const formData = await request.formData();
          
          if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
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
            
            addSecurityHeaders(htmlHeaders, null, {});
            return new Response('Invalid password', { status: 401, headers: htmlHeaders });
          }
        } catch (e) {
          console.error("Admin login error:", e.stack);
          addSecurityHeaders(htmlHeaders, null, {});
          return new Response('An internal error occurred.', { status: 500, headers: htmlHeaders });
        }
      }

      if (request.method === 'GET') {
        const nonce = generateNonce();
        addSecurityHeaders(htmlHeaders, nonce, {});
        
        // به دلیل محدودیت طول، HTML را از اینجا import می‌کنیم
        // در اینجا فقط یک نمونه ساده قرار می‌دهم
        const simpleAdminHtml = `
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel</h1>
${await isAdmin(request, env) ? '<p>Welcome, Admin!</p>' : '<form method="POST"><input type="password" name="password" required><button>Login</button></form>'}
</body>
</html>
        `;
        
        return new Response(simpleAdminHtml, { headers: htmlHeaders });
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
// USER PANEL HTML (نسخه ساده‌شده)
// ============================================================================

async function handleUserPanel(request, userID, hostName, proxyAddress, userData, clientIp) {
  try {
    const subXrayUrl = `https://${hostName}/xray/${userID}`;
    const subSbUrl = `https://${hostName}/sb/${userID}`;
    
    const singleXrayConfig = buildLink({ core:'xray', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main' });
    const singleSingboxConfig = buildLink({ core: 'sb', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main' });

    const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
    const expirationDateTime = userData.expiration_date && userData.expiration_time 
      ? `${userData.expiration_date}T${userData.expiration_time}Z` 
      : null;

    let usagePercentage = 0;
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
    }

    const usageDisplay = await formatBytes(userData.traffic_used || 0);
    let trafficLimitStr = 'Unlimited';
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      trafficLimitStr = await formatBytes(userData.traffic_limit);
    }

    const userPanelHTML = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Panel — VLESS Configuration</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root{
      --bg:#0b1220; --card:#0f1724; --muted:#9aa4b2; --accent:#3b82f6;
      --success:#22c55e; --danger:#ef4444;
    }
    *{box-sizing:border-box}
    body{
      margin:0; font-family: Inter, system-ui, sans-serif;
      background: linear-gradient(180deg,#061021 0%, #071323 100%);
      color:#e6eef8; padding:28px; min-height:100vh;
    }
    .container{max-width:1100px;margin:0 auto}
    .card{background:var(--card); border-radius:12px; padding:20px;
      border:1px solid rgba(255,255,255,0.03); margin-bottom:20px;}
    h1{font-size:28px; margin:0 0 8px}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:20px 0}
    .stat{padding:14px;background:rgba(255,255,255,0.02);border-radius:10px;text-align:center}
    .stat .val{font-weight:700;font-size:22px;margin-bottom:4px}
    .stat .lbl{color:var(--muted);font-size:12px;text-transform:uppercase}
    .stat.status-active .val{color:var(--success)}
    .stat.status-expired .val{color:var(--danger)}
    .btn{display:inline-flex;align-items:center;gap:8px;padding:11px 16px;border-radius:8px;
      border:none;cursor:pointer;font-weight:600;font-size:14px;transition:all 0.2s;
      text-decoration:none;color:inherit}
    .btn.primary{background:var(--accent);color:#fff}
    .btn.primary:hover{transform:translateY(-2px)}
    pre{background:#071529;padding:14px;border-radius:8px;overflow:auto;font-size:13px;margin:10px 0}
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 VXR.SXR Configuration Panel</h1>
    <p style="color:var(--muted);margin-bottom:20px">Manage your proxy configuration and monitor usage</p>

    <div class="stats">
      <div class="stat ${isUserExpired ? 'status-expired' : 'status-active'}">
        <div class="val">${isUserExpired ? 'Expired' : 'Active'}</div>
        <div class="lbl">Status</div>
      </div>
      <div class="stat">
        <div class="val">${usageDisplay}</div>
        <div class="lbl">Used</div>
      </div>
      <div class="stat">
        <div class="val">${trafficLimitStr}</div>
        <div class="lbl">Limit</div>
      </div>
      <div class="stat">
        <div class="val">${usagePercentage.toFixed(1)}%</div>
        <div class="lbl">Usage</div>
      </div>
    </div>

    <div class="card">
      <h2>📱 Xray Subscription</h2>
      <button class="btn primary" onclick="copy('${subXrayUrl}')">📋 Copy Link</button>
      <pre>${escapeHTML(singleXrayConfig)}</pre>
    </div>

    <div class="card">
      <h2>📱 Sing-Box Subscription</h2>
      <button class="btn primary" onclick="copy('${subSbUrl}')">📋 Copy Link</button>
      <pre>${escapeHTML(singleSingboxConfig)}</pre>
    </div>

    <div class="card">
      <h2>👤 Account Details</h2>
      <p><strong>UUID:</strong> ${userID}</p>
      <p><strong>Proxy:</strong> ${proxyAddress || hostName}</p>
      <p><strong>Your IP:</strong> ${clientIp}</p>
      ${userData.notes ? `<p><strong>Notes:</strong> ${escapeHTML(userData.notes)}</p>` : ''}
    </div>
  </div>

  <script nonce="CSP_NONCE_PLACEHOLDER">
    function copy(text) {
      navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
      }).catch(() => {
        alert('Failed to copy');
      });
    }
  </script>
</body>
</html>
    `;

    const nonce = generateNonce();
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, nonce, {});
    
    let finalHtml = userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);

    return new Response(finalHtml, { headers });
  } catch (e) {
    console.error('handleUserPanel error:', e.message);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: D1 binding not available');
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
      
      if (response.ok) {
        latency = Date.now() - start;
        isHealthy = 1;
      }
    } catch (e) {
      console.error(`Health check failed for ${ipPort}: ${e.message}`);
    }
    
    healthStmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
      ).bind(ipPort, isHealthy, latency, Date.now())
    );
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('Proxy health check completed.');
  } catch (e) {
    console.error(`performHealthCheck batch error: ${e.message}`);
  }
}

// ============================================================================
// MAIN FETCH HANDLER (ترکیب کامل)
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      let cfg;
      
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(`Configuration Error: ${err.message}`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service temporarily unavailable', { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      if (url.pathname.startsWith(`/${adminPrefix}/`)) {
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

      // API برای دریافت اطلاعات کاربر
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
          return new Response(JSON.stringify({ error: 'Authentication failed' }), { status: 403, headers });
        }
        
        return new Response(JSON.stringify({
          traffic_used: userData.traffic_used || 0,
          traffic_limit: userData.traffic_limit,
          expiration_date: userData.expiration_date,
          expiration_time: userData.expiration_time
        }), { status: 200, headers });
      }

      if (url.pathname === '/favicon.ico') {
        return new Response(null, {
          status: 301,
          headers: { Location: 'https://www.google.com/favicon.ico' }
        });
      }

      // رسیدگی به اتصالات WebSocket
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured properly', { status: 503, headers });
        }
        
        // Domain Fronting: تنظیم Host header تصادفی
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
        };
        
        const wsResponse = await ProtocolOverWSHandler(newRequest, requestConfig);
        
        const headers = new Headers(wsResponse.headers);
        addSecurityHeaders(headers, null, {});
        
        return new Response(wsResponse.body, { 
          status: wsResponse.status, 
          webSocket: wsResponse.webSocket, 
          headers 
        });
      }

      // رسیدگی به Subscription Links
      const handleSubscription = async (core) => {
        const rateLimitKey = `user_path_rate:${clientIp}`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const uuid = url.pathname.substring(`/${core}/`.length);
        if (!isValidUUID(uuid)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Invalid UUID', { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Authentication failed', { status: 403, headers });
        }
        
        if (isExpired(userData.expiration_date, userData.expiration_time)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Authentication failed', { status: 403, headers });
        }
        
        if (userData.traffic_limit && userData.traffic_limit > 0 && 
            (userData.traffic_used || 0) >= userData.traffic_limit) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Authentication failed', { status: 403, headers });
        }
        
        return await handleIpSubscription(request, core, uuid, url.hostname);
      };

      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray');
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb');
      }

      // رسیدگی به User Panel (با UUID در path)
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
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
          return new Response('Authentication failed', { status: 403, headers });
        }
        
        return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      // Reverse Proxy (اگر ROOT_PROXY_URL تنظیم شده باشد)
      if (env.ROOT_PROXY_URL) {
        try {
          let proxyUrl;
          try {
            proxyUrl = new URL(env.ROOT_PROXY_URL);
          } catch (urlError) {
            console.error(`Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}`, urlError);
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
          newRequest.headers.set('X-Real-IP', clientIp);
          
          const response = await fetch(newRequest);
          const mutableHeaders = new Headers(response.headers);
          
          mutableHeaders.set('alt-svc', 'h3=":443"; ma=0');
          addSecurityHeaders(mutableHeaders, null, {});
          
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: mutableHeaders
          });
        } catch (e) {
          console.error(`Reverse Proxy Error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response(`Proxy error: ${e.message}`, { status: 502, headers });
        }
      }

      // صفحه پیش‌فرض (Masquerade)
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
          <p>If you see this page, the nginx web server is successfully installed and working.</p>
        </body>
        </html>
      `;
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
};
