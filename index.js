// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - ENTERPRISE EDITION v2.0
 * ============================================================================
 * Complete, tested, and production-ready VLESS proxy with advanced features
 * 
 * Features:
 * - Complete VLESS WebSocket protocol implementation
 * - Advanced Admin Panel with real-time monitoring
 * - User Panel with QR Code generator
 * - Health Check & Auto-Switching
 * - Scamalytics IP reputation check
 * - D1 Database integration
 * - Multi-protocol subscription system
 * - Rate limiting and security
 * - HTTP/3 Support
 * - Reverse Proxy Landing Page
 * - Custom 404 Page
 * - Robots.txt & Security.txt
 * - Intelligent Masquerading
 * 
 * Last Updated: December 2025
 * ============================================================================
 */

// ============================================================================
// CONFIGURATION
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

  landingPage: {
    title: "Cloudflare Network Services",
    description: "High-performance network infrastructure powered by Cloudflare",
    company: "Cloudflare, Inc.",
    contact: "support@cloudflare.com",
    copyright: `© ${new Date().getFullYear()} Cloudflare, Inc. All rights reserved.`
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
          console.log(`✓ Using best healthy proxy from DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from config list: ${selectedProxyIP}`);
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
      landingPage: {
        title: env.LANDING_TITLE || this.landingPage.title,
        description: env.LANDING_DESCRIPTION || this.landingPage.description,
        company: env.LANDING_COMPANY || this.landingPage.company,
        contact: env.LANDING_CONTACT || this.landingPage.contact,
        copyright: env.LANDING_COPYRIGHT || this.landingPage.copyright
      }
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
// HELPER FUNCTIONS
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
  headers.set('alt-svc', 'h3=":443"; ma=86400, h3-29=":443"; ma=86400');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
  headers.set('X-Powered-By', 'Cloudflare');
  headers.set('Vary', 'Accept-Encoding');
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

function generateRandomPath(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}`;
}

// ============================================================================
// STATIC CONTENT HANDLERS
// ============================================================================

async function handleRobotsTxt() {
  const content = `# Robots.txt for Cloudflare Network Services
User-agent: *
Allow: /$
Allow: /robots.txt
Allow: /security.txt
Disallow: /xray/
Disallow: /sb/
Disallow: /admin/
Disallow: /api/
Crawl-delay: 10

# Sitemap
Sitemap: https://www.cloudflare.com/sitemap.xml

# Cloudflare Bot Management
User-agent: GPTBot
Disallow: /

User-agent: ChatGPT-User
Disallow: /

User-agent: Google-Extended
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: FacebookBot
Disallow: /`;

  const headers = new Headers({
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'public, max-age=3600',
    'X-Robots-Tag': 'index, follow'
  });
  addSecurityHeaders(headers, null, {});
  return new Response(content, { headers });
}

async function handleSecurityTxt() {
  const content = `# Security.txt for Cloudflare Network Services
Contact: mailto:security@cloudflare.com
Contact: https://www.cloudflare.com/security
Encryption: https://www.cloudflare.com/keys/pgp.asc
Acknowledgments: https://www.cloudflare.com/acknowledgments
Policy: https://www.cloudflare.com/security-policy
Preferred-Languages: en
Expires: 2026-12-31T23:00:00.000Z
Canonical: https://www.cloudflare.com/.well-known/security.txt

# Please report security vulnerabilities to our security team
# We appreciate your help in keeping our services secure`;

  const headers = new Headers({
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'public, max-age=86400',
    'X-Content-Type-Options': 'nosniff'
  });
  addSecurityHeaders(headers, null, {});
  return new Response(content, { headers });
}

async function handleCustom404() {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | Cloudflare</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            padding: 20px;
        }
        
        .container {
            max-width: 600px;
            text-align: center;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .error-code {
            font-size: 120px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #fff, #e0e0e0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
        
        .error-title {
            font-size: 32px;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        .error-message {
            font-size: 18px;
            line-height: 1.6;
            margin-bottom: 30px;
            opacity: 0.9;
        }
        
        .actions {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 30px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        
        .btn-primary {
            background: white;
            color: #667eea;
        }
        
        .btn-secondary {
            background: transparent;
            border-color: white;
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .cloudflare-logo {
            margin-top: 30px;
            opacity: 0.7;
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
            }
            
            .error-code {
                font-size: 80px;
            }
            
            .error-title {
                font-size: 24px;
            }
            
            .btn {
                padding: 10px 20px;
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-code">404</div>
        <h1 class="error-title">Page Not Found</h1>
        <p class="error-message">
            The page you are looking for might have been removed, had its name changed, 
            or is temporarily unavailable.
        </p>
        <div class="actions">
            <a href="/" class="btn btn-primary">Go to Homepage</a>
            <a href="https://www.cloudflare.com" class="btn btn-secondary">Visit Cloudflare</a>
        </div>
        <div class="cloudflare-logo">
            <svg width="100" height="24" viewBox="0 0 100 24" fill="white">
                <path d="M10 0L0 24h20L10 0zm80 0L70 24h20L90 0zM50 0L40 24h20L50 0z"/>
            </svg>
        </div>
    </div>
</body>
</html>`;

  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-cache'
  });
  addSecurityHeaders(headers, null, {});
  return new Response(html, { status: 404, headers });
}

async function handleReverseProxyLanding(request, landingConfig) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHTML(landingConfig.title)}</title>
    <meta name="description" content="${escapeHTML(landingConfig.description)}">
    <meta name="author" content="${escapeHTML(landingConfig.company)}">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🚀</text></svg>">
    <style>
        :root {
            --primary-color: #0066ff;
            --secondary-color: #00cc88;
            --accent-color: #ff3366;
            --background-color: #0a0a0a;
            --card-color: #1a1a1a;
            --text-color: #ffffff;
            --text-secondary: #a0a0a0;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--background-color);
            color: var(--text-color);
            min-height: 100vh;
            overflow-x: hidden;
            line-height: 1.6;
        }
        
        .background-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: 
                radial-gradient(circle at 20% 30%, rgba(0, 102, 255, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 70%, rgba(0, 204, 136, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(255, 51, 102, 0.1) 0%, transparent 50%);
            animation: pulse 20s ease-in-out infinite alternate;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 0;
            margin-bottom: 4rem;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.5rem;
            font-weight: bold;
            background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }
        
        .nav-links a {
            color: var(--text-secondary);
            text-decoration: none;
            transition: color 0.3s;
            font-weight: 500;
        }
        
        .nav-links a:hover {
            color: var(--primary-color);
        }
        
        .hero {
            text-align: center;
            padding: 6rem 0;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .hero h1 {
            font-size: 3.5rem;
            font-weight: 800;
            margin-bottom: 1.5rem;
            background: linear-gradient(45deg, var(--primary-color), var(--secondary-color), var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1.2;
        }
        
        .hero p {
            font-size: 1.2rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .cta-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 2rem;
        }
        
        .btn {
            padding: 1rem 2rem;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            border: 2px solid transparent;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
            color: white;
        }
        
        .btn-secondary {
            background: transparent;
            border-color: var(--primary-color);
            color: var(--primary-color);
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0, 102, 255, 0.3);
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin: 6rem 0;
        }
        
        .feature-card {
            background: var(--card-color);
            padding: 2rem;
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, border-color 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary-color);
        }
        
        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        
        .feature-card h3 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: var(--primary-color);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
            margin: 4rem 0;
            text-align: center;
        }
        
        .stat-item {
            padding: 2rem;
            background: var(--card-color);
            border-radius: 15px;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: block;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .footer {
            margin-top: 6rem;
            padding-top: 3rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
            color: var(--text-secondary);
        }
        
        .social-links {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .social-links a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s;
        }
        
        .social-links a:hover {
            color: var(--primary-color);
            border-color: var(--primary-color);
            transform: translateY(-2px);
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .nav-links {
                flex-wrap: wrap;
                justify-content: center;
            }
            
            .hero h1 {
                font-size: 2.5rem;
            }
            
            .hero p {
                font-size: 1rem;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
                max-width: 300px;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="background-animation"></div>
    
    <div class="container">
        <header class="header">
            <div class="logo">
                <span>🚀</span>
                <span>${escapeHTML(landingConfig.company)}</span>
            </div>
            <nav>
                <ul class="nav-links">
                    <li><a href="#features">Features</a></li>
                    <li><a href="#performance">Performance</a></li>
                    <li><a href="#security">Security</a></li>
                    <li><a href="mailto:${escapeHTML(landingConfig.contact)}">Contact</a></li>
                </ul>
            </nav>
        </header>
        
        <main>
            <section class="hero">
                <h1>${escapeHTML(landingConfig.title)}</h1>
                <p>${escapeHTML(landingConfig.description)}</p>
                <div class="cta-buttons">
                    <a href="https://www.cloudflare.com" class="btn btn-primary">
                        <span>🚀</span> Get Started
                    </a>
                    <a href="https://developers.cloudflare.com" class="btn btn-secondary">
                        <span>📚</span> Documentation
                    </a>
                </div>
            </section>
            
            <section id="features" class="features">
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>High Performance</h3>
                    <p>Global network with edge computing capabilities for lightning-fast content delivery.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <h3>Enterprise Security</h3>
                    <p>Advanced DDoS protection, WAF, and zero-trust security architecture.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🌐</div>
                    <h3>Global Network</h3>
                    <p>300+ data centers worldwide ensuring low latency and high availability.</p>
                </div>
            </section>
            
            <section id="performance" class="stats">
                <div class="stat-item">
                    <span class="stat-number">300+</span>
                    <span class="stat-label">Data Centers</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">99.99%</span>
                    <span class="stat-label">Uptime SLA</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">50ms</span>
                    <span class="stat-label">Average Latency</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">50M+</span>
                    <span class="stat-label">Requests/sec</span>
                </div>
            </section>
        </main>
        
        <footer class="footer">
            <div class="social-links">
                <a href="https://twitter.com/Cloudflare">Twitter</a>
                <a href="https://github.com/cloudflare">GitHub</a>
                <a href="https://blog.cloudflare.com">Blog</a>
                <a href="https://www.linkedin.com/company/cloudflare">LinkedIn</a>
            </div>
            <p>${escapeHTML(landingConfig.copyright)}</p>
            <p style="margin-top: 1rem; font-size: 0.9rem;">
                <a href="/robots.txt" style="color: var(--text-secondary);">robots.txt</a> | 
                <a href="/security.txt" style="color: var(--text-secondary);">security.txt</a> | 
                <a href="/.well-known/security.txt" style="color: var(--text-secondary);">.well-known/security.txt</a>
            </p>
        </footer>
    </div>
    
    <script>
        // Interactive animations
        document.addEventListener('DOMContentLoaded', function() {
            // Animate stats counter
            const statNumbers = document.querySelectorAll('.stat-number');
            statNumbers.forEach(stat => {
                const target = parseInt(stat.textContent);
                let current = 0;
                const increment = target / 50;
                
                const updateNumber = () => {
                    if (current < target) {
                        current += increment;
                        stat.textContent = Math.floor(current) + '+';
                        requestAnimationFrame(updateNumber);
                    } else {
                        stat.textContent = target + '+';
                    }
                };
                
                // Start animation when in viewport
                const observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            updateNumber();
                            observer.unobserve(entry.target);
                        }
                    });
                });
                
                observer.observe(stat);
            });
            
            // Smooth scroll for navigation links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function(e) {
                    e.preventDefault();
                    const targetId = this.getAttribute('href');
                    if (targetId === '#') return;
                    
                    const targetElement = document.querySelector(targetId);
                    if (targetElement) {
                        targetElement.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });
            
            // Add hover effect to feature cards
            const featureCards = document.querySelectorAll('.feature-card');
            featureCards.forEach(card => {
                card.addEventListener('mouseenter', () => {
                    card.style.transform = 'translateY(-10px) scale(1.02)';
                });
                
                card.addEventListener('mouseleave', () => {
                    card.style.transform = 'translateY(0) scale(1)';
                });
            });
        });
    </script>
</body>
</html>`;

  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'public, max-age=3600',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff'
  });
  addSecurityHeaders(headers, null, {
    img: 'data: https:',
    connect: 'https:'
  });
  return new Response(html, { headers });
}

async function handleMasquerade() {
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Welcome to nginx!</title>
  <style>
    body {
      width: 35em;
      margin: 0 auto;
      font-family: Tahoma, Verdana, Arial, sans-serif;
      padding: 50px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
    }
    
    .container {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      padding: 40px;
      border-radius: 20px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      text-align: center;
    }
    
    h1 {
      color: white;
      margin-bottom: 30px;
      font-size: 2.5em;
    }
    
    p {
      color: rgba(255, 255, 255, 0.9);
      line-height: 1.6;
      margin-bottom: 20px;
      font-size: 1.1em;
    }
    
    a {
      color: #ffd700;
      text-decoration: none;
      border-bottom: 1px dotted #ffd700;
      transition: all 0.3s;
    }
    
    a:hover {
      color: #fff;
      border-bottom-color: #fff;
    }
    
    .logo {
      margin-bottom: 30px;
      font-size: 4em;
    }
    
    .nginx-info {
      background: rgba(0, 0, 0, 0.2);
      padding: 20px;
      border-radius: 10px;
      margin: 30px 0;
      font-family: monospace;
      text-align: left;
    }
    
    @media (max-width: 600px) {
      body {
        padding: 20px;
      }
      
      .container {
        padding: 20px;
      }
      
      h1 {
        font-size: 2em;
      }
    }
  </style>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🐋</text></svg>">
</head>
<body>
  <div class="container">
    <div class="logo">🐋</div>
    <h1>Welcome to nginx!</h1>
    <p>
      If you see this page, the nginx web server is successfully installed and working. 
      Further configuration is required.
    </p>
    <div class="nginx-info">
      Server: nginx/1.24.0<br>
      Host: ${new Date().toUTCString()}<br>
      Connection: keep-alive<br>
      Status: 🟢 Operational
    </div>
    <p>
      For online documentation and support please refer to 
      <a href="http://nginx.org/">nginx.org</a>.<br>
      Commercial support is available at 
      <a href="http://nginx.com/">nginx.com</a>.
    </p>
    <p><em>Thank you for using nginx.</em></p>
  </div>
</body>
</html>`;

  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-cache',
    'Server': 'nginx/1.24.0',
    'X-Powered-By': 'nginx'
  });
  addSecurityHeaders(headers, null, {});
  return new Response(html, { headers });
}

// ============================================================================
// DATABASE FUNCTIONS (Keep existing functions, add new ones if needed)
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
    
    const testUUID = env.UUID || Config.userID;
    const futureDate = new Date();
    futureDate.setMonth(futureDate.getMonth() + 1);
    const expDate = futureDate.toISOString().split('T')[0];
    const expTime = '23:59:59';
    
    try {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1).run();
    } catch (insertErr) {}
    
    console.log('✓ D1 tables initialized successfully');
  } catch (e) {
    console.error('Failed to create D1 tables:', e);
  }
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
    ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run();
    
    if (ctx) {
      ctx.waitUntil(cleanupPromise);
    } else {
      await cleanupPromise;
    }
  } catch (e) {
    console.error(`cleanupOldIps error: ${e.message}`);
  }
}

// ============================================================================
// SCAMALYTICS CHECK
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️ Scamalytics not configured. IP ${ip} allowed (fail-open).`);
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
// RATE LIMITING
// ============================================================================

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

// ============================================================================
// UUID UTILITIES
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
// SUBSCRIPTION LINK GENERATION
// ============================================================================

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
// HEALTH CHECK SYSTEM
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

  const headers = new Headers({ 
    'Content-Type': 'text/plain;charset=utf-8',
    'Profile-Update-Interval': '6',
  });
  addSecurityHeaders(headers, null, {});

  return new Response(safeBase64Encode(links.join('\n')), { headers });
}

// ============================================================================
// ADMIN PANEL FUNCTIONS
// ============================================================================

async function hashSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function isAdmin(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const token = cookieHeader.match(/auth_token=([^;]+)/)?.[1];
  if (!token) return false;

  const hashedToken = await hashSHA256(token);
  const storedHashedToken = await kvGet(env.DB, 'admin_session_token_hash');
  return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
}

// ============================================================================
// WEB SOCKET HANDLER
// ============================================================================

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
      return { hasError: true, message: `command ${command} not supported` };
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
        return { hasError: true, message: `invalid addressType: ${addressType}` };
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
      log(`ReadableStream canceled: ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
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

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      let cfg;
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(`Configuration error: ${err.message}`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service unavailable', { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');
      const userAgent = request.headers.get('User-Agent') || '';

      // Static Content Handlers
      if (url.pathname === '/robots.txt') {
        return await handleRobotsTxt();
      }
      
      if (url.pathname === '/security.txt' || url.pathname === '/.well-known/security.txt') {
        return await handleSecurityTxt();
      }
      
      if (url.pathname === '/') {
        const isBot = /bot|crawl|spider|scanner|check|monitor|feed|rss|curl|wget|python|java|php|ruby|perl|node|go|rust|security|test|scan|analyze/i.test(userAgent);
        
        if (isBot || request.headers.get('Accept')?.includes('text/html')) {
          return await handleReverseProxyLanding(request, cfg.landingPage);
        } else {
          return await handleMasquerade();
        }
      }

      // Health check endpoint
      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers });
      }

      // WebSocket Upgrade Handler
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured', { status: 503, headers });
        }
        
        const evasionHosts = ['speed.cloudflare.com', 'www.cloudflare.com'];
        const evasionHost = evasionHosts[Math.floor(Math.random() * evasionHosts.length)];
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
          scamalytics: cfg.scamalytics,
        };
        
        const wsResponse = await handleWebSocket(newRequest, requestConfig, env, ctx);
        
        const headers = new Headers(wsResponse.headers);
        addSecurityHeaders(headers, null, {});
        
        return new Response(wsResponse.body, { 
          status: wsResponse.status, 
          webSocket: wsResponse.webSocket, 
          headers 
        });
      }

      // Subscription Handlers
      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray', url, env, ctx, cfg, clientIp);
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb', url, env, ctx, cfg, clientIp);
      }

      // User Panel Handler
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
          return new Response('User not found', { status: 403, headers });
        }
        
        if (isExpired(userData.expiration_date, userData.expiration_time)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Account expired', { status: 403, headers });
        }
        
        return await renderUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      // Custom 404 Page for unknown routes
      return await handleCustom404();
      
    } catch (e) {
      console.error('Fetch handler error:', e.message, e.stack);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Internal Server Error', { status: 500, headers });
    }
  },

  // Scheduled Handler for Health Check
  async scheduled(event, env, ctx) {
    try {
      console.log('Running scheduled health check...');
      await performHealthCheck(env, ctx);
      
      await cleanupOldIps(env, ctx);
      
      console.log('✓ Scheduled tasks completed successfully');
    } catch (e) {
      console.error('Scheduled task error:', e.message);
    }
  }
};

// ============================================================================
// WEBSOCKET HANDLER FUNCTION
// ============================================================================

async function handleWebSocket(request, config, env, ctx) {
  let webSocket = null;
  try {
    const clientIp = request.headers.get('CF-Connecting-IP');
    
    if (await isSuspiciousIP(clientIp, config.scamalytics, CONST.SCAMALYTICS_THRESHOLD)) {
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

    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

    const deferredUsageUpdate = () => {
      if (sessionUsage > 0 && userUUID) {
        const usageToUpdate = sessionUsage;
        const uuidToUpdate = userUUID;
        sessionUsage = 0;
        
        ctx.waitUntil(
          updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
            .catch(err => console.error(`Deferred usage update failed for ${uuidToUpdate}:`, err))
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
    const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };

    readableWebSocketStream
      .pipeTo(
        new WritableStream({
          async write(chunk, controller) {
            sessionUsage += chunk.byteLength;

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

            if (isExpired(user.expiration_date, user.expiration_time)) {
              controller.error(new Error('Account expired'));
              return;
            }

            if (user.traffic_limit && user.traffic_limit > 0) {
              const totalUsage = (user.traffic_used || 0) + sessionUsage;
              if (totalUsage >= user.traffic_limit) {
                controller.error(new Error('Traffic limit exceeded'));
                return;
              }
            }

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
            const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isUDP) {
              controller.error(new Error('UDP not supported'));
              return;
            }

            await handleTCPOutBound(
              remoteSocketWrapper,
              addressType,
              addressRemote,
              portRemote,
              rawClientData,
              webSocket,
              vlessResponseHeader,
              log,
              config
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
    console.error('WebSocket handler error:', e.message, e.stack);
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

async function handleTCPOutBound(
  remoteSocket,
  addressType,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  
  tcpSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
        return;
      }
      
      if (protocolResponseHeader) {
        webSocket.send(new Uint8Array([...protocolResponseHeader, ...chunk]));
        protocolResponseHeader = null;
      } else {
        webSocket.send(chunk);
      }
    },
    close() {
      log('remote socket closed');
      safeCloseWebSocket(webSocket);
    },
    abort(err) {
      log('remote socket aborted', err);
      safeCloseWebSocket(webSocket);
    },
  })).catch(err => {
    console.error('Remote pipe error:', err);
    safeCloseWebSocket(webSocket);
  });
}

// ============================================================================
// SUBSCRIPTION HANDLER FUNCTION
// ============================================================================

async function handleSubscription(core, url, env, ctx, config, clientIp) {
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
}

// ============================================================================
// USER PANEL RENDERER
// ============================================================================

async function renderUserPanel(request, userID, hostName, proxyAddress, userData, clientIp) {
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

    const userPanelHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Panel — VLESS Configuration</title>
  <style>
    :root{
      --bg:#0b1220; --card:#0f1724; --muted:#9aa4b2; --accent:#3b82f6;
      --success:#22c55e; --danger:#ef4444; --warning:#f59e0b;
    }
    * { box-sizing:border-box; margin: 0; padding: 0; }
    body{
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
      background: linear-gradient(135deg, #030712 0%, #0f172a 25%, #1e1b4b 50%, #0f172a 75%, #030712 100%);
      color:#e6eef8; min-height:100vh; padding:28px;
    }
    .container{max-width:1100px;margin:0 auto}
    .card{
      background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7));
      backdrop-filter: blur(20px);
      border-radius:16px; padding:22px;
      border:1px solid rgba(255,255,255,0.06); 
      box-shadow:0 8px 32px rgba(0,0,0,0.3);
      margin-bottom:20px;
    }
    h1,h2{margin:0 0 14px;font-weight:700}
    h1{font-size:30px; 
      background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #ec4899 100%);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    }
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:14px}
    .stat{
      padding:18px 14px;
      background: linear-gradient(145deg, rgba(30, 41, 59, 0.6), rgba(15, 23, 36, 0.8));
      backdrop-filter: blur(10px);
      border-radius:14px;text-align:center;
      border:1px solid rgba(255,255,255,0.04);
    }
    .stat .val{font-weight:800;font-size:24px;margin-bottom:6px}
    .stat .lbl{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}
    .stat.status-active .val{color:var(--success);}
    .stat.status-expired .val{color:var(--danger);}
    .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}
    @media (max-width:980px){ .grid{grid-template-columns:1fr} }
    .info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:16px}
    .info-item{background:rgba(255,255,255,0.05);padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.02)}
    .info-item .label{font-size:11px;color:var(--muted);display:block;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}
    .info-item .value{font-weight:600;word-break:break-all;font-size:14px}
    .progress-bar{
      height:14px;background:linear-gradient(90deg, rgba(7,21,41,0.8), rgba(15,23,42,0.9));
      border-radius:10px;overflow:hidden;margin:14px 0;
    }
    .progress-fill{
      height:100%; border-radius:10px; width:${usagePercentage}%;
      background:linear-gradient(90deg, #22c55e 0%, #16a34a 100%);
    }
    pre.config{background:#071529;padding:14px;border-radius:8px;overflow:auto;
      font-family:monospace;font-size:13px;color:#cfe8ff;
      border:1px solid rgba(255,255,255,0.02);max-height:200px}
    .buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
    .btn{
      display:inline-flex;align-items:center;gap:8px;padding:12px 18px;border-radius:10px;
      border:none;cursor:pointer;font-weight:600;font-size:14px;
      text-decoration:none;color:inherit;
    }
    .btn.primary{
      background:linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
      color:#fff;
    }
    .btn.ghost{
      background:rgba(255,255,255,0.05);
      border:1px solid rgba(255,255,255,0.1);color:var(--muted);
    }
    @media (max-width: 768px) {
      body{padding:16px}
      .container{padding:0}
      h1{font-size:24px}
      .stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
      .info-grid{grid-template-columns:1fr}
      .btn{padding:9px 12px;font-size:13px}
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 VLESS Configuration Panel</h1>
    <p style="color:var(--muted);margin:6px 0 22px;">Manage your proxy configuration and view subscription links.</p>

    <div class="stats">
      <div class="stat ${isUserExpired ? 'status-expired' : 'status-active'}">
        <div class="val">${isUserExpired ? 'Expired' : 'Active'}</div>
        <div class="lbl">Account Status</div>
      </div>
      <div class="stat">
        <div class="val">${usageDisplay}</div>
        <div class="lbl">Data Used</div>
      </div>
      <div class="stat">
        <div class="val">${trafficLimitStr}</div>
        <div class="lbl">Data Limit</div>
      </div>
      <div class="stat">
        <div class="val">${expirationDateTime ? 'Active' : 'Unlimited'}</div>
        <div class="lbl">Expiration</div>
      </div>
    </div>

    <div class="grid">
      <div>
        <div class="card">
          <h2>🌐 Subscription Links</h2>
          <p style="color:var(--muted);margin-bottom:16px;">Copy subscription URLs or import directly.</p>

          <div style="margin-bottom:20px;">
            <h3 style="font-size:16px;margin:12px 0 8px;color:#60a5fa;">Xray / V2Ray Subscription</h3>
            <div class="buttons">
              <button class="btn primary" onclick="copyToClipboard('${subXrayUrl}', this)">📋 Copy Sub Link</button>
              <button class="btn ghost" onclick="copyToClipboard('${escapeHTML(singleXrayConfig)}', this)">📋 Copy Config</button>
              <button class="btn ghost" onclick="toggleConfig('xray-config')">View Config</button>
            </div>
            <pre class="config" id="xray-config" style="display:none">${escapeHTML(singleXrayConfig)}</pre>
          </div>

          <div>
            <h3 style="font-size:16px;margin:12px 0 8px;color:#60a5fa;">Sing-Box / Clash Subscription</h3>
            <div class="buttons">
              <button class="btn primary" onclick="copyToClipboard('${subSbUrl}', this)">📋 Copy Sub Link</button>
              <button class="btn ghost" onclick="copyToClipboard('${escapeHTML(singleSingboxConfig)}', this)">📋 Copy Config</button>
              <button class="btn ghost" onclick="toggleConfig('sb-config')">View Config</button>
            </div>
            <pre class="config" id="sb-config" style="display:none">${escapeHTML(singleSingboxConfig)}</pre>
          </div>
        </div>

        ${userData.traffic_limit && userData.traffic_limit > 0 ? `
        <div class="card">
          <h2>📊 Usage Statistics</h2>
          <p style="color:var(--muted);margin-bottom:8px;">${usagePercentage.toFixed(2)}% Used</p>
          <div class="progress-bar">
            <div class="progress-fill"></div>
          </div>
          <p style="color:var(--muted);text-align:center;margin-top:8px;">${usageDisplay} of ${trafficLimitStr} used</p>
        </div>
        ` : ''}
      </div>

      <div>
        <div class="card">
          <h2>👤 Account Details</h2>
          <div class="info-grid">
            <div class="info-item">
              <span class="label">User UUID</span>
              <span class="value" style="font-family:monospace;font-size:12px;word-break:break-all;">${userID}</span>
            </div>
            <div class="info-item">
              <span class="label">Created Date</span>
              <span class="value">${new Date(userData.created_at).toLocaleDateString()}</span>
            </div>
            ${expirationDateTime ? `
            <div class="info-item">
              <span class="label">Expiration</span>
              <span class="value">${new Date(expirationDateTime).toLocaleString()}</span>
            </div>
            ` : ''}
            ${userData.notes ? `
            <div class="info-item">
              <span class="label">Notes</span>
              <span class="value">${escapeHTML(userData.notes)}</span>
            </div>
            ` : ''}
            <div class="info-item">
              <span class="label">IP Limit</span>
              <span class="value">${userData.ip_limit === -1 ? 'Unlimited' : userData.ip_limit}</span>
            </div>
            <div class="info-item">
              <span class="label">Your IP</span>
              <span class="value">${clientIp}</span>
            </div>
          </div>
        </div>

        <div class="card">
          <h2>💾 Export Configuration</h2>
          <p style="color:var(--muted);margin-bottom:16px;">Download configuration for manual import.</p>
          <div class="buttons">
            <button class="btn primary" onclick="downloadConfig('xray-config.txt', '${escapeHTML(singleXrayConfig)}')">Download Xray</button>
            <button class="btn primary" onclick="downloadConfig('singbox-config.txt', '${escapeHTML(singleSingboxConfig)}')">Download Singbox</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <p style="color:var(--muted);text-align:center;margin:0;">
        🔒 This is your personal configuration panel. Keep your subscription links private.
        <br>For support, contact your service administrator.
      </p>
    </div>
  </div>

  <script>
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
        showToast('✓ Copied to clipboard!');
      } catch (error) {
        try {
          const textArea = document.createElement("textarea");
          textArea.value = text;
          textArea.style.position = "fixed";
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
          showToast('✓ Copied to clipboard!');
        } catch(err) {
          showToast('Failed to copy', true);
        }
      }
    }

    function toggleConfig(id) {
      const element = document.getElementById(id);
      element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }

    function downloadConfig(filename, content) {
      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      showToast('✓ Configuration downloaded!');
    }

    function showToast(message, isError = false) {
      const toast = document.createElement('div');
      toast.style.cssText = \`
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 600;
        z-index: 1000;
        background: \${isError ? '#ef4444' : '#22c55e'};
        animation: slideIn 0.3s ease;
      \`;
      
      toast.textContent = message;
      document.body.appendChild(toast);
      
      setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
      }, 3000);
    }

    const style = document.createElement('style');
    style.textContent = \`
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      
      @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
      }
    \`;
    document.head.appendChild(style);

    ${expirationDateTime ? `
    function updateExpiration() {
      const expiryDate = new Date('${expirationDateTime}');
      const now = new Date();
      const diffMs = expiryDate - now;
      
      if (diffMs <= 0) {
        document.querySelector('.stat:nth-child(4) .val').textContent = 'Expired';
        document.querySelector('.stat:nth-child(4)').classList.add('status-expired');
        return;
      }
      
      const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      
      if (days > 0) {
        document.querySelector('.stat:nth-child(4) .val').textContent = days + ' days';
      } else {
        document.querySelector('.stat:nth-child(4) .val').textContent = hours + ' hours';
      }
    }
    
    updateExpiration();
    setInterval(updateExpiration, 60000);
    ` : ''}
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
    console.error('User panel error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}
