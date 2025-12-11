# EdgeTunnel - Cloudflare VLESS Proxy Worker

## Overview
This is a Cloudflare Workers project that runs a VLESS proxy server on Cloudflare's edge network. It provides a web-based management panel and proxy configuration generation.

## Project Structure
- `index.js` - Main worker code (readable format)
- `_worker.js` - Minified worker code (for Pages deployment)
- `wrangler.toml` - Cloudflare Wrangler configuration
- `package.json` - Node.js dependencies

## Development
The project uses Cloudflare Wrangler for local development:
```bash
npx wrangler dev --port 5000 --ip 0.0.0.0
```

## Configuration
Environment variables in `wrangler.toml`:
- `UUID` - Unique user identifier for authentication
- `PROXYIP` - Proxy IP address for fronting
- `ADMIN_KEY` - Admin panel password

## Access
- User Panel: `/{YOUR_UUID}`
- Admin Panel: `/admin/{ADMIN_KEY}`
- Default UUID: `d342d11e-d424-4583-b36e-524ab1f0afa4`
- Default Admin Key: `admin123`

## Recent Changes (December 2025)

### Latest Fixes (December 11, 2025)
- **Wrangler v4 Upgrade**: Updated from v3.114.15 to v4.54.0 with compatibility date 2024-12-01
- **QR Code Generator Enhancement**:
  - 3-tier fallback system: Embedded/Local FIRST → CDN fallback → Google Charts API
  - Embedded generator works offline without external resources
  - Updated CSP headers to allow cdnjs.cloudflare.com, unpkg.com, and chart.googleapis.com
  - Cross-Origin-Embedder-Policy set to 'unsafe-none' for external image loading
  - Increased QR code capacity (typeNumber 10 instead of 5) for longer VLESS URLs
  - Smart error handling with user-friendly toast notifications
  - Better error handling for complex configurations
- **Admin Panel Enhancements**:
  - Added CSV Export button for exporting user data with proper escaping
  - Added real-time Server Time display card with 1-second updates
- **Geo-Location Detection Improvements**:
  - Added 3-second timeout for all geo API calls
  - Added more fallback providers (ipinfo.io, freeipapi.com)
  - Uses Cloudflare CF headers as primary source
  - Returns fallback "Global" location if all APIs fail
- **Admin Panel Proxy Health**:
  - Fixed health display to show proper Healthy/Unhealthy states
  - Added null checks for DOM elements
  - Proper initialization on page load
- **Data Limit Input Visibility**:
  - Fixed flex layout with proper min-width values
  - Input field now fully visible with dropdown
- **User Panel Auto-Refresh**:
  - Added 30-second auto-refresh for user statistics
  - Real-time traffic usage updates
  - Dynamic connection history display
- **Analytics/History Tabs**:
  - Enhanced tab functionality with proper content switching
  - History tab shows session data with formatted timestamps

### UI/UX Improvements
- **User Panel Redesign**: Modern dark theme with glassmorphism effects
  - Live Traffic widget with animated graph (download/upload speeds)
  - Connection Health card showing latency, uptime, and stability meter
  - Network Statistics with colorful icons (latency, jitter, packets in/out)
  - Analytics section with tab-based interface (Analytics/History)
  - Account status cards (Status, Data Used, Data Limit, Time Remaining)
- **Admin Panel Enhancements**: 
  - Enhanced glassmorphism effects
  - Proxy Health and Server Status cards with pulsing indicators
  - Improved table styling with sticky headers
  - Toast notifications with icons and animations

### Bug Fixes
- Fixed critical syntax error (duplicate formatBytes function on line 1503)
- Fixed D1 database binding issues
- Added automatic test user creation for development environment
- **User Panel Button Fixes (December 2025)**:
  - Migrated from inline onclick handlers to event delegation pattern
  - Fixed JavaScript string escaping using JSON.stringify for window.CONFIG
  - QR Code, Copy Link, Download Config, View Config buttons now work correctly
- **Admin Panel Proxy Health Fix**:
  - `/api/stats` endpoint now returns proxy health data from database
  - `fetchStats()` function calls `updateProxyHealth()` to update status
  - Proxy Health card no longer stuck on "Checking..."
- **User API Endpoints Added**:
  - `/api/user/:uuid` - Returns user data (traffic, expiry, limits)
  - `/api/user/:uuid/analytics` - Returns analytics data
  - `/api/user/:uuid/history` - Returns 7-day usage history

### Database
- D1 database binding configured for local development
- Tables: users, user_ips, key_value, proxy_health
- Test user automatically created on startup

## Design Specifications
- Dark gradient theme: #0b1220 to #071323
- Card background: #0f1724
- Accent colors:
  - Blue: #3b82f6
  - Green: #22c55e
  - Orange: #f59e0b
  - Red: #ef4444
  - Purple: #a855f7

## Notes
- D1 database is simulated locally via Miniflare
- Connection configurations remain unchanged
- All proxy and WebSocket functionality preserved
