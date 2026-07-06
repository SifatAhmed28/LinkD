#!/usr/bin/env node
/**
 * sync-blocklist.js
 *
 * Fetches the OpenPhish community feed (and optionally the PhishTank verified
 * feed) and writes a deduplicated hash-set to gateway/config/phishing_blocklist.json.
 *
 * Run on a schedule (e.g. every 6 hours via Task Scheduler / cron) to keep
 * the in-memory blocklist fresh. Never executed at scan time.
 *
 * Usage:
 *   node scripts/sync-blocklist.js [--phishtank-key YOUR_KEY]
 *
 * Environment variables (alternative to CLI flags):
 *   PHISHTANK_API_KEY   — PhishTank app key (optional; omit to use OpenPhish only)
 *
 * Output:
 *   gateway/config/phishing_blocklist.json
 *   { "updated": "ISO8601", "count": N, "urls": ["sha256hex", ...] }
 *
 * Notes:
 *   • URL hashes (SHA-256) are stored instead of raw URLs to reduce the file
 *     size and avoid shipping a ready-made phishing URL list in the repo.
 *   • blocklist.js performs the same hash on scan-time URLs and checks for membership.
 */

const https = require('https');
const http  = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URLSearchParams } = require('url');

// ── Config ─────────────────────────────────────────────────────────────────────
const OUT_PATH = path.resolve(__dirname, '../config/phishing_blocklist.json');
const OPENPHISH_URL = 'https://openphish.com/feed.txt';
const PHISHTANK_URL = 'https://data.phishtank.com/data/%KEY%/online-valid.csv';

const PHISHTANK_KEY = (() => {
  const idx = process.argv.indexOf('--phishtank-key');
  return idx !== -1 ? process.argv[idx + 1] : (process.env.PHISHTANK_API_KEY || null);
})();

// ── Helpers ────────────────────────────────────────────────────────────────────
function log(msg) { process.stdout.write(`[sync-blocklist] ${msg}\n`); }
function err(msg)  { process.stderr.write(`[sync-blocklist] ERROR: ${msg}\n`); }

function hashUrl(url) {
  return crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex');
}

function fetchText(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) { reject(new Error('Too many redirects')); return; }
    const lib = url.startsWith('https') ? https : http;
    lib.get(url, { headers: { 'User-Agent': 'LinkD-Blocklist-Sync/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        let next = res.headers.location;
        if (!next.startsWith('http')) {
          const base = new URL(url);
          next = `${base.protocol}//${base.host}${next.startsWith('/') ? '' : '/'}${next}`;
        }
        res.resume(); // drain the redirect response
        resolve(fetchText(next, redirectCount + 1));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      res.on('error', reject);
    }).on('error', reject);
  });
}

// ── Fetch sources ─────────────────────────────────────────────────────────────
async function fetchOpenPhish() {
  log('Fetching OpenPhish community feed …');
  try {
    const text = await fetchText(OPENPHISH_URL);
    const urls = text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('http'));
    log(`OpenPhish: ${urls.length} URLs`);
    return urls;
  } catch (e) {
    err(`OpenPhish fetch failed: ${e.message}`);
    return [];
  }
}

async function fetchPhishTank(key) {
  if (!key) return [];
  log('Fetching PhishTank verified feed …');
  try {
    const url = PHISHTANK_URL.replace('%KEY%', key);
    const csv = await fetchText(url);
    // CSV columns: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
    const urls = csv
      .split('\n')
      .slice(1) // skip header
      .map((l) => l.split(',')[1]?.replace(/^"|"$/g, '').trim())
      .filter((u) => u && u.startsWith('http'));
    log(`PhishTank: ${urls.length} URLs`);
    return urls;
  } catch (e) {
    err(`PhishTank fetch failed: ${e.message}`);
    return [];
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function sync() {
  const [openPhishUrls, phishTankUrls] = await Promise.all([
    fetchOpenPhish(),
    fetchPhishTank(PHISHTANK_KEY),
  ]);

  const allUrls = [...new Set([...openPhishUrls, ...phishTankUrls])];
  const hashes  = [...new Set(allUrls.map(hashUrl))];

  log(`Total unique URLs: ${allUrls.length} → ${hashes.length} unique hashes`);

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify({
    updated: new Date().toISOString(),
    count:   hashes.length,
    hashes,
  }, null, 2), 'utf-8');

  log(`✅ Written to ${OUT_PATH}`);
  return hashes.length;
}

sync()
  .then((count) => { log(`Done. ${count} hashes saved.`); process.exit(0); })
  .catch((e)    => { err(e.message); process.exit(1); });
