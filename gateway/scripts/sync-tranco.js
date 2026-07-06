#!/usr/bin/env node
/**
 * sync-tranco.js
 *
 * Downloads the latest Tranco top-1M list and writes the top-10k domain names
 * to gateway/config/tranco_top10k.txt (one domain per line).
 *
 * Run manually or via a scheduled task / cron job. Not executed at scan time.
 *
 * Usage:
 *   node scripts/sync-tranco.js [--limit N]
 *
 * Options:
 *   --limit N   Number of domains to keep (default: 10000)
 *
 * Output:
 *   gateway/config/tranco_top10k.txt
 *
 * Tranco is a research-grade top-site list aggregating Alexa, Majestic, Cisco
 * Umbrella and others. Updated daily. No API key required.
 * https://tranco-list.eu/
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// ── Config ─────────────────────────────────────────────────────────────────────
const TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip';
const LIMIT = (() => {
  const idx = process.argv.indexOf('--limit');
  return idx !== -1 ? parseInt(process.argv[idx + 1], 10) : 10000;
})();
const OUT_PATH = path.resolve(__dirname, '../config/tranco_top10k.txt');

// ── Helpers ────────────────────────────────────────────────────────────────────
function log(msg) { process.stdout.write(`[sync-tranco] ${msg}\n`); }
function err(msg)  { process.stderr.write(`[sync-tranco] ERROR: ${msg}\n`); }

// ── Download + unzip + parse in streaming fashion ──────────────────────────────
function httpsGet(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) { reject(new Error('Too many redirects')); return; }
    https.get(url, { headers: { 'User-Agent': 'LinkD-Sync/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        let next = res.headers.location;
        // Resolve relative redirect against the current URL's origin
        if (!next.startsWith('http')) {
          const base = new URL(url);
          next = `${base.protocol}//${base.host}${next.startsWith('/') ? '' : '/'}${next}`;
        }
        log(`Redirect ${res.statusCode} → ${next}`);
        resolve(httpsGet(next, redirectCount + 1));
        return;
      }
      resolve(res);
    }).on('error', reject);
  });
}

async function syncTranco() {
  log(`Downloading Tranco top-1M list from ${TRANCO_URL} …`);

  return new Promise(async (resolve, reject) => {
    let res;
    try { res = await httpsGet(TRANCO_URL); } catch (e) { reject(e); return; }

    if (res.statusCode !== 200) {
      reject(new Error(`HTTP ${res.statusCode} from Tranco`));
      return;
    }

    // Collect the full response buffer (application/zip)
    const chunks = [];
    res.on('data', (chunk) => chunks.push(chunk));
    res.on('error', reject);
    res.on('end', () => {
      const buf = Buffer.concat(chunks);
      log(`Downloaded ${(buf.length / 1024 / 1024).toFixed(1)} MB`);

      let csvText;
      try {
        // Parse ZIP: find the first local file entry (signature 0x04034b50)
        // Local file header: 30 bytes + filename_length + extra_length, then compressed data
        const sig = buf.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
        if (sig === -1) throw new Error('ZIP local file header not found');

        const compression  = buf.readUInt16LE(sig + 8);   // 0=stored, 8=deflated
        const compressedSize   = buf.readUInt32LE(sig + 18);
        const filenameLen  = buf.readUInt16LE(sig + 26);
        const extraLen     = buf.readUInt16LE(sig + 28);
        const dataStart    = sig + 30 + filenameLen + extraLen;
        const compressed   = buf.slice(dataStart, dataStart + compressedSize);

        if (compression === 0) {
          // Stored (no compression)
          csvText = compressed.toString('utf-8');
        } else if (compression === 8) {
          // Deflate — use inflateRaw
          csvText = zlib.inflateRawSync(compressed).toString('utf-8');
        } else {
          throw new Error(`Unsupported ZIP compression method: ${compression}`);
        }
      } catch (e) {
        reject(new Error(`ZIP extraction failed: ${e.message}`));
        return;
      }

      const lines = csvText.split('\n');
      const domains = [];
      for (const line of lines) {
        if (domains.length >= LIMIT) break;
        const parts = line.trim().split(',');
        // CSV format: rank,domain — take second column
        const domain = parts[1];
        if (domain && domain.length > 0) domains.push(domain.toLowerCase());
      }

      log(`Parsed ${domains.length} domains (limit=${LIMIT})`);

      fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
      fs.writeFileSync(OUT_PATH, domains.join('\n') + '\n', 'utf-8');

      log(`✅ Written to ${OUT_PATH}`);
      resolve(domains.length);
    });
  });
}

syncTranco()
  .then((count) => {
    log(`Done. ${count} domains saved.`);
    process.exit(0);
  })
  .catch((e) => {
    err(e.message);
    process.exit(1);
  });
