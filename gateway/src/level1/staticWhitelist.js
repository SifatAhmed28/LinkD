const axios = require('axios');
const logger = require('../utils/logger');

const API_URL = 'https://whitelist.freehosting.dev/check.php';

// Common wildcard hosting platforms where subdomains should NOT be auto-trusted
const WILDCARD_HOSTING = new Set([
  // Git hosting
  'github.io',
  'gitlab.io',
  'bitbucket.io',

  // Vercel / Netlify / Cloudflare
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',

  // Firebase / Google
  'firebaseapp.com',
  'web.app',

  // Microsoft
  'azurewebsites.net',
  'azurestaticapps.net',
  'cloudapp.net',

  // AWS
  'amazonaws.com',
  'elasticbeanstalk.com',
  'amplifyapp.com',

  // Oracle / IBM / SAP
  'oraclecloud.com',
  'mybluemix.net',
  'ondigitalocean.app',

  // Railway / Render / Fly
  'onrender.com',
  'railway.app',
  'fly.dev',
  'fly.io',

  // Heroku
  'herokuapp.com',
  'herokudns.com',

  // DigitalOcean
  'ondigitalocean.app',

  // Glitch / Replit / Codespaces
  'glitch.me',
  'replit.app',
  'repl.co',
  'replit.dev',
  'githubpreview.dev',

  // Cloud IDEs
  'gitpod.io',
  'codesandbox.io',
  'stackblitz.io',

  // Surge / Static hosting
  'surge.sh',
  'pages.fm',
  'tiiny.site',

  // InfinityFree / Free hosting
  'epizy.com',
  'rf.gd',
  '42web.io',
  'infy.uk',
  'free.nf',

  // 000webhost
  '000webhostapp.com',

  // Blogger / Wordpress
  'blogspot.com',
  'wordpress.com',

  // Wix / Weebly / Squarespace
  'wixsite.com',
  'weebly.com',
  'square.site',

  // Google Sites
  'sites.google.com',

  // Notion
  'notion.site',

  // Carrd
  'carrd.co',

  // Tilda
  'tilda.ws',

  // ReadTheDocs
  'readthedocs.io',

  // GitBook
  'gitbook.io',

  // Shopify previews
  'myshopify.com',

  // Tumblr
  'tumblr.com',

  // Medium
  'medium.com',

  // Substack
  'substack.com',

  // Ghost
  'ghost.io',

  // Webflow
  'webflow.io',

  // Bubble
  'bubbleapps.io',

  // Softr
  'softr.app',

  // Framer
  'framer.website',
  'framer.app',

  // Typedream
  'typedream.app',

  // Webnode
  'webnode.page',

  // Strikingly
  'mystrikingly.com',

  // Jimdo
  'jimdosite.com',

  // Cargo
  'cargo.site',

  // Neocities
  'neocities.org',

  // Glitch
  'glitch.global',

  // Pantheon
  'pantheonsite.io',

  // Kinsta
  'kinsta.cloud',

  // Render previews
  'onrender.com',

  // Cloudflare Pages
  'pages.dev',

  // Zeabur
  'zeabur.app',

  // Northflank
  'northflank.app',

  // Cyclic
  'cyclic.app',

  // Deno Deploy
  'deno.dev',

  // EdgeOne Pages
  'edgeone.app',

  // IPFS gateways
  'ipfs.dweb.link',
  'ipfs.cf-ipfs.com',

  // LocalTunnel / ngrok-like
  'loca.lt',
  'serveo.net',
  'trycloudflare.com',
  'ngrok-free.app',

  // DuckDNS
  'duckdns.org',

  // No-IP
  'ddns.net',
  'hopto.org',
  'zapto.org',
  'serveftp.net',
  'sytes.net',

  // Dynu
  'dynu.net',

  // Freedns
  'mywire.org',
  'mooo.com',

  // DynDNS
  'dyndns.org',
  'homeip.net',

  // DuckDNS alternatives
  'duckdns.info',

  // Hoppy
  'hoppy.jp',

  // PageXL
  'pagexl.com',

  // Yolasite
  'yolasite.com',

  // Hostinger Horizons
  'hstgr.io',

  // Netlify aliases
  'netlify.live',

  // Cloud66
  'cloud66.ws',

  // EasyWP
  'easywp.com',

  // Zoho Sites
  'zohosites.com',

  // Google App Engine
  'appspot.com',

  // PythonAnywhere
  'pythonanywhere.com',

  // AlwaysData
  'alwaysdata.net',

  // AwardSpace
  'awardspace.info',

  // Altervista
  'altervista.org',

  // ByetHost
  'byethost.com',

  // Hostinger free
  'hostingerapp.com',

  // Infinity mirrors
  'lovestoblog.com',
  'great-site.net',

  // Misc
  'dev.to',
  'hashnode.dev',
  'hashnode.com',
  'codeberg.page',
  'sourcehut.io'
]);

/**
 * Dynamic Whitelist with Subdomain Awareness
 */
async function trustScore(hostname, registeredDomain) {
  const domainToCheck = registeredDomain || hostname;

  try {
    const TEST_COOKIE = process.env.INFINITYFREE_TEST_COOKIE;
    const response = await axios.get(API_URL, {
      params: { name: domainToCheck },
      timeout: 6000,
      headers: {
        "User-Agent": "Google Chrome/11",
        Cookie: `__test=${TEST_COOKIE}`,
        "Accept": "application/json, text/plain, */*"
      }
    });

    const data = response.data;

    logger.info(`Whitelist response: ${JSON.stringify(response.data)}`);
    logger.info(JSON.stringify(response.config.headers, null, 2));

    if (data.exists === true) {
      // Check if this is a dangerous wildcard hosting domain
      if (WILDCARD_HOSTING.has(domainToCheck)) {
        logger.info(`⚠️  Wildcard hosting domain detected: ${domainToCheck} — sending to L2`);
        return {
          fastPath: false,
          whitelistPartialMatch: true,   // Important flag
          isWildcardHosting: true,
        };
      }

      // Normal trusted domain (e.g. google.com, microsoft.com)
      logger.info(`✅ Dynamic Whitelist HIT: ${domainToCheck}`);
      return {
        fastPath: true,
        whitelistPartialMatch: false,
      };
    } else {
      return {
        fastPath: false,
        whitelistPartialMatch: false,
      };
    }
  } catch (error) {
    logger.warn(`Whitelist API error for ${domainToCheck}: ${error.message}`);
    return {
      fastPath: false,
      whitelistPartialMatch: false,
    };
  }
}

module.exports = { trustScore };