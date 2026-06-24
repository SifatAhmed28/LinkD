const cheerio = require('cheerio');

/**
 * Parses raw HTML using Cheerio and extracts structured elements
 * relevant to phishing detection.
 *
 * @param {string} html - Raw HTML string
 * @returns {Object} Extracted elements
 */
function parseHtml(html) {
  const $ = cheerio.load(html);

  // ── Anchor Links ─────────────────────────────────────────────
  const anchors = [];
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href') || '';
    const text = $(el).text().trim();
    if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
      anchors.push({ href, text });
    }
  });

  // ── Forms ─────────────────────────────────────────────────────
  const forms = [];
  $('form').each((_, el) => {
    const action = $(el).attr('action') || '';
    const method = ($(el).attr('method') || 'get').toLowerCase();
    const inputs = [];
    $(el).find('input').each((__, inp) => {
      inputs.push({
        type: $(inp).attr('type') || 'text',
        name: $(inp).attr('name') || '',
        id: $(inp).attr('id') || '',
      });
    });
    forms.push({ action, method, inputs });
  });

  // ── Password Inputs (anywhere in document) ────────────────────
  const passwordInputs = [];
  $('input[type="password"]').each((_, el) => {
    passwordInputs.push({
      name: $(el).attr('name') || '',
      id: $(el).attr('id') || '',
      placeholder: $(el).attr('placeholder') || '',
    });
  });

  // ── Image Alt Text ────────────────────────────────────────────
  const imageAlts = [];
  $('img[alt]').each((_, el) => {
    const alt = $(el).attr('alt')?.trim();
    if (alt) imageAlts.push(alt);
  });

  // ── Visible Text ──────────────────────────────────────────────
  // Remove scripts, styles, comments
  $('script, style, noscript').remove();
  const visibleText = $('body').text().replace(/\s+/g, ' ').trim();

  // ── Meta ──────────────────────────────────────────────────────
  const title = $('title').text().trim();
  const metaDescription = $('meta[name="description"]').attr('content') || '';

  return {
    anchors,
    forms,
    passwordInputs,
    imageAlts,
    visibleText,
    title,
    metaDescription,
    hasPasswordInput: passwordInputs.length > 0,
    hasForm: forms.length > 0,
  };
}

module.exports = { parseHtml };
