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

  // ── Meta ──────────────────────────────────────────────────────
  const title = $('title').text().trim();
  const metaDescription = $('meta[name="description"]').attr('content') || '';

  // ── Phishing-Kit Fingerprints ────────────────────────────────────────
  // Extract inline scripts BEFORE removing them from the DOM
  const inlineScripts = [];
  $('script:not([src])').each((_, el) => {
    inlineScripts.push($(el).html() || '');
  });
  const allScriptText = inlineScripts.join('\n');

  const htmlNumEvalCalls = (allScriptText.match(/\beval\s*\(/g) || []).length;
  const htmlNumUnescapeCalls = (allScriptText.match(/\b(?:unescape|decodeURIComponent)\s*\(/g) || []).length;

  // ── Visible Text ───────────────────────────────────────────
  // Strip scripts/styles to isolate user-facing text
  $('script, style, noscript').remove();
  const visibleText = $('body').text().replace(/\s+/g, ' ').trim();

  // Right-click disabled (common anti-inspection kit behavior)
  const htmlHasRightClickDisabled =
    /oncontextmenu\s*=\s*["'][^"']*return\s+false/i.test(html) ||
    allScriptText.includes('oncontextmenu') && /return\s+false/i.test(allScriptText);

  // Form action pointing nowhere or to blank page
  let sfhIsEmpty = false;
  let sfhIsAboutBlank = false;
  for (const form of forms) {
    if (!form.action || form.action.trim() === '' || form.action.trim() === '#') sfhIsEmpty = true;
    if (form.action.trim().toLowerCase() === 'about:blank') sfhIsAboutBlank = true;
  }

  // Favicon presence (legitimate sites almost always have one)
  const htmlHasFavicon = $('link[rel~="icon"], link[rel="shortcut icon"]').length > 0;

  // Hidden input count (exfiltration via hidden fields)
  const htmlNumHiddenInputs = $('input[type="hidden"]').length;

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
    // Phishing-kit fingerprints
    html_num_eval_calls:          htmlNumEvalCalls,
    html_num_unescape_calls:      htmlNumUnescapeCalls,
    html_has_right_click_disabled: htmlHasRightClickDisabled,
    sfh_is_empty:                 sfhIsEmpty,
    sfh_is_about_blank:           sfhIsAboutBlank,
    html_has_favicon:             htmlHasFavicon,
    html_num_hidden_inputs:       htmlNumHiddenInputs,
  };
}

module.exports = { parseHtml };
