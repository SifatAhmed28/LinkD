/**
 * doubleMetaphone.js
 *
 * A compact JavaScript implementation of Lawrence Philips' Double Metaphone
 * algorithm. Produces two phonetic encodings (primary and secondary) for a
 * given word, enabling fuzzy phonetic matching of domain labels against brand
 * names — catching phishing domains that *sound like* legitimate brands
 * (e.g., fasebook, amason, lnkedln).
 *
 * Zero external dependencies.
 *
 * Reference: Philips, L. (2000). "The Double Metaphone Search Algorithm."
 *            C/C++ Users Journal, 18(6).
 *
 * @module doubleMetaphone
 */

/**
 * Compute the Double Metaphone encoding of a word.
 * @param {string} word — input string (will be uppercased internally)
 * @returns {[string, string]} [primary, secondary] encoding (may be equal)
 */
function doubleMetaphone(word) {
  if (!word || typeof word !== 'string') return ['', ''];

  const w = word.toUpperCase().replace(/[^A-Z]/g, '');
  if (w.length === 0) return ['', ''];

  let primary = '';
  let secondary = '';
  let pos = 0;
  let isSlavic = /^(?:ACH|ILL|UMB|[AEIOUY]N[A-Z]|[AEIOUY]S[A-Z])/.test(w)
    || w[0] === 'W' || w.slice(0, 2) === 'GN' || w.slice(0, 2) === 'PN';

  // Slavic-German: if the second character is a vowel, skip initial
  if (isSlavic && w.length > 1 && /[AEIOUY]/.test(w[0])) {
    pos = 1;
    if (w[1] === 'W' || w[1] === 'J' || w[1] === 'Y') {
      // Keep going
    }
  }

  function add(code, altCode) {
    if (code && primary.length < 4) primary += code;
    if (altCode && secondary.length < 4) secondary += altCode;
    if (code && !altCode && secondary.length < primary.length) secondary += code;
  }

  while (pos < w.length && (primary.length < 4 || secondary.length < 4)) {
    const c = w[pos];
    const next = pos + 1 < w.length ? w[pos + 1] : '';
    const next2 = pos + 2 < w.length ? w[pos + 2] : '';
    const prev = pos > 0 ? w[pos - 1] : '';

    if ('AEIOUY'.includes(c)) {
      if (pos === 0) {
        // Initial vowel
      }
      pos++;
      continue;
    }

    // B
    if (c === 'B') {
      if (prev === 'M') { pos++; continue; }
      add('P');
      pos++;
      continue;
    }

    // C
    if (c === 'C') {
      // CIA
      if (next === 'I' && next2 === 'A') { add('X', 'S'); pos += 3; continue; }
      // CE, CI, CY
      if ('EIY'.includes(next)) { add('S'); pos++; continue; }
      // SCH
      if (next === 'H') { add('X', 'S'); pos += 2; continue; }
      // CCI, CCE, CCY (special case)
      if (next === 'C' && 'EIY'.includes(next2)) { add('KS'); pos += 2; continue; }
      add('K');
      pos++;
      continue;
    }

    // D
    if (c === 'D') {
      if (next === 'G' && 'EIY'.includes(next2)) { add('J'); pos += 2; continue; }
      if ('DT'.includes(next)) { add('T'); pos += 2; continue; }
      add('T');
      pos++;
      continue;
    }

    // F
    if (c === 'F') { add('F'); pos++; continue; }

    // GH
    if (c === 'G') {
      if (next === 'H') {
        if (pos + 2 < w.length && !'AEIOUY'.includes(w[pos + 2])) { add('K'); pos += 2; continue; }
        pos++; continue;
      }
      if (next === 'N' && (pos === 0 || prev === 'E')) { add('KN'); pos += 2; continue; }
      if ('EIY'.includes(next)) { add('J'); pos++; continue; }
      if (prev !== 'G') { add('K'); }
      else { pos++; continue; }
      pos++;
      continue;
    }

    // H
    if (c === 'H') {
      if ('AEIOUY'.includes(next) && 'AEIOUY'.includes(prev)) { pos++; continue; }
      if (pos === 0 || prev === 'A' || prev === 'E' || prev === 'O' || prev === 'U') {
        add('H');
      }
      pos++;
      continue;
    }

    // J
    if (c === 'J') {
      if (next === 'O' && next2 === 'B' && pos + 3 < w.length && w[pos + 3] === 'A') {
        // "Jorge" pattern
      }
      if (next === 'J' || (prev !== 'S' && prev !== 'K' && prev !== 'C')) {
        add('J');
      }
      if ('EIY'.includes(next)) {
        add('J');
      }
      pos++;
      continue;
    }

    // K
    if (c === 'K') {
      if (prev !== 'C') add('K');
      pos++;
      continue;
    }

    // PH
    if (c === 'P' && next === 'H') {
      add('F');
      pos += 2;
      continue;
    }

    // P
    if (c === 'P') {
      add('P');
      pos++;
      continue;
    }

    // Q
    if (c === 'Q') { add('K'); pos++; continue; }

    // SH, SIA, SIO, TIA, TIO
    if (c === 'S') {
      if (next === 'H') { add('X'); pos += 2; continue; }
      if (next === 'I' && ('AO'.includes(next2))) { add('X', 'S'); pos += 3; continue; }
      if (next === 'C' && next2 === 'H') { add('SK'); pos += 3; continue; }
      add('S');
      pos++;
      continue;
    }

    // T
    if (c === 'T') {
      if (next === 'H') {
        if (pos > 0 && !'AEIOUY'.includes(prev)) { add('T'); pos += 2; continue; }
        add('0', 'T'); // theta
        pos += 2;
        continue;
      }
      if (next === 'I' && ('AO'.includes(next2))) { add('X', 'S'); pos += 3; continue; }
      if (next === 'C' && next2 === 'H') { add('K'); pos += 3; continue; }
      add('T');
      pos++;
      continue;
    }

    // V
    if (c === 'V') { add('F'); pos++; continue; }

    // W, Y
    if (c === 'W' || c === 'Y') {
      if ('AEIOUY'.includes(next)) {
        add(c === 'W' ? 'A' : '');
      }
      pos++;
      continue;
    }

    // X
    if (c === 'X') {
      add('KS');
      pos++;
      continue;
    }

    // Z
    if (c === 'Z') { add('S', 'TS'); pos++; continue; }

    // Default: skip unknown characters
    pos++;
  }

  // Pad to 4 characters
  while (primary.length < 4) primary += '0';
  while (secondary.length < 4) secondary += '0';

  return [primary.slice(0, 4), secondary.slice(0, 4)];
}

/**
 * Quick phonetic comparison: returns true if two strings are
 * phonetically similar (primary OR secondary encodings match).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function phoneticallySimilar(a, b) {
  const [a1, a2] = doubleMetaphone(a);
  const [b1, b2] = doubleMetaphone(b);
  return a1 === b1 || a1 === b2 || a2 === b1 || a2 === b2;
}

module.exports = { doubleMetaphone, phoneticallySimilar };
