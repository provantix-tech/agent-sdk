// Redaction profile applied inside the customer's collector before any text leaves.
// Spec: plan/02-data-model.md section 6 (profile default-v1). Rules are conservative:
// they replace, never keep, anything that looks like a credential or personal identifier.

export const REDACTION_PROFILE_ID = 'default-v1';

function luhnValid(digits) {
  const d = digits.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

const RULES = [
  {
    name: 'secret',
    re: /\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    replace: () => '<secret>',
  },
  {
    name: 'email',
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    replace: () => '<email>',
  },
  {
    name: 'iban',
    re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}\b/g,
    replace: () => '<iban>',
  },
  {
    name: 'pan',
    re: /\b(?:\d[ -]?){13,19}\b/g,
    replace: (m) => (luhnValid(m) ? '<pan>' : null),
  },
  {
    name: 'phone',
    re: /\+\d{1,3}[\s()-]?\d[\d\s()-]{6,}\d/g,
    replace: () => '<phone>',
  },
];

/**
 * Cap for stored text summaries (tool arguments, results). 2 KB matches the hosted
 * intake attribute cap (P3): stored content is a redacted excerpt for the drawer and
 * the export, never the full payload.
 */
export const SUMMARY_MAX_CHARS = 2000;

/**
 * @param {string|null} text
 * @param {object} [opts]
 * @param {number|null} [opts.maxLength] cap in characters; null means no cap
 * @returns {{text: string|null, counts: Record<string, number>, truncated: boolean}}
 */
export function redact(text, { maxLength = null } = {}) {
  const counts = {};
  if (text === null || text === undefined) return { text: null, counts, truncated: false };
  if (typeof text !== 'string') throw new TypeError('redact: text must be a string or null');
  let out = text;
  for (const rule of RULES) {
    out = out.replace(rule.re, (m) => {
      const r = rule.replace(m);
      if (r === null) return m;
      counts[rule.name] = (counts[rule.name] ?? 0) + 1;
      return r;
    });
  }
  let truncated = false;
  if (maxLength !== null && out.length > maxLength) {
    out = `${out.slice(0, maxLength)} …[truncated]`;
    truncated = true;
  }
  return { text: out, counts, truncated };
}

// Redact every string inside a JSON-compatible value, keeping its shape.
export function redactDeep(value, { maxLength = null } = {}) {
  const counts = {};
  let truncated = false;
  const add = (c) => {
    for (const [k, v] of Object.entries(c)) counts[k] = (counts[k] ?? 0) + v;
  };
  const walk = (v) => {
    if (typeof v === 'string') {
      const r = redact(v, { maxLength });
      add(r.counts);
      if (r.truncated) truncated = true;
      return r.text;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = {};
      for (const k of Object.keys(v)) o[k] = walk(v[k]);
      return o;
    }
    return v;
  };
  return { value: walk(value), counts, truncated };
}

// P3: derive record data classes from redaction rule hits. The mapping is deterministic
// and lives next to the rules so a new rule name forces an explicit decision here.
const RULE_TO_DATA_CLASS = {
  secret: 'secret',
  email: 'pii',
  phone: 'pii',
  pan: 'pci',
  iban: 'financial',
};

/**
 * @param {Record<string, number>} counts redaction rule hit counts
 * @returns {string[]} sorted, de-duplicated data class names
 */
export function dataClassesFromCounts(counts) {
  const classes = new Set();
  for (const [rule, n] of Object.entries(counts ?? {})) {
    if (n > 0 && RULE_TO_DATA_CLASS[rule]) classes.add(RULE_TO_DATA_CLASS[rule]);
  }
  return [...classes].sort();
}
