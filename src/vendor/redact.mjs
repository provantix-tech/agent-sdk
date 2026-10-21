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
 * @returns {{text: string|null, counts: Record<string, number>}}
 */
export function redact(text) {
  const counts = {};
  if (text === null || text === undefined) return { text: null, counts };
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
  return { text: out, counts };
}

// Redact every string inside a JSON-compatible value, keeping its shape.
export function redactDeep(value) {
  const counts = {};
  const add = (c) => {
    for (const [k, v] of Object.entries(c)) counts[k] = (counts[k] ?? 0) + v;
  };
  const walk = (v) => {
    if (typeof v === 'string') {
      const r = redact(v);
      add(r.counts);
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
  return { value: walk(value), counts };
}
