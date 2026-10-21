// Canonical JSON used for every hash in the ledger.
// Rules (see plan/02-data-model.md section 1.3):
//   - object keys sorted at every depth
//   - no insignificant whitespace
//   - UTF-8 strings via JSON string escaping
//   - numbers must be finite; shortest round-trip form (JS default)
//   - null is kept; undefined is rejected (absence must be explicit)

export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError('canonicalize: non-finite number');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
      }
      const keys = Object.keys(value).sort();
      const parts = [];
      for (const k of keys) {
        const v = value[k];
        if (v === undefined) {
          throw new TypeError(`canonicalize: undefined at key "${k}"`);
        }
        parts.push(JSON.stringify(k) + ':' + canonicalize(v));
      }
      return '{' + parts.join(',') + '}';
    }
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof value}`);
  }
}
