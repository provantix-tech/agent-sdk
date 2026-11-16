// Cost tags: reading what a source says about department, cost center, product, project, environment and anything else (PRO-63).
//
// A source states tags in the span attributes (or in `ext.tags` through the SDK). What it said is kept in the record as evidence. What Provantix makes of it
// (which value wins, whether it is on the organization's list) is worked out separately and can be corrected, so it is not part of the sealed record.
//
// Attribute names, first match wins for a dimension:
//   provantix.cost.department | .cost_center | .product | .project | .environment     the five standard dimensions
//   provantix.tag.<key>                                                                 any other dimension, named by the sender
//   deployment.environment.name, then deployment.environment                            the OpenTelemetry resource attribute, for `environment`
//
// Frameworks carry their own metadata on spans, and tags set there are read too, without any setup, when the key is one of the five standard names:
//   langsmith.metadata.<key>                       LangChain traces exported by LangSmith's OpenTelemetry support
//   traceloop.association.properties.<key>         OpenLLMetry (Traceloop)
//   metadata (a JSON object as text) or metadata.<key>   OpenInference instrumentors (LangChain, LlamaIndex and others)
// Any other key in them is a tag only if an admin lists it (the admin list can name `metadata.team`, `langsmith.metadata.team` and so on).
// Written from the projects' published conventions; not yet checked against live exports from each.
export const METADATA_CARRIERS = ['langsmith.metadata.', 'traceloop.association.properties.', 'metadata.'];

/** Attributes with the entries of a JSON `metadata` attribute spread out as `metadata.<key>`, so they can be read like any other attribute. Anything else is left as it is. */
export function expandMetadata(attrs) {
  const raw = attrs?.metadata;
  let obj = null;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) obj = raw;
  else if (typeof raw === 'string' && raw.trim().startsWith('{') && raw.length <= 8192) { try { obj = JSON.parse(raw); } catch { obj = null; } }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return attrs;
  const out = { ...attrs };
  for (const [k, v] of Object.entries(obj)) if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[`metadata.${k}`] = v;
  return out;
}

// Limits keep a faulty source from bloating a record or creating thousands of dimensions. Anything over a limit is counted and shown, never dropped silently.

export const STANDARD_TAG_DIMENSIONS = ['department', 'cost_center', 'product', 'project', 'environment'];
export const TAG_LIMITS = { maxKey: 40, maxValue: 100, maxPerRecord: 20, maxDimensions: 50 };

/** A tag key as a dimension name: lower case, spaces and dashes of any kind become underscores, only letters, digits and _ . - kept. Null if nothing usable is left. */
export function sanitizeTagKey(k) {
  const s = String(k ?? '').trim().toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_.-]/g, '');
  return /^[a-z0-9]/.test(s) && s.length <= TAG_LIMITS.maxKey ? s : null;
}

/** A tag value: a short string. Numbers and booleans are written out; objects, lists and empty values are not tags. */
export function sanitizeTagValue(v) {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') return null;
  const s = String(v).replace(/\s+/g, ' ').trim().slice(0, TAG_LIMITS.maxValue);
  return s === '' ? null : s;
}

/**
 * The tags a span's attributes carry.
 * @param {Record<string, any>} attrs span attributes (resource attributes already merged under them)
 * @param {Record<string, string>|null} extra attribute names an admin listed, each mapped to the tag it means
 * @returns {{ tags: Record<string, string>, over: number }} `over` is how many tags were past the per-record limit and left out
 */
export function tagsFromAttributes(attrs, extra = null) {
  const all = {};
  const put = (key, value) => {
    const k = sanitizeTagKey(key); const v = sanitizeTagValue(value);
    if (k && v !== null && !(k in all)) all[k] = v;
  };
  for (const d of STANDARD_TAG_DIMENSIONS) put(d, attrs?.[`provantix.cost.${d}`]);
  for (const prefix of METADATA_CARRIERS) for (const d of STANDARD_TAG_DIMENSIONS) put(d, attrs?.[`${prefix}${d}`]);
  for (const [name, value] of Object.entries(attrs ?? {})) if (name.startsWith('provantix.tag.')) put(name.slice('provantix.tag.'.length), value);
  if (!('environment' in all)) put('environment', attrs?.['deployment.environment.name'] ?? attrs?.['deployment.environment']);
  // Attribute names an admin listed, because many companies already tag spans their own way: { 'acme.team': 'department' }. The documented names above win over these.
  for (const [name, dimension] of Object.entries(extra ?? {})) put(dimension, attrs?.[name]);
  const keys = Object.keys(all);
  const kept = keys.slice(0, TAG_LIMITS.maxPerRecord);
  return { tags: Object.fromEntries(kept.map((k) => [k, all[k]])), over: keys.length - kept.length };
}

/**
 * The cost tags an imported trace or run carries (Langfuse, LangSmith): what the platform itself says, mapped to Provantix tags.
 * Read without any setup: a metadata key that is one of the five standard names (or provantix.cost.<name>, provantix.tag.<name>), and the platform's own environment.
 * Read only through the admin's mapping (an import job's `tagMap`):
 *   metadata    { sourceKey: tag }        a metadata key to a tag
 *   tagPrefixes { 'dept:': 'department' } a platform tag such as "dept:sales" to a tag, value after the prefix
 *   fields      { userId: tag, sessionId: tag, release: tag, name: tag }   a field of the trace or run to a tag
 * Nothing is guessed: a key nobody mapped is not a tag, and the platform's own tag strings are kept as evidence either way (ext.imported_tags).
 * @returns {Record<string, string>}
 */
export function importedTags({ tags = [], metadata = null, fields = {} } = {}, map = {}) {
  const out = {};
  const put = (k, v) => { const key = sanitizeTagKey(k); const val = sanitizeTagValue(v); if (key && val !== null && !(key in out)) out[key] = val; };
  const meta = metadata && typeof metadata === 'object' && !Array.isArray(metadata) ? metadata : {};
  for (const d of STANDARD_TAG_DIMENSIONS) { put(d, meta[d]); put(d, meta[`provantix.cost.${d}`]); }
  for (const [k, v] of Object.entries(meta)) if (k.startsWith('provantix.tag.')) put(k.slice('provantix.tag.'.length), v);
  put('environment', fields.environment);
  for (const [key, dim] of Object.entries(map.metadata ?? {})) put(dim, meta[key]);
  for (const [prefix, dim] of Object.entries(map.tagPrefixes ?? {})) {
    for (const t of Array.isArray(tags) ? tags : []) if (typeof t === 'string' && prefix && t.startsWith(prefix)) put(dim, t.slice(prefix.length));
  }
  for (const [field, dim] of Object.entries(map.fields ?? {})) put(dim, fields[field]);
  const keys = Object.keys(out);
  return Object.fromEntries(keys.slice(0, TAG_LIMITS.maxPerRecord).map((k) => [k, out[k]]));
}

/** The tags a record's source stated, from its body: `erasable.ext.value.tags` once sealed, or `ext.tags` before. */
export function sourceTagsOf(body) {
  const b = typeof body === 'string' ? safeParse(body) : body;
  const t = b?.erasable?.ext?.value?.tags ?? b?.erasable?.ext?.tags ?? b?.ext?.tags ?? null;
  if (!t || typeof t !== 'object' || Array.isArray(t)) return { tags: {}, over: 0 };
  const out = {};
  for (const [k, v] of Object.entries(t)) { const key = sanitizeTagKey(k); const val = sanitizeTagValue(v); if (key && val !== null && !(key in out)) out[key] = val; }
  const over = Number(b?.erasable?.ext?.value?.tags_over_limit ?? b?.erasable?.ext?.tags_over_limit ?? 0) || 0;
  return { tags: out, over };
}

function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }
