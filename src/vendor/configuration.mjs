// The configuration a step ran under, as its source reported it (PRO-59): the feature flags a span or an emitter names, each with the flag key and the variant served.
// One definition, used by the hosted intake and vendored into the SDK, so an SDK emitter and an OpenTelemetry span say the same thing the same way.
//
// Read from OpenTelemetry's feature flag attributes: `feature_flag.key`, `feature_flag.result.variant` (older exporters send `feature_flag.variant`) and
// `feature_flag.provider.name` (older: `feature_flag.provider_name`). A flag with no variant is kept with a boolean value only when that is all the source sent;
// other values are not read, because a flag value can be large or sensitive. At most ten, so a source cannot bloat a record. Provantix records what the source said
// it served. It does not know whether the flag was the cause of anything.

export const MAX_FLAGS = 10;
const LIMIT = 100;

/**
 * Add the flag one attribute map (a span's, or one `feature_flag.evaluation` event's) names to `out`.
 * @returns {void}
 */
function fromAttributes(a, out, seen) {
  const flag = a?.['feature_flag.key'];
  if (typeof flag !== 'string' || !flag.trim()) return;
  const raw = a['feature_flag.result.variant'] ?? a['feature_flag.variant'] ?? (typeof a['feature_flag.result.value'] === 'boolean' ? a['feature_flag.result.value'] : null);
  const variant = raw === null || raw === undefined || raw === '' ? null : String(raw).slice(0, LIMIT);
  const provider = a['feature_flag.provider.name'] ?? a['feature_flag.provider_name'] ?? null;
  const id = `${flag}\u0000${variant}`;
  if (seen.has(id) || out.length >= MAX_FLAGS) return;
  seen.add(id);
  out.push({ flag: flag.trim().slice(0, LIMIT), variant, provider: provider ? String(provider).slice(0, LIMIT) : null });
}

/**
 * The configuration a span reports: its own attributes, then the attributes of its `feature_flag.evaluation` events (`span.flagEvents`, already reduced to attribute maps).
 * @returns {{flag: string, variant: string|null, provider: string|null}[]}
 */
export function configurationOf(span) {
  const out = []; const seen = new Set();
  fromAttributes(span?.attributes, out, seen);
  for (const e of span?.flagEvents ?? []) fromAttributes(e, out, seen);
  return out;
}

/**
 * The same, from a span in the shape OpenTelemetry's JavaScript SDK hands an exporter: `attributes` and `events: [{ name, attributes }]`.
 * Only events named `feature_flag.evaluation` are read.
 */
export function configurationOfOtelSpan(span) {
  return configurationOf({
    attributes: span?.attributes ?? {},
    flagEvents: (Array.isArray(span?.events) ? span.events : []).filter((e) => e?.name === 'feature_flag.evaluation').map((e) => e.attributes ?? {}),
  });
}

/**
 * Check and clean a configuration an emitter states directly: `[{ flag, variant, provider? }]`. A variant is a string, a number or a boolean (kept as text); nothing
 * else, because a value can be large or sensitive. Throws with a message that names the problem, so a wrong call is found when it is written, not in the dashboard.
 * @returns {{flag: string, variant: string|null, provider: string|null}[]}
 */
export function normaliseConfiguration(list) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new TypeError('configuration must be a list: [{ flag, variant, provider? }]');
  if (list.length > MAX_FLAGS) throw new RangeError(`configuration holds at most ${MAX_FLAGS} flags per step`);
  const out = []; const seen = new Set();
  for (const [i, e] of list.entries()) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) throw new TypeError(`configuration[${i}] must be an object: { flag, variant, provider? }`);
    for (const k of Object.keys(e)) if (!['flag', 'variant', 'provider'].includes(k)) throw new TypeError(`configuration[${i}]: "${k}" is not a field. Use flag, variant and provider`);
    if (typeof e.flag !== 'string' || !e.flag.trim()) throw new TypeError(`configuration[${i}].flag is required: the flag key, as a string`);
    const v = e.variant;
    if (v !== undefined && v !== null && !['string', 'number', 'boolean'].includes(typeof v)) throw new TypeError(`configuration[${i}].variant must be a string, a number or a boolean`);
    if (typeof v === 'number' && !Number.isFinite(v)) throw new TypeError(`configuration[${i}].variant must be a finite number`);
    if (e.provider !== undefined && e.provider !== null && typeof e.provider !== 'string') throw new TypeError(`configuration[${i}].provider must be a string`);
    const variant = v === undefined || v === null || v === '' ? null : String(v).slice(0, LIMIT);
    const id = `${e.flag.trim()}\u0000${variant}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ flag: e.flag.trim().slice(0, LIMIT), variant, provider: e.provider ? String(e.provider).slice(0, LIMIT) : null });
  }
  return out;
}
