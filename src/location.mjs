// Where an emitter runs and what it acts on, kept as short codes (SDK 0.3.0; plan/26 in the Provantix repo).
//
// Only provider, region, zone and country are kept, each with how it is known. A city, an address or free text is
// dropped, and the platform refuses a record that carries more. This mirrors the platform's own check
// (ledger/packages/aar-schema/src/location.mjs); a test keeps the two in step.

const REGION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const COUNTRY = /^[A-Za-z]{2}$/;
const PROVIDER = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const BASES = ['declared', 'derived', 'edge'];

const clean = (re, value, fold = (v) => v) => {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  return re.test(v) ? fold(v) : null;
};
const region = (v) => clean(REGION, v, (s) => s.toLowerCase());
const country = (v) => clean(COUNTRY, v, (s) => s.toUpperCase());
const provider = (v) => clean(PROVIDER, typeof v === 'string' ? v.toLowerCase() : v);
const prune = (o) => {
  const out = Object.fromEntries(Object.entries(o).filter(([, v]) => v !== null && v !== undefined));
  return Object.keys(out).length ? out : null;
};

/** The `location` stored on a record: { runtime?, target? }, or null when nothing valid was given. */
export function sanitizeLocation(input) {
  if (!input || typeof input !== 'object') return null;
  const r = input.runtime && typeof input.runtime === 'object' ? input.runtime : null;
  const t = input.target && typeof input.target === 'object' ? input.target : null;
  const runtime = r && prune({ provider: provider(r.provider), region: region(r.region), zone: region(r.zone), country: country(r.country) });
  const target = t && prune({ region: region(t.region), country: country(t.country) });
  const basis = (x) => (BASES.includes(x?.basis) ? x.basis : 'declared');
  const out = {
    ...(runtime ? { runtime: { ...runtime, basis: basis(r) } } : {}),
    ...(target ? { target: { ...target, basis: basis(t) } } : {}),
  };
  return Object.keys(out).length ? out : null;
}

/** Runtime location from the cloud environment the process runs in, when it names one. */
export function locationFromEnv(env = process.env) {
  const pick = (name, prov) => (env[name] ? { runtime: { provider: prov, region: env[name] } } : null);
  return sanitizeLocation(
    pick('AWS_REGION', 'aws') ?? pick('AWS_DEFAULT_REGION', 'aws') ?? pick('GOOGLE_CLOUD_REGION', 'gcp')
      ?? pick('FUNCTION_REGION', 'gcp') ?? pick('FLY_REGION', 'fly') ?? pick('VERCEL_REGION', 'vercel')
      ?? pick('REGION_NAME', 'azure'),
  );
}
