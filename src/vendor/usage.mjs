// What "input tokens" and "output tokens" mean, made the same for every provider (PRO-65).
//
// Providers disagree, and pricing from a wrong assumption double counts or drops tokens:
//
//   Anthropic   input_tokens does NOT include cache reads or cache writes. They are separate fields, so the total input is the three added up.
//   OpenAI      prompt tokens INCLUDE the cached ones; the cached count is a part of the total. Reasoning tokens are part of the output count.
//   Gemini      the prompt count INCLUDES cached content. Thinking tokens are NOT in the candidates (output) count, so they are added to the output.
//   DeepSeek    prompt tokens are cache hits plus cache misses: the total includes them.
//   Others      OpenAI-compatible (Kimi, GLM, OpenRouter): treated as OpenAI.
//
// (Written from the providers' published usage fields and the OpenTelemetry GenAI conventions, whose newer versions say input tokens should include cached ones.
// Not yet checked against live responses from each provider.)
//
// What Provantix keeps: tokens_in is the TOTAL input (cache included); tokens_cache_read and tokens_cache_write are parts of it; tokens_out is the TOTAL output
// (reasoning included); tokens_reasoning is a part of it. Where a source gives no cache figure, those stay null: "not reported" is never 0.
//
// Two safeguards, because instrumentation does not always follow the provider's own rule:
//   - A source can say which it sent, with provantix.usage.input_includes_cache (true or false). That wins over the provider's default.
//   - If the cache figures add up to MORE than the input count, they cannot be parts of it, so the input must have excluded them. They are added, and the basis is
//     recorded as inferred, so the number is visible as a judgement and not a report.

const num = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : null;
};

export const USAGE_BASIS = {
  NO_CACHE: 'no_cache_reported',
  INCLUDES: 'input_includes_cache',
  EXCLUDES: 'input_excludes_cache',
  EXCLUDES_INFERRED: 'input_excludes_cache_inferred',
};

const isAnthropic = (provider) => /anthropic/i.test(String(provider ?? ''));
const thoughtsSeparate = (provider) => /gemini|google|vertex/i.test(String(provider ?? ''));

/** A boolean from an attribute that may arrive as a boolean or a string. Anything else is "not said". */
export function readBool(v) {
  if (v === true || v === false) return v;
  const s = String(v ?? '').trim().toLowerCase();
  return s === 'true' ? true : s === 'false' ? false : null;
}

/** The service tier as one of four words, or null when the source did not say or said something else. */
export function normalizeTier(v) {
  const s = String(v ?? '').trim().toLowerCase();
  if (!s) return null;
  if (s === 'batch') return 'batch';
  if (s === 'priority') return 'priority';
  if (s === 'flex') return 'flex';
  if (['standard', 'default', 'auto', 'on_demand', 'scale'].includes(s)) return 'standard';
  return null;
}

/**
 * @param {{provider?: string|null, input?: any, output?: any, cacheRead?: any, cacheWrite?: any, reasoning?: any, inputIncludesCache?: boolean|null, outputIncludesReasoning?: boolean|null}} u
 * @returns {{tokens_in: number|null, tokens_out: number|null, tokens_cache_read: number|null, tokens_cache_write: number|null, tokens_reasoning: number|null, usage_basis: string}}
 */
export function normalizeUsage(u) {
  const input = num(u.input); const output = num(u.output);
  const read = num(u.cacheRead); const write = num(u.cacheWrite); const reasoning = num(u.reasoning);

  // input
  let basis = USAGE_BASIS.NO_CACHE;
  let tokensIn = input;
  if (read !== null || write !== null) {
    const parts = (read ?? 0) + (write ?? 0);
    const said = u.inputIncludesCache === true || u.inputIncludesCache === false ? u.inputIncludesCache : null;
    const includes = said ?? !isAnthropic(u.provider);
    if (includes && input !== null && parts > input) {
      tokensIn = input + parts; basis = USAGE_BASIS.EXCLUDES_INFERRED;           // parts cannot exceed their whole, so the whole left them out
    } else if (includes) {
      tokensIn = input; basis = USAGE_BASIS.INCLUDES;
    } else {
      tokensIn = (input ?? 0) + parts; basis = USAGE_BASIS.EXCLUDES;
    }
  }

  // output
  let tokensOut = output;
  if (reasoning !== null) {
    const said = u.outputIncludesReasoning === true || u.outputIncludesReasoning === false ? u.outputIncludesReasoning : null;
    const includes = said ?? !thoughtsSeparate(u.provider);
    if (!includes || (output !== null && reasoning > output)) tokensOut = (output ?? 0) + reasoning;
  }

  return { tokens_in: tokensIn, tokens_out: tokensOut, tokens_cache_read: read, tokens_cache_write: write, tokens_reasoning: reasoning, usage_basis: basis };
}

/** The attribute names a span can carry these under: the OpenTelemetry GenAI names first, then the ones other instrumentations use. */
export const USAGE_ATTRIBUTES = {
  cacheRead: ['gen_ai.usage.cache_read.input_tokens', 'gen_ai.usage.cache_read_input_tokens', 'llm.token_count.prompt_details.cache_read'],
  cacheWrite: ['gen_ai.usage.cache_creation.input_tokens', 'gen_ai.usage.cache_creation_input_tokens', 'llm.token_count.prompt_details.cache_write'],
  reasoning: ['gen_ai.usage.reasoning.output_tokens', 'gen_ai.usage.reasoning_tokens', 'llm.token_count.completion_details.reasoning'],
  tier: ['provantix.usage.tier', 'openai.response.service_tier', 'gen_ai.openai.response.service_tier'],
  inputIncludesCache: ['provantix.usage.input_includes_cache'],
};
