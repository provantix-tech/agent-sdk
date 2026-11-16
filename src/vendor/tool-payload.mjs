// Tool-call payload extraction shared by the SDK OTel mapping (app/agent-sdk/src/otel.mjs)
// and the hosted intake (ledger/packages/ingest/src/intake.mjs). P3: tool arguments and
// results become a redacted, truncated erasable summary on collector-sealed records; the
// hosted intake is hash-only by design and hashes them instead. Both paths record
// external_recipient for send actions from the same attribute sources.
//
// Pure functions over plain attribute objects.

// OTel GenAI semconv (current + legacy drafts) for tool-call payloads.
export const TOOL_ARGUMENTS_ATTRS = ['gen_ai.tool.call.arguments', 'gen_ai.tool.arguments'];
export const TOOL_RESULT_ATTRS = ['gen_ai.tool.call.result', 'gen_ai.tool.result'];

const RECIPIENT_MAX_CHARS = 200;

function firstAttr(attributes, names) {
  for (const name of names) {
    const value = attributes?.[name];
    if (value !== null && value !== undefined && value !== '') return value;
  }
  return null;
}

function asText(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Extract the tool call arguments and result text from span attributes.
 * @returns {{argumentsText: string|null, resultText: string|null}}
 */
export function toolCallText(attributes) {
  return {
    argumentsText: asText(firstAttr(attributes, TOOL_ARGUMENTS_ATTRS)),
    resultText: asText(firstAttr(attributes, TOOL_RESULT_ATTRS)),
  };
}

// Send detection: an explicit send action type, a messaging send operation, or a
// send-shaped tool/operation name. Keep in sync with the E2 sensitive predicate's
// notion of "send" (behaviour.mjs SENSITIVE_ACTION_TYPES).
const SEND_NAME_RE = /(?:^|[._-])(send|deliver|dispatch|notify|email|message|sms|webhook)(?:[._-]|$)/i;

export function isSendAction({ actionType, operation, toolName } = {}) {
  if (actionType === 'send') return true;
  if (operation && SEND_NAME_RE.test(operation)) return true;
  if (toolName && SEND_NAME_RE.test(toolName)) return true;
  return false;
}

const RECIPIENT_ARG_KEYS = ['to', 'recipient', 'recipients', 'destination', 'channel', 'email', 'address', 'phone'];

function recipientFromArgs(argsText) {
  if (!argsText) return null;
  let parsed = null;
  try {
    parsed = JSON.parse(argsText);
  } catch {
    return null;
  }
  const candidates = Array.isArray(parsed) ? parsed : [parsed];
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== 'object') continue;
    for (const key of RECIPIENT_ARG_KEYS) {
      const value = candidate[key];
      if (typeof value === 'string' && value.trim()) return value.trim();
      if (Array.isArray(value) && typeof value[0] === 'string' && value[0].trim()) return value[0].trim();
    }
  }
  return null;
}

/**
 * Where a send action sent its payload. Sources, in order: messaging semconv destination
 * attributes, then the usual recipient keys inside the tool call arguments.
 * @returns {string|null} capped at 200 characters
 */
export function extractExternalRecipient(attributes) {
  const direct = firstAttr(attributes, [
    'messaging.destination.name',
    'messaging.destination.topic',
    'messaging.destination.queue',
    'messaging.destination.endpoint',
  ]);
  const text = asText(direct) ?? recipientFromArgs(asText(firstAttr(attributes, TOOL_ARGUMENTS_ATTRS)));
  if (!text) return null;
  const trimmed = text.trim();
  return trimmed.length > RECIPIENT_MAX_CHARS ? `${trimmed.slice(0, RECIPIENT_MAX_CHARS)}…` : trimmed;
}
