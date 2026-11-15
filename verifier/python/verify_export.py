#!/usr/bin/env python3
"""Independent Provantix export verifier (standard library only).

Implements verifier/FORMAT.md without reading the Node implementation. Passing the shared test
vectors in verifier/vectors/ is the conformance test between the two.

Usage: python3 verify_export.py <exportDir> [--emitter-keys emitter-keys.pem|.json] [--json]
Exit: 0 verified, 1 verification failed, 2 usage or unreadable input.

The emitter proof (FORMAT.md, "Emitter proof") is checked here too, with a pure-Python ECDSA P-256
verifier because the standard library has none. This implementation does not check the Provantix
manifest signature, so a customer-supplied key listed in the export is reported as taken from an
export whose signature was not checked, never as attested by Provantix.
"""

import base64
import hashlib
import json
import os
import re
import sys

# Keep in sync with the platform's record-integrity module (aar-schema/src/integrity.mjs). 'authorization' was
# appended for Epic E (2026-10-24); records sealed before it existed carry no entry or
# commitment and are skipped, so pre-E exports keep verifying unchanged.
ERASABLE_FIELDS = [
    "on_behalf_of",
    "delegation_chain",
    "input_summary",
    "output_summary",
    "attribution_evidence",
    "ext",
    "user_agent",
    "authorization",
]


# The two things a passing check never means (PRO-16). Shown beside every result, whatever it says.
CAVEATS = [
    "A valid signature shows who signed this. It does not show that what is signed is true.",
    "Integrity is not completeness. Nothing in here was altered since it was recorded, but that does not show that every action was captured.",
]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canonical(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("non-finite number")
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        parts = [json.dumps(k, ensure_ascii=False) + ":" + canonical(value[k]) for k in sorted(value.keys())]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unsupported type {type(value).__name__}")


def merkle_root(leaves):
    if not leaves:
        return sha256(b"")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(sha256(level[i] + right))
        level = nxt
    return level[0]


def verify_record(rec):
    reasons = []
    commitments = []
    erasable = rec.get("erasable") or {}
    claimed_all = (rec.get("integrity") or {}).get("commitments") or {}
    for f in ERASABLE_FIELDS:
        entry = erasable.get(f)
        claimed = claimed_all.get(f)
        # Absent = sealed before this field existed in the schema (append-only evolution);
        # excluded from the leaf set, exactly as the sealer computed it.
        if entry is None or not isinstance(claimed, str):
            continue
        commitments.append(bytes.fromhex(claimed))
        if entry.get("erased") is True:
            continue
        salt = bytes.fromhex(entry["salt"])
        recomputed = sha256(salt + canonical(entry.get("value")).encode("utf-8")).hex()
        if recomputed != claimed:
            reasons.append(f"commitment mismatch on {f}")
    if not reasons:
        root = merkle_root(commitments)
        recomputed = sha256(canonical(rec["fields"]).encode("utf-8") + b"|" + root).hex()
        if recomputed != rec["integrity"]["record_hash"]:
            reasons.append("record_hash mismatch")
    return {"valid": not reasons, "reasons": reasons}


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ---- ECDSA P-256 (verify only) --------------------------------------------------------------------------------

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
# DER prefix of a P-256 SubjectPublicKeyInfo: the algorithm, the curve, then a 65-byte uncompressed point.
_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _pem_der(pem):
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


def _public_point(pem):
    der = _pem_der(pem)
    if len(der) != len(_SPKI_PREFIX) + 65 or not der.startswith(_SPKI_PREFIX) or der[len(_SPKI_PREFIX)] != 4:
        raise ValueError("not an ECDSA P-256 SPKI public key")
    raw = der[len(_SPKI_PREFIX):]
    return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big"))


def fingerprint_of(pem):
    """SHA-256 of the DER SPKI encoding, hex: what a seal's key_fingerprint names."""
    _public_point(pem)  # refuses anything that is not a P-256 key
    return hashlib.sha256(_pem_der(pem)).hexdigest()


def _der_signature(sig):
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("bad signature encoding")
    pos = 2 if sig[1] < 0x80 else 2 + (sig[1] & 0x7F)
    ints = []
    for _ in range(2):
        if sig[pos] != 0x02:
            raise ValueError("bad signature encoding")
        length = sig[pos + 1]
        ints.append(int.from_bytes(sig[pos + 2:pos + 2 + length], "big"))
        pos += 2 + length
    return ints[0], ints[1]


def ecdsa_p256_verify(pem, message, signature_b64):
    """True when signature_b64 (DER, base64) is a valid ECDSA P-256 / SHA-256 signature of message."""
    try:
        q = _public_point(pem)
        r, s = _der_signature(base64.b64decode(signature_b64))
    except Exception:
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    point = _add(_mul(z * w % _N, _G), _mul(r * w % _N, q))
    return point is not None and point[0] % _N == r


# ---- emitter proof ---------------------------------------------------------------------------------------------

SOURCE_TEXT = {
    "auditor": "a key supplied by the auditor (independent of Provantix)",
    "bundle_attested": "a customer-supplied key listed in a Provantix-signed export (Provantix attests the key; not independent of Provantix)",
    "bundle_unsigned": "a key taken from the export itself, whose signature is absent or not checked (this proves nothing about who holds the key)",
    "generated": "a key Provantix generated (Provantix once held the private key, so this is only Provantix's own attestation)",
    "unknown": "a key whose origin the export does not record",
}


def parse_emitter_keys(text):
    """Auditor key file: PEM public keys, or JSON (array of PEM, {"keys": [...]}, or {emitter id: PEM})."""
    out = {"keys": [], "by_emitter": {}}
    trimmed = text.strip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        doc = json.loads(trimmed)
        if isinstance(doc, list):
            out["keys"].extend(doc)
        elif isinstance(doc.get("keys"), list):
            out["keys"].extend(doc["keys"])
        else:
            for emitter_id, pem in doc.items():
                out["by_emitter"][emitter_id] = pem
                out["keys"].append(pem)
    else:
        out["keys"].extend(re.findall(r"-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----", trimmed))
    for pem in out["keys"]:
        fingerprint_of(pem)  # a malformed key is refused loudly
    return out


def _read_jsonl_maybe(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _iso_ms(text):
    """Milliseconds since the epoch of an ISO-8601 UTC timestamp, like JavaScript's Date.parse for these values."""
    from datetime import datetime, timezone
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp() * 1000


def _iso_ms_or_none(text):
    try:
        return _iso_ms(text)
    except (AttributeError, ValueError, TypeError):
        return None


def verify_emitter_proof(directory, manifest, records, emitter_keys=None):
    """Mirror of verifyEmitterProof in verify-export.mjs. Returns (summary, checks)."""
    total = len(records)
    seals = _read_jsonl_maybe(os.path.join(directory, "seals.jsonl"))
    summary = {
        "present": bool(seals), "records_total": total, "records_signed": 0, "records_unsealed": 0,
        "records_key_missing": 0, "records_failed": 0, "refused_at_ingest": [], "missing_from_export": [],
        "key_sources": {}, "lines": [],
    }
    checks = []
    sealed = {(s["collector_id"], s["batch_seq"]): s for s in (seals or [])}

    emitters_path = os.path.join(directory, "emitters.json")
    emitters_doc = {"emitters": []}
    if os.path.exists(emitters_path):
        with open(emitters_path, encoding="utf-8") as fh:
            emitters_doc = json.load(fh)
    auditor_fp = {fingerprint_of(pem): pem for pem in (emitter_keys or {}).get("keys", [])}
    by_emitter = (emitter_keys or {}).get("by_emitter", {})
    bundle_keys = {}
    events = {}
    for e in emitters_doc.get("emitters", []):
        events[e["collector_id"]] = e.get("key_events", [])
        for k in e.get("keys", []):
            if k.get("public_key_pem"):
                bundle_keys[(e["collector_id"], k["fingerprint"])] = k

    problems = {"seals": [], "match": [], "compromised": []}
    key_source_of = {}
    outcome = {}

    for s in seals or []:
        bk = (s["collector_id"], s["batch_seq"])
        label = f"{s['collector_id']}#{s['batch_seq']}"
        mapped = by_emitter.get(s["collector_id"])
        if mapped and fingerprint_of(mapped) != s["key_fingerprint"]:
            problems["seals"].append(f"batch {label} was sealed with a key other than the one the auditor holds for {s['collector_id']}")
            outcome[bk] = "failed"
            continue
        pem = None
        source = None
        if s["key_fingerprint"] in auditor_fp:
            pem, source = auditor_fp[s["key_fingerprint"]], "auditor"
        else:
            k = bundle_keys.get((s["collector_id"], s["key_fingerprint"]))
            if k:
                pem = k["public_key_pem"]
                # This verifier does not check the manifest signature, so a customer key from the export is never "attested".
                source = "generated" if k.get("key_source") == "generated" else "bundle_unsigned" if k.get("key_source") == "customer" else "unknown"
        if not pem:
            outcome[bk] = "key_missing"
            continue
        if not ecdsa_p256_verify(pem, canonical(s["statement"]).encode("utf-8"), s["signature"]):
            problems["seals"].append(f"the seal of batch {label} does not verify with its key")
            outcome[bk] = "failed"
            continue
        key_source_of[bk] = source
        suspect = next((e for e in events.get(s["collector_id"], []) if e.get("event") == "compromised" and e.get("suspect_from")
                        and _iso_ms(s["statement"]["created_at"]) >= _iso_ms(e["suspect_from"])), None)
        if suspect:
            problems["compromised"].append(f"batch {label} was sealed at {s['statement']['created_at']}, after its key was declared compromised (suspect from {suspect['suspect_from']})")
            outcome[bk] = "failed"
            continue
        outcome[bk] = "signed"

    present = {}
    for r in records:
        src = r.get("source") or {}
        bk = (src.get("collector_id"), src.get("batch_seq")) if src.get("collector_id") is not None else None
        if bk is None or bk not in sealed:
            summary["records_unsealed"] += 1
            continue
        present.setdefault(bk, set()).add(src.get("batch_index"))
        o = outcome.get(bk)
        if o == "key_missing":
            summary["records_key_missing"] += 1
            continue
        if o == "failed":
            summary["records_failed"] += 1
            continue
        hashes = sealed[bk]["statement"].get("record_hashes") or []
        idx = src.get("batch_index")
        sealed_hash = hashes[idx] if isinstance(idx, int) and 0 <= idx < len(hashes) else None
        if sealed_hash != r["integrity"]["record_hash"]:
            summary["records_failed"] += 1
            problems["match"].append(f"record {r.get('record_id')} ({src.get('collector_id')}#{src.get('batch_seq')}[{idx}]) does not match the hash the emitter sealed")
        else:
            summary["records_signed"] += 1

    missing = []
    for s in seals or []:
        bk = (s["collector_id"], s["batch_seq"])
        if outcome.get(bk) != "signed":
            continue
        have = present.get(bk, set())
        said = {x["index"]: x["why"] for x in (s.get("not_stored") or [])}
        for i, h in enumerate(s["statement"]["record_hashes"]):
            if i in have:
                continue
            if i in said:
                summary["refused_at_ingest"].append({"collector_id": s["collector_id"], "batch_seq": s["batch_seq"], "index": i, "why": said[i]})
            else:
                missing.append({"collector_id": s["collector_id"], "batch_seq": s["batch_seq"], "index": i, "record_hash": h})
    summary["missing_from_export"] = missing if manifest.get("complete") else []

    for v in key_source_of.values():
        summary["key_sources"][v] = summary["key_sources"].get(v, 0) + 1

    if summary["present"]:
        checks.append({"name": "emitter proof: seals verify", "ok": not problems["seals"], "detail": "; ".join(problems["seals"][:3])})
        checks.append({"name": "emitter proof: records match seals", "ok": not problems["match"], "detail": "; ".join(problems["match"][:3])})
        if manifest.get("complete"):
            checks.append({"name": "emitter proof: no sealed record missing", "ok": not summary["missing_from_export"],
                           "detail": "; ".join(f"{m['collector_id']}#{m['batch_seq']}[{m['index']}] {m['record_hash'][:12]}" for m in summary["missing_from_export"][:3])})
        checks.append({"name": "emitter proof: no seal from a compromised key", "ok": not problems["compromised"], "detail": "; ".join(problems["compromised"][:3])})

    lines = [f"emitter proof: {summary['records_signed']} of {total} records signed by the emitter's key"]
    if summary["records_unsealed"]:
        lines.append(f"  {summary['records_unsealed']} records are in batches the emitter did not seal (not covered, not failed)")
    if summary["records_key_missing"]:
        lines.append(f"  {summary['records_key_missing']} records are sealed, but no key for the seal was supplied or listed (not checked, not failed)")
    if summary["records_failed"]:
        lines.append(f"  {summary['records_failed']} records FAILED against their seal")
    if summary["refused_at_ingest"]:
        shown = ", ".join(f"{x['collector_id']}#{x['batch_seq']}[{x['index']}] {x['why']}" for x in summary["refused_at_ingest"][:5])
        more = ", and more" if len(summary["refused_at_ingest"]) > 5 else ""
        lines.append(f"  {len(summary['refused_at_ingest'])} sealed records are absent from the export and the platform says it refused or skipped them at ingest (a platform statement, not signed by the emitter): {shown}{more}")
    if summary["missing_from_export"]:
        shown = ", ".join(f"{m['collector_id']}#{m['batch_seq']}[{m['index']}]" for m in summary["missing_from_export"][:5])
        lines.append(f"  {len(summary['missing_from_export'])} sealed records are MISSING from this complete export: {shown}")
    sources = list(summary["key_sources"].keys())
    if sources:
        lines.append("  key source: " + "; ".join(SOURCE_TEXT[k] for k in sources))
    elif summary["present"]:
        lines.append("  key source: no seal could be checked")
    summary["lines"] = lines
    return summary, checks



# ---- decision evidence (optional, in records: ext.decision and ext.decision_ref) ----------------------------------------------------------
# Why an agent chose an action, as the agent recorded it. Computed from records.jsonl alone, so it needs no extra file and no version change.
# It says what the agent said it considered. It does not show the reasoning was sound or was the reason, or that the action happened.
# Written to agree with verify-export.mjs on every vector (the check names and the summary lines), and a test holds the two to it.

DECISION_VERSION = 1
DECISION_SOURCES = ["agent", "human", "system"]
DECISION_MAX_ITEMS = 20


def _is_obj(v):
    return isinstance(v, dict)


def _str(v):
    return v if isinstance(v, str) and v.strip() else None


def _text(v):
    return v.strip() if isinstance(v, str) and v.strip() else None


def _ext_of(rec):
    body = rec.get("body") if isinstance(rec, dict) and rec.get("body") is not None else rec
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return None
    ext = ((body or {}).get("erasable") or {}).get("ext") if isinstance(body, dict) else None
    if not ext:
        return None
    if ext.get("erased"):
        return {"erased": True}
    return {"value": ext["value"]} if _is_obj(ext.get("value")) else None


def _json_text(v):
    return "undefined" if v is None else json.dumps(v, separators=(",", ":"))


def validate_decision(d):
    problems = []
    if not _is_obj(d):
        return ["the decision is not an object"]
    if d.get("v") != DECISION_VERSION or isinstance(d.get("v"), bool):
        problems.append(f"the decision version is {_json_text(d.get('v'))}, and only {DECISION_VERSION} is understood")
    if not _str(d.get("decision_id")):
        problems.append("there is no decision_id")
    if d.get("source") not in DECISION_SOURCES:
        problems.append(f"source must be one of {', '.join(DECISION_SOURCES)}")
    cands = d.get("candidates") if isinstance(d.get("candidates"), list) else []
    if not cands:
        problems.append("there is no candidate action")
    if len(cands) > DECISION_MAX_ITEMS:
        problems.append(f"more than {DECISION_MAX_ITEMS} candidates")
    ids = set()
    for c in cands:
        if not _is_obj(c) or not _str(c.get("id")) or not _str(c.get("action")):
            problems.append("a candidate has no id or no action")
            continue
        if c["id"] in ids:
            problems.append(f"candidate id {c['id']} is used twice")
        ids.add(c["id"])
    sel = d.get("selected")
    if not _is_obj(sel) or not _str(sel.get("candidate_id")) or not _str(sel.get("action_id")):
        problems.append("the selected action needs a candidate_id and an action_id")
    elif sel["candidate_id"] not in ids:
        problems.append("the selected candidate is not among the candidates")
    for r in d.get("rejected") if isinstance(d.get("rejected"), list) else []:
        if not _is_obj(r) or not _str(r.get("candidate_id")):
            problems.append("a rejected alternative names no candidate")
        elif r["candidate_id"] not in ids:
            problems.append(f"rejected candidate {r['candidate_id']} is not among the candidates")
        elif sel and r["candidate_id"] == sel.get("candidate_id"):
            problems.append("the selected candidate is also listed as rejected")
    intent = d.get("intent_ref")
    if intent is not None and (not _is_obj(intent) or not _str(intent.get("ref"))):
        problems.append("intent_ref needs a ref")
    model = d.get("model_ref")
    if model is not None and (not _is_obj(model) or not _str(model.get("model_id"))):
        problems.append("model_ref needs a model_id")
    return problems


def _decision_of(rec):
    ext = _ext_of(rec)
    if not ext or ext.get("erased"):
        return None
    d = ext["value"].get("decision")
    if not _is_obj(d):
        return None
    return {"record_id": rec.get("record_id"), "decision": d, "problems": validate_decision(d)}


def _decision_ref_of(rec):
    ext = _ext_of(rec)
    if not ext or ext.get("erased"):
        return None
    r = ext["value"].get("decision_ref")
    if not _is_obj(r) or not _str(r.get("decision_id")):
        return None
    return {"record_id": rec.get("record_id"), "decision_id": str(r["decision_id"]), "candidate_id": _str(r.get("candidate_id")), "action_id": _str(r.get("action_id"))}


def decision_links(records):
    decisions, refs = [], []
    for rec in records:
        d = _decision_of(rec)
        if d:
            decisions.append(d)
        r = _decision_ref_of(rec)
        if r:
            refs.append(r)
    by_id = {}
    for d in decisions:
        by_id.setdefault(d["decision"].get("decision_id"), []).append(d)
    links = []
    for r in refs:
        found = by_id.get(r["decision_id"], [])
        base = {"action_record_id": r["record_id"], "decision_id": r["decision_id"], "candidate_id": r["candidate_id"], "action_id": r["action_id"]}
        if not found:
            links.append({**base, "status": "not_in_scope", "reason": "the decision this action cites is not among these records"})
        elif len(found) > 1:
            links.append({**base, "status": "duplicate", "reason": "more than one record claims this decision id"})
        else:
            sel = found[0]["decision"].get("selected") or {}
            if sel.get("action_id") != r["action_id"] or sel.get("candidate_id") != r["candidate_id"]:
                links.append({**base, "decision_record_id": found[0]["record_id"], "status": "mismatch", "reason": "the decision selects a different action or candidate than the one that cites it"})
            else:
                links.append({**base, "decision_record_id": found[0]["record_id"], "status": "linked", "reason": None})
    cited = {f"{r['decision_id']}|{r['action_id']}" for r in refs}
    undelivered = [
        {"decision_record_id": d["record_id"], "decision_id": d["decision"].get("decision_id"), "action_id": (d["decision"].get("selected") or {}).get("action_id")}
        for d in decisions
        if (d["decision"].get("selected") or {}).get("action_id") and f"{d['decision'].get('decision_id')}|{d['decision']['selected']['action_id']}" not in cited
    ]
    return {"decisions": decisions, "links": links, "undelivered": undelivered}


def verify_decision_evidence(records):
    r = decision_links(records)
    erased = sum(1 for rec in records if ((rec.get("erasable") or {}).get("ext") or {}).get("erased"))

    def count(status):
        return sum(1 for l in r["links"] if l["status"] == status)

    counts = {
        "decisions": len(r["decisions"]), "actions_citing": len(r["links"]), "linked": count("linked"), "mismatched": count("mismatch"), "duplicates": count("duplicate"),
        "not_in_scope": count("not_in_scope"), "undelivered": len(r["undelivered"]), "malformed": sum(1 for d in r["decisions"] if d["problems"]), "erased_extensions": erased,
    }
    if not counts["decisions"] and not counts["actions_citing"]:
        return [], {"present": False, **counts, "lines": ["decision evidence: this export carries no decision records"]}
    checks = []
    bad_links = counts["mismatched"] + counts["duplicates"]
    checks.append({
        "name": "decision evidence: every decision agrees with the action that cites it", "ok": bad_links == 0,
        "detail": f"{counts['linked']} of {counts['actions_citing']} cited" if bad_links == 0 else f"{counts['mismatched']} differ from what the decision selected, {counts['duplicates']} cite a decision id claimed by two records",
    })
    checks.append({
        "name": "decision evidence: decisions are well formed", "ok": counts["malformed"] == 0,
        "detail": "" if counts["malformed"] == 0 else "; ".join(f"{d['decision'].get('decision_id')}: {d['problems'][0]}" for d in r["decisions"] if d["problems"]),
    })

    def plural(n, one, many):
        return one if n == 1 else many

    parts = [f"{counts['decisions']} decision{plural(counts['decisions'], '', 's')} recorded, {counts['linked']} linked to the action each selected"]
    if counts["not_in_scope"]:
        parts.append(f"{counts['not_in_scope']} {plural(counts['not_in_scope'], 'action cites', 'actions cite')} a decision that is not in this export (not recorded here, which is not the same as there being none)")
    if counts["undelivered"]:
        parts.append(f"{counts['undelivered']} decision{plural(counts['undelivered'], '', 's')} selected an action that no record here points back at (this is not evidence the action did not happen)")
    if counts["erased_extensions"]:
        parts.append(f"{counts['erased_extensions']} record{plural(counts['erased_extensions'], ' has', 's have')} an erased extension, so a decision or a pointer there cannot be read")
    lines = [
        f"decision evidence: {'; '.join(parts)}",
        "decision evidence: a decision is what the agent said it considered and chose. It does not show the reasoning was sound or was the reason, or that the action happened as chosen.",
    ]
    return checks, {"present": True, **counts, "lines": lines}


# ---- control decision evidence (optional, in records: ext.control and ext.control_ref) ----------------------------------------------------
# What an enforcement tool said it decided about an action (allow, ask, deny, steer), as the emitter sealed it, and whether the records agree with
# each other. An integrity check over the records in the export. It does not show the enforcer was in the path, that its verdict was obeyed, or
# that an action it denied did not happen. Written to agree with verify-export.mjs on every vector (check names and summary lines).

CONTROL_VERSION = 1
CONTROL_VERDICTS = ["allow", "ask", "deny", "steer"]


def _parses_as_time(v):
    # Only the forms an emitter writes (ISO 8601) are accepted here; the Node verifier's Date.parse is wider, so the vectors stay within ISO 8601.
    from datetime import datetime
    if not isinstance(v, str):
        return False
    try:
        datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def validate_control(c):
    problems = []
    if not _is_obj(c):
        return ["the control decision is not an object"]
    if c.get("v") != CONTROL_VERSION or isinstance(c.get("v"), bool):
        problems.append(f"the control decision version is {'missing' if 'v' not in c else _json_text(c.get('v'))}, and only {CONTROL_VERSION} is understood")
    if not _str(c.get("control_id")):
        problems.append("there is no control_id")
    if not _is_obj(c.get("enforcer")) or not _str(c["enforcer"].get("name")):
        problems.append("the enforcer needs a name")
    if c.get("verdict") not in CONTROL_VERDICTS:
        problems.append(f"verdict must be one of {', '.join(CONTROL_VERDICTS)}")
    if not _is_obj(c.get("policy")) or not _str(c["policy"].get("id")):
        problems.append("the policy that decided needs an id")
    if c.get("decided_at") is not None and not _parses_as_time(c.get("decided_at")):
        problems.append("decided_at must be a date and time")
    return problems


def _control_of(rec):
    ext = _ext_of(rec)
    if not ext or ext.get("erased"):
        return None
    c = ext["value"].get("control")
    if not _is_obj(c):
        return None
    return {"record_id": rec.get("record_id"), "control": c, "problems": validate_control(c)}


def _control_ref_of(rec):
    ext = _ext_of(rec)
    if not ext or ext.get("erased"):
        return None
    r = ext["value"].get("control_ref")
    if not _is_obj(r) or not _str(r.get("control_id")):
        return None
    return {"record_id": rec.get("record_id"), "control_id": str(r["control_id"]), "action_id": _str(r.get("action_id"))}


def control_ref_links(records):
    controls, refs = [], []
    for rec in records:
        c = _control_of(rec)
        if c:
            controls.append(c)
        r = _control_ref_of(rec)
        if r:
            refs.append(r)
    by_id = {}
    for c in controls:
        by_id.setdefault(c["control"].get("control_id"), []).append(c)
    links = []
    for r in refs:
        found = by_id.get(r["control_id"], [])
        base = {"action_record_id": r["record_id"], "control_id": r["control_id"], "action_id": r["action_id"]}
        if not found:
            links.append({**base, "status": "not_in_scope", "reason": "the control decision this action cites is not among these records"})
        elif len(found) > 1:
            links.append({**base, "status": "duplicate", "reason": "more than one record claims this control id"})
        else:
            want = _str(found[0]["control"].get("action_id"))
            verdict = found[0]["control"].get("verdict")
            extra = {"control_record_id": found[0]["record_id"], "verdict": verdict}
            if not want:
                links.append({**base, **extra, "status": "unbound", "reason": None})
            elif want != r["action_id"]:
                links.append({**base, **extra, "status": "mismatch", "reason": "the control decision names a different action than the one that cites it"})
            else:
                links.append({**base, **extra, "status": "linked", "reason": None})
    denied_cited = sum(1 for l in links if l["status"] == "linked" and l.get("verdict") == "deny")
    return {"controls": controls, "links": links, "denied_cited": denied_cited}


def verify_control_evidence(records):
    r = control_ref_links(records)

    def count(status):
        return sum(1 for l in r["links"] if l["status"] == status)

    counts = {
        "controls": len(r["controls"]), "actions_citing": len(r["links"]), "linked": count("linked"), "unbound": count("unbound"), "mismatched": count("mismatch"),
        "duplicates": count("duplicate"), "not_in_scope": count("not_in_scope"), "malformed": sum(1 for c in r["controls"] if c["problems"]), "denied_cited": r["denied_cited"],
    }
    if not counts["controls"] and not counts["actions_citing"]:
        return [], {"present": False, **counts, "lines": ["control evidence: this export carries no control decision records"]}
    checks = []
    bad_links = counts["mismatched"] + counts["duplicates"]
    checks.append({
        "name": "control evidence: every control decision agrees with the action that cites it", "ok": bad_links == 0,
        "detail": f"{counts['linked'] + counts['unbound']} of {counts['actions_citing']} cited" if bad_links == 0 else f"{counts['mismatched']} name a different action than the one citing them, {counts['duplicates']} cite a control id claimed by two records",
    })
    checks.append({
        "name": "control evidence: control decisions are well formed", "ok": counts["malformed"] == 0,
        "detail": "" if counts["malformed"] == 0 else "; ".join(f"{c['control'].get('control_id')}: {c['problems'][0]}" for c in r["controls"] if c["problems"]),
    })

    def plural(n, one, many):
        return one if n == 1 else many

    parts = [f"{counts['controls']} control decision{plural(counts['controls'], '', 's')} recorded, {counts['linked']} linked to the action each named"]
    if counts["denied_cited"]:
        parts.append(f"{counts['denied_cited']} denied by the enforcer and cited by an action record in this export (what the enforcer said and what a record shows, side by side; not a finding about the control)")
    if counts["not_in_scope"]:
        parts.append(f"{counts['not_in_scope']} {plural(counts['not_in_scope'], 'action cites', 'actions cite')} a control decision that is not in this export (not recorded here, which is not the same as there being none)")
    lines = [
        f"control evidence: {'; '.join(parts)}",
        "control evidence: a control decision is what the enforcement tool said it decided. It does not show the tool was in the path, that its verdict was obeyed, or that an action it denied did not happen.",
    ]
    return checks, {"present": True, **counts, "lines": lines}


# ---- reconciliation, approval binding and later outcomes (export 1.1, optional reconciliation.json) -------------------------------------
# The section says what Provantix compared. This checks that it is well formed, that each result is consistent with the destination
# record the export carries, and that each approval's coverage recomputes from the record and the policy version carried. It does not
# claim the destination's record is true: that is the destination's own statement, carried and hashed, not vouched for.

RECON_STATES = ["agent_reported", "destination_confirmed", "conflicting", "pending", "unverified"]
RECON_METHODS = ["reference", "action_id", "payment_amount_time"]
LINK_KINDS = ["reversal", "retry", "dispute", "reopened", "human_override"]
AUTHORITY = ["verified", "not_covered", "unchecked", "binding_not_recorded"]
SUCCESS_STATES = {"pending", "succeeded"}
FAILURE_STATES = {"failed", "canceled"}


def _whole(v):
    """An integer from a value the way the engine reads one, or None."""
    if v is None or v == "" or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return int(f) if f.is_integer() else None


def _num(v):
    """Number(v) for the values the comparison meets: None reads as 0."""
    if v is None or v == "":
        return 0
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def _claim_of_record(r):
    ext = (r.get("erasable") or {}).get("ext")
    if isinstance(ext, dict) and ext.get("erased"):
        return None, "the claim was erased"
    c = ((ext or {}).get("value") or {}).get("claim") if isinstance(ext, dict) else None
    if not isinstance(c, dict):
        return None, "the record carries no claim"
    action = (r.get("fields") or {}).get("action") or {}
    claim = {
        "action_id": str(c["action_id"]) if c.get("action_id") else None,
        "destination_ref": str(c["destination_ref"]) if c.get("destination_ref") else None,
        "payment_ref": str(c["payment_ref"]) if c.get("payment_ref") else (str(action["target_entity_id"]) if action.get("target_entity_id") else None),
        "amount_minor": _whole(c.get("amount_minor")),
        "currency": str(c["currency"]).upper() if c.get("currency") else None,
        "outcome": ((r.get("fields") or {}).get("quality") or {}).get("outcome"),
    }
    if claim["amount_minor"] is None or not claim["currency"]:
        return claim, "the claim has no amount and currency"
    return claim, None


def _claim_differs(claim, rec):
    differs = []
    aliases = (rec.get("provenance") or {}).get("payment_aliases")
    ids = [rec.get("payment_ref")] + (aliases if isinstance(aliases, list) else [])
    if claim["payment_ref"] and rec.get("payment_ref") and claim["payment_ref"] not in ids:
        differs.append("payment")
    if _num(rec.get("amount_minor")) != claim["amount_minor"]:
        differs.append("amount")
    if str(rec.get("currency") or "").upper() != claim["currency"]:
        differs.append("currency")
    if claim["outcome"] in ("success", "failure"):
        ok = (rec.get("status") in SUCCESS_STATES) if claim["outcome"] == "success" else (rec.get("status") in FAILURE_STATES)
        if not ok:
            differs.append("outcome")
    return differs


def _binding_authority(r, approval):
    az = (r.get("erasable") or {}).get("authorization")
    if isinstance(az, dict) and az.get("erased"):
        return None, "the approval was erased from the record", None
    raw = ((az or {}).get("value") or {}).get("binding") if isinstance(az, dict) else None
    if isinstance(raw, dict):
        mx = raw.get("max_amount_minor")
        mx_ok = mx is not None and mx != "" and _whole(mx) is not None
        b = {
            "target_system": raw.get("target_system"), "target_entity_id": raw.get("target_entity_id"), "action_type": raw.get("action_type"),
            "max_amount_minor": _whole(mx) if mx_ok else None,
            "currency": str(raw["currency"]).upper() if raw.get("currency") else None,
            "expires_at": raw.get("expires_at"), "policy_version": raw.get("policy_version"),
            # exact-change fields (all optional): an approval that states none of them is checked exactly as before
            "environment": _text(raw.get("environment")), "resource": _text(raw.get("resource")), "operation": _text(raw.get("operation")),
            "change_digest": (_text(raw.get("change_digest")) or "").lower() or None,
            "risk_ref": _text(raw.get("risk_ref")), "break_glass": True if raw.get("break_glass") is True else None,
        }
    else:
        b = None
    if not b or all(v is None for v in b.values()):
        return "binding_not_recorded", None, "normal"
    a = (r.get("fields") or {}).get("action") or {}
    st = []
    if b["target_system"] is not None:
        st.append("unchecked" if not a.get("target_system") else ("holds" if a["target_system"] == b["target_system"] else "fails"))
    if b["target_entity_id"] is not None:
        st.append("unchecked" if not a.get("target_entity_id") else ("holds" if a["target_entity_id"] == b["target_entity_id"] else "fails"))
    if b["action_type"] is not None:
        st.append("holds" if a.get("action_type") == b["action_type"] else "fails")
    if b["max_amount_minor"] is not None:
        claim, _ = _claim_of_record(r)
        readable = claim and claim["amount_minor"] is not None and claim["currency"] and (claim["destination_ref"] or claim["action_id"] or claim["payment_ref"])
        if not readable:
            st.append("unchecked")
        elif b["currency"] and claim["currency"] and b["currency"] != claim["currency"]:
            st.append("fails")
        else:
            st.append("fails" if claim["amount_minor"] > b["max_amount_minor"] else "holds")
    if b["expires_at"] is not None:
        exp, at = _iso_ms(b["expires_at"]), _iso_ms((r.get("fields") or {}).get("observed_at"))
        st.append("unchecked" if exp is None or at is None else ("holds" if at <= exp else "fails"))
    if b["policy_version"] is not None:
        in_force = approval.get("policy_version_in_force")
        st.append("unchecked" if in_force is None else ("holds" if in_force == b["policy_version"] else "fails"))
    if b["environment"] or b["resource"] or b["operation"] or b["change_digest"] or b["break_glass"]:
        ext = (r.get("erasable") or {}).get("ext")
        if isinstance(ext, dict) and ext.get("erased"):
            m = {"erased": True}
        elif isinstance(ext, dict) and isinstance((ext.get("value") or {}).get("mutation"), dict):
            mv = ext["value"]["mutation"]
            m = {"environment": _text(mv.get("environment")), "resource": _text(mv.get("resource")), "change_digest": (_text(mv.get("change_digest")) or "").lower() or None}
        else:
            m = None
        for key in ("environment", "resource", "change_digest"):
            want = b[key]
            if want is not None:
                st.append("unchecked" if (m is None or m.get("erased") or not m.get(key)) else ("holds" if m[key] == want else "fails"))
        if b["operation"] is not None:
            st.append("unchecked" if not a.get("operation") else ("holds" if a["operation"] == b["operation"] else "fails"))
        approved_at = _iso_ms_or_none(((az or {}).get("value") or {}).get("approved_at"))
        acted_at = _iso_ms_or_none((r.get("fields") or {}).get("observed_at"))
        st.append("unchecked" if approved_at is None or acted_at is None else ("holds" if approved_at <= acted_at else "fails"))
        if b["break_glass"]:
            st.append("unchecked")
    return ("not_covered" if "fails" in st else "unchecked" if "unchecked" in st else "verified"), None, ("break_glass" if b["break_glass"] else "normal")


def verify_reconciliation(directory, manifest, records):
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    entry = next((f for f in manifest.get("files", []) if f.get("path") == "reconciliation.json"), None)
    summary = {"present": entry is not None, "lines": []}
    if entry is None:
        summary["lines"].append("reconciliation: this export carries no reconciliation section (nothing was checked against a destination system for it).")
        return summary, checks
    try:
        with open(os.path.join(directory, "reconciliation.json"), encoding="utf-8") as fh:
            sec = json.load(fh)
    except (OSError, ValueError) as e:
        add("reconciliation: structure", False, f"unreadable: {e}")
        return summary, checks
    by_id = {r.get("record_id"): r for r in records}
    problems = []

    def lst(k):
        v = sec.get(k)
        if isinstance(v, list):
            return v
        problems.append(f"{k} is not a list")
        return []

    scopes, results, dests, approvals, links = lst("scopes"), lst("results"), lst("destination_records"), lst("approvals"), lst("links")
    if sec.get("version") != 1:
        problems.append(f"unknown section version {sec.get('version')}")
    if not isinstance(sec.get("statement"), str) or not sec.get("statement"):
        problems.append("the statement of what the section does and does not show is missing")
    scope_ids = {s.get("scope_id") for s in scopes}
    for s in scopes:
        if not s.get("scope_id") or not s.get("destination_source") or not s.get("statement"):
            problems.append("a scope is missing its id, destination or statement")
    seen = set()
    for r in results:
        rid = r.get("record_id")
        if rid not in by_id:
            problems.append(f"a result is for {rid}, which is not in this export")
        if rid in seen:
            problems.append(f"two current results for {rid}")
        seen.add(rid)
        if r.get("state") not in RECON_STATES:
            problems.append(f"result for {rid} has an unknown state \"{r.get('state')}\"")
        if r.get("method") is not None and r.get("method") not in RECON_METHODS:
            problems.append(f"result for {rid} has an unknown method \"{r.get('method')}\"")
        if not r.get("reason"):
            problems.append(f"result for {rid} has no reason")
        if r.get("scope_id") not in scope_ids:
            problems.append(f"result for {rid} names a scope that is not in the section")
        for h in r.get("history") or []:
            if h.get("state") not in RECON_STATES or not h.get("reason"):
                problems.append(f"result history for {rid} is malformed")
    for a in approvals:
        if a.get("record_id") not in by_id:
            problems.append(f"an approval entry is for {a.get('record_id')}, which is not in this export")
        if a.get("authority") not in AUTHORITY:
            problems.append(f"approval for {a.get('record_id')} has an unknown authority \"{a.get('authority')}\"")
    for l in links:
        if l.get("original_record_id") not in by_id:
            problems.append(f"a later outcome is for {l.get('original_record_id')}, which is not in this export")
        if l.get("kind") not in LINK_KINDS:
            problems.append(f"a later outcome has an unknown kind \"{l.get('kind')}\"")
        if _iso_ms(l.get("occurred_at")) is None:
            problems.append("a later outcome has no usable time")
    add("reconciliation: structure", not problems, "; ".join(problems[:3]))

    dest_by_key = {f"{d.get('source_id')}|{d.get('external_id')}": d for d in dests}
    inconsistent, unsupported, not_checked, checked = [], [], [], 0
    for r in results:
        rec = by_id.get(r.get("record_id"))
        if rec is None:
            continue
        key = f"{r.get('destination_source')}|{r.get('destination_external_id')}"
        if r.get("state") == "destination_confirmed" and not (r.get("destination_external_id") and key in dest_by_key):
            unsupported.append(r.get("record_id"))
            continue
        if r.get("state") not in ("destination_confirmed", "conflicting"):
            continue
        dest = dest_by_key.get(key) if r.get("destination_external_id") else None
        if dest is None:
            not_checked.append(f"{r.get('record_id')}: no destination record carried")
            continue
        claim, unreadable = _claim_of_record(rec)
        if unreadable or claim is None:
            not_checked.append(f"{r.get('record_id')}: {unreadable}")
            continue
        checked += 1
        differs = _claim_differs(claim, dest)
        rid, method = r.get("record_id"), r.get("method")
        dups = r.get("duplicate_records")
        if method == "reference" and claim["destination_ref"] and claim["destination_ref"] != dest.get("external_id"):
            inconsistent.append(f"{rid}: matched by the cited refund id, but the claim cites {claim['destination_ref']} and the record carried is {dest.get('external_id')}")
        elif method == "action_id" and claim["action_id"] and claim["action_id"] != dest.get("action_id"):
            inconsistent.append(f"{rid}: matched by action id, but the ids differ")
        elif r.get("state") == "destination_confirmed" and differs:
            inconsistent.append(f"{rid}: marked destination-confirmed, but the claim and the destination record differ in {', '.join(differs)}")
        elif r.get("state") == "conflicting" and not differs and not (isinstance(dups, list) and len(dups) > 1):
            inconsistent.append(f"{rid}: marked conflicting, but the claim and the destination record agree")
    add("reconciliation: results consistent with the destination records carried", not inconsistent, "; ".join(inconsistent[:3]))
    add("reconciliation: every confirmed result rests on a destination record carried", not unsupported, "; ".join(f"{i}: no destination record" for i in unsupported[:3]))

    wrong, approvals_checked, approvals_skipped = [], 0, []
    for a in approvals:
        rec = by_id.get(a.get("record_id"))
        if rec is None:
            continue
        authority, skip, path_now = _binding_authority(rec, a)
        if skip:
            approvals_skipped.append(f"{a.get('record_id')}: {skip}")
            continue
        approvals_checked += 1
        if authority != a.get("authority"):
            wrong.append(f"{a.get('record_id')}: the section says {a.get('authority')}, the record gives {authority}")
        elif (a.get("path") or "normal") != path_now:
            wrong.append(f"{a.get('record_id')}: the section says the approval path was {a.get('path') or 'normal'}, the record says {path_now}")
    add("approval binding: results recompute from the records", not wrong, "; ".join(wrong[:3]))

    link_problems = sum(1 for l in links if l.get("later_record_id") and l.get("later_record_id") not in by_id and l.get("kind") == "retry")
    add("later outcomes: each retry names a record in this export", link_problems == 0,
        f"{link_problems} retr{'y names' if link_problems == 1 else 'ies name'} a record that is not in the export" if link_problems else "")

    def count(s):
        return sum(1 for r in results if r.get("state") == s)

    summary.update({"results": len(results), "checked": checked, "approvals": len(approvals), "links": len(links)})
    summary["lines"].append(f"reconciliation: {len(results)} result{'' if len(results) == 1 else 's'}: {count('destination_confirmed')} destination-confirmed, {count('conflicting')} conflicting, {count('pending')} pending, {count('unverified')} unverified, {count('agent_reported')} agent-reported")
    extra = f"; {len(not_checked)} could not be ({'; '.join(not_checked[:2])})" if not_checked else ""
    summary["lines"].append(f"  {checked} checked against the destination record carried in the export{extra}")
    skipped = f", {len(approvals_skipped)} not ({approvals_skipped[0]})" if approvals_skipped else ""
    summary["lines"].append(f"  approvals: {len(approvals)} carried, {approvals_checked} recomputed from the record{skipped}; later outcomes: {len(links)}")
    summary["lines"].append("  this does not show that the destination's record is true: it is the destination's own statement, carried and hashed, not vouched for.")
    return summary, checks


# ---- Cost statement (optional files, version 1.1): the figures added up from the cells ----------------------------------------------------------
# A cost statement bundle carries statement/statement.json, statement/cells.json (every figure the totals are built from) and, optionally, statement/chargeback/*.csv.
# These checks appear only when statement/statement.json is listed in the manifest. They show that the stated totals are what the cells add up to. They do NOT show
# that the cells are the right figures: they are estimates frozen at close, from the organization's own price table.
STATEMENT_TOLERANCE = 0.0002  # dollars: figures are kept to four decimal places
_ST_DIMS = [("department", "department", "(unallocated)"), ("cost_center", "cost_center", "(unallocated)"), ("product", "product", "(unallocated)"), ("agent_id", "agent", "(no agent)")]


def _st_num(v):
    return 0 if v is None else float(v)


def _st_near(a, b):
    return abs(_st_num(a) - _st_num(b)) < STATEMENT_TOLERANCE


def _st_sum(rows, key):
    return sum(_st_num(r.get(key)) for r in rows)


def _st_group(cells, key_of):
    groups = {}
    for c in cells:
        g = groups.setdefault(key_of(c), {"calls": 0, "cost": 0.0, "tokens_in": 0, "tokens_out": 0})
        g["calls"] += _st_num(c.get("calls"))
        g["cost"] += _st_num(c.get("cost_usd"))
        g["tokens_in"] += _st_num(c.get("tokens_in"))
        g["tokens_out"] += _st_num(c.get("tokens_out"))
    return groups


def _st_rows_match(rows, groups, label_of, total):
    if not isinstance(rows, list) or len(rows) != len(groups):
        return False
    for r in rows:
        g = groups.get(label_of(r))
        if g is None or _st_num(r.get("calls")) != g["calls"] or not _st_near(r.get("cost_usd"), g["cost"]):
            return False
    return _st_near(_st_sum(rows, "cost_usd"), total)


def verify_statement(directory, manifest):
    listed = [f["path"] for f in manifest.get("files", [])]
    if "statement/statement.json" not in listed:
        return [], {"present": False, "lines": ["statement: this export carries no cost statement"]}
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    try:
        with open(os.path.join(directory, "statement", "statement.json"), encoding="utf-8") as fh:
            st = json.load(fh)
        with open(os.path.join(directory, "statement", "cells.json"), encoding="utf-8") as fh:
            cells = json.load(fh)
        if not isinstance(cells, list) or "totals" not in st or "sections" not in st:
            raise ValueError("statement.json or cells.json is not in the expected shape")
    except (OSError, ValueError) as e:
        add("statement: files readable", False, str(e))
        return checks, {"present": True, "lines": [f"statement: cannot be read ({e})"]}
    total = st["totals"].get("cost_usd")
    cells_total = _st_sum(cells, "cost_usd")
    cells_calls = _st_sum(cells, "calls")
    add("statement: total equals the cells", _st_near(cells_total, total) and cells_calls == _st_num(st["totals"].get("calls")), f"{round(cells_total, 4)} from the cells, {total} stated")
    by_pm = _st_group(cells, lambda c: (c.get("provider") or "(no provider)", c.get("model")))
    s1 = (st["sections"].get("1") or {}).get("by_provider_model")
    ok1 = isinstance(s1, list) and len(s1) == len(by_pm)
    if ok1:
        for r in s1:
            g = by_pm.get((r.get("provider"), r.get("model")))
            if g is None or _st_num(r.get("calls")) != g["calls"] or not _st_near(r.get("cost_usd"), g["cost"]) or _st_num(r.get("tokens_in")) != g["tokens_in"] or _st_num(r.get("tokens_out")) != g["tokens_out"]:
                ok1 = False
                break
        ok1 = ok1 and _st_near(_st_sum(s1, "cost_usd"), total)
    add("statement: totals by provider and model equal the cells", ok1)
    section3 = st["sections"].get("3") or {}
    for field, label, none in _ST_DIMS:
        add(f"statement: allocation by {label} equals the cells and adds up to the total", _st_rows_match(section3.get(label), _st_group(cells, lambda c, f=field, n=none: c.get(f) or n), lambda r, l=label: r.get(l), total))
    add("statement: cover total equals the total", _st_near(((st.get("cover") or {}).get("totals") or {}).get("estimated_usd"), total))
    person = section3.get("person")
    if person:
        add("statement: allocation by person adds up to the total", _st_near(_st_sum(person.get("rows") or [], "cost_usd"), total))
    chargeback = [f for f in listed if f.startswith("statement/chargeback/")]
    if chargeback:
        csum = 0.0
        readable = True
        for f in chargeback:
            try:
                with open(os.path.join(directory, *f.split("/")), encoding="utf-8") as fh:
                    last = fh.read().strip().split(chr(10))[-1].split(",")
                csum += float(last[-1])
            except (OSError, ValueError):
                readable = False
        add("statement: chargeback files add up to the total", readable and _st_near(csum, total), f"{round(csum, 4)} across {len(chargeback)} files, {total} stated")
    failing = sum(1 for c in checks if not c["ok"])
    return checks, {"present": True, "cells": len(cells), "total_cost_usd": total, "calls": st["totals"].get("calls"), "failing": failing, "lines": [
        f"statement: {len(cells)} cells add up to {total} USD over {st['totals'].get('calls')} calls" + (f"; {failing} check{'' if failing == 1 else 's'} failed" if failing else ""),
        "statement: the check shows the stated totals are what the cells add up to. It does not show the cells are right: they are estimates frozen at close from the organization's own price table, not an invoice, and the statement is not an audit.",
    ]}


def verify_export(directory, emitter_keys=None):
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    try:
        with open(os.path.join(directory, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as e:
        add("manifest readable", False, str(e))
        return {"ok": False, "checks": checks}
    add("manifest readable", True)

    for f in manifest.get("files", []):
        full = os.path.join(directory, f["path"])
        if not os.path.exists(full):
            add(f"file present: {f['path']}", False)
            continue
        digest = file_sha256(full)
        add(f"file hash: {f['path']}", digest == f["sha256"], "" if digest == f["sha256"] else "hash differs from manifest")

    try:
        with open(os.path.join(directory, "records.jsonl"), encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError) as e:
        add("records readable", False, str(e))
        return {"ok": False, "checks": checks}

    bad = 0
    for rec in records:
        v = verify_record(rec)
        if not v["valid"]:
            bad += 1
            add(f"record {rec.get('record_id')}", False, "; ".join(v["reasons"]))
    add("records recompute", bad == 0, f"{len(records) - bad} of {len(records)} ok")

    by_chain = {}
    for rec in records:
        by_chain.setdefault(rec["chain_key"], []).append(rec)
    breaks = 0
    for group in by_chain.values():
        group.sort(key=lambda r: r["chain_seq"])
        by_seq = {r["chain_seq"]: r for r in group}
        for r in group:
            prev = by_seq.get(r["chain_seq"] - 1)
            if prev is not None and r.get("prev_record_hash") != prev["integrity"]["record_hash"]:
                breaks += 1
    add("chain links hold", breaks == 0, f"{breaks} broken links" if breaks else "")

    if manifest.get("complete"):
        for day in manifest.get("roots_included", []):
            root_file = os.path.join(directory, "roots", f"{day}.json")
            if not os.path.exists(root_file):
                add(f"root {day}", False, "root file missing")
                continue
            with open(root_file, encoding="utf-8") as fh:
                root = json.load(fh)
            day_records = [r for r in records if r["ingest_day"] == day]
            groups = {}
            for r in day_records:
                groups.setdefault(r["chain_key"], []).append(r)
            leaves = []
            for key in sorted(groups.keys()):
                group = sorted(groups[key], key=lambda r: r["chain_seq"])
                leaves.append(merkle_root([bytes.fromhex(r["integrity"]["record_hash"]) for r in group]))
            tenant = merkle_root(leaves).hex()
            ok = tenant == root["tenant_root"] and len(day_records) == root["record_count"]
            add(f"root {day}", ok, "" if ok else "recomputed root differs")
    else:
        add("daily roots", True, "partial export: roots are verified against a complete export only")

    # Integrity only: everything checked above is recomputable by anyone holding the bundle, so a
    # forger could recompute it too. Authenticity (did Provantix issue this export) is checked from
    # manifest.sig.json against Provantix's published keys by the node verifier (--keys); this
    # implementation does not check signatures and says so rather than implying it did.
    authenticity = {
        "state": "not_checked",
        "detail": "this verifier checks integrity only; use verify-export.mjs --keys to check that Provantix issued the export",
    }
    proof, proof_checks = verify_emitter_proof(directory, manifest, records, emitter_keys)
    checks.extend(proof_checks)
    recon, recon_checks = verify_reconciliation(directory, manifest, records)
    checks.extend(recon_checks)
    decision_checks, decision_summary = verify_decision_evidence(records)
    checks.extend(decision_checks)
    control_checks, control_summary = verify_control_evidence(records)
    checks.extend(control_checks)
    statement_checks, statement_summary = verify_statement(directory, manifest)
    checks.extend(statement_checks)
    return {"ok": all(c["ok"] for c in checks), "authenticity": authenticity, "emitter_proof": proof, "reconciliation": recon, "decision_evidence": decision_summary, "control_evidence": control_summary, "statement": statement_summary, "caveats": CAVEATS, "checks": checks}


def main(argv):
    keys_at = argv.index("--emitter-keys") if "--emitter-keys" in argv else -1
    args = [a for i, a in enumerate(argv) if i > 0 and not a.startswith("--") and not (keys_at >= 0 and i == keys_at + 1)]
    if not args:
        print("usage: python3 verify_export.py <exportDir> [--emitter-keys emitter-keys.pem|.json] [--json]", file=sys.stderr)
        return 2
    emitter_keys = None
    if keys_at >= 0:
        try:
            with open(argv[keys_at + 1], encoding="utf-8") as fh:
                emitter_keys = parse_emitter_keys(fh.read())
        except Exception as e:
            print(f"cannot read the emitter keys file: {e}", file=sys.stderr)
            return 2
    try:
        result = verify_export(args[0], emitter_keys)
    except Exception as e:  # unreadable or malformed input
        print(f"cannot verify {args[0]}: {e}", file=sys.stderr)
        return 2
    if "--json" in argv:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            suffix = f"  ({c['detail']})" if c["detail"] else ""
            print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['name']}{suffix}")
        print(f"NOT CHECKED  authenticity  ({result['authenticity']['detail']})")
        for line in result.get("emitter_proof", {}).get("lines", []):
            print(line)
        for line in result.get("reconciliation", {}).get("lines", []):
            print(line)
        if result.get("decision_evidence", {}).get("present"):
            for line in result["decision_evidence"]["lines"]:
                print(line)
        if result.get("control_evidence", {}).get("present"):
            for line in result["control_evidence"]["lines"]:
                print(line)
        if result.get("statement", {}).get("present"):
            for line in result["statement"]["lines"]:
                print(line)
        print("\nWhat a pass never means:")
        for c in CAVEATS:
            print(f"  - {c}")
        print("\nexport is consistent with itself (authenticity not checked)" if result["ok"] else "\nexport FAILED verification")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
