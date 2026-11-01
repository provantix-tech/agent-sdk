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
    return {"ok": all(c["ok"] for c in checks), "authenticity": authenticity, "emitter_proof": proof, "checks": checks}


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
        print("\nexport is consistent with itself (authenticity not checked)" if result["ok"] else "\nexport FAILED verification")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
