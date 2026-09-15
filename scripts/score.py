#!/usr/bin/env python3
"""
Score a scanner run against expected-findings.json.

    scripts/score.py results.sarif                 # SARIF 2.1.0 (auto-detected)
    scripts/score.py results.json --format json    # [{"file","line","ref"?,"rule"?,"message"?}, ...]
    scripts/score.py results.csv  --format csv     # file,line,ref,message
    scripts/score.py results.sarif --category SAST --tolerance 3 --json report.json

Matching rules
  * file: scanner path is normalised (absolute -> repo-relative, leading ./ stripped).
  * line: a hit must fall inside [line - tol, line_end + tol]; file-level findings
          accept any hit in the file.
  * ref : the expected CWE or any of its CVEs must appear in the hit's rule id,
          tags, or message. Location-only matches are reported as "loose".

Outcome classes
  TP-strict   location and CWE/CVE both match
  TP-loose    location matches, classification differs / missing
  FN          nothing reported at the expected location
  FP-control  a hit landed on a negative control  -> definite false positive
  unlisted    a hit that matched nothing (may be a real extra detection - review)
"""
import argparse, csv, json, os, re, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = re.compile(r"(CWE-\d+|CVE-\d{4}-\d+)", re.I)


def norm_path(p):
    p = (p or "").replace("\\", "/")
    p = re.sub(r"^file://", "", p)
    if p.startswith(ROOT + "/"):
        p = p[len(ROOT) + 1:]
    p = re.sub(r"^\./", "", p)
    # scanners that ran from a different checkout: keep the tail that exists here
    if not os.path.exists(os.path.join(ROOT, p)):
        parts = p.split("/")
        for i in range(1, len(parts)):
            cand = "/".join(parts[i:])
            if os.path.exists(os.path.join(ROOT, cand)):
                return cand
    return p


def refs_in(*texts):
    out = set()
    for t in texts:
        if not t:
            continue
        for m in REF.findall(str(t)):
            m = m.upper()
            # normalise "CWE-089" -> "CWE-89"
            if m.startswith("CWE-"):
                m = "CWE-" + str(int(m[4:]))
            out.add(m)
    return out


def load_sarif(doc):
    hits = []
    for run in doc.get("runs", []):
        rules = {}
        for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            rules[r.get("id")] = r
        for ext in run.get("tool", {}).get("extensions") or []:
            for r in ext.get("rules") or []:
                rules[r.get("id")] = r
        for res in run.get("results", []):
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or ""
            rule = rules.get(rid, {})
            tags = " ".join((rule.get("properties") or {}).get("tags") or [])
            msg = (res.get("message") or {}).get("text", "")
            rel = " ".join(str(x) for x in (rule.get("relationships") or []))
            locs = res.get("locations") or [{}]
            for loc in locs:
                pl = loc.get("physicalLocation") or {}
                uri = (pl.get("artifactLocation") or {}).get("uri", "")
                line = (pl.get("region") or {}).get("startLine")
                hits.append({"file": norm_path(uri), "line": line, "rule": rid, "message": msg,
                             "refs": refs_in(rid, tags, msg, rel, rule.get("name"), (rule.get("fullDescription") or {}).get("text"))})
    return hits


def load_flat(items):
    return [{"file": norm_path(i.get("file") or i.get("path")), "line": i.get("line"), "rule": i.get("rule", ""),
             "message": i.get("message", ""), "refs": refs_in(i.get("ref"), i.get("cwe"), i.get("cve"), i.get("rule"), i.get("message"))}
            for i in items]


def load(path, fmt):
    if fmt == "csv" or (fmt == "auto" and path.endswith(".csv")):
        with open(path, newline="") as fh:
            return load_flat(list(csv.DictReader(fh)))
    doc = json.load(open(path))
    if fmt == "sarif" or (fmt == "auto" and isinstance(doc, dict) and "runs" in doc):
        return load_sarif(doc)
    if isinstance(doc, dict):
        doc = doc.get("results") or doc.get("findings") or doc.get("issues") or []
    return load_flat(doc)


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results")
    ap.add_argument("--format", choices=["auto", "sarif", "json", "csv"], default="auto")
    ap.add_argument("--expected", default=os.path.join(ROOT, "expected-findings.json"))
    ap.add_argument("--tolerance", type=int, default=None, help="line slack (default: manifest's line_tolerance)")
    ap.add_argument("--category", action="append", help="only score these categories (repeatable)")
    ap.add_argument("--json", help="write machine-readable report here")
    ap.add_argument("--show-unlisted", action="store_true")
    a = ap.parse_args()

    manifest = json.load(open(a.expected))
    tol = a.tolerance if a.tolerance is not None else manifest.get("line_tolerance", 2)
    findings = manifest["findings"]
    if a.category:
        want = {c.lower() for c in a.category}
        findings = [f for f in findings if f["category"].lower() in want or (not f["expected"])]
    expected = [f for f in findings if f["expected"]]
    controls = [f for f in findings if not f["expected"]]

    hits = load(a.results, a.format)
    for h in hits:
        h["line"] = to_int(h["line"])
        h["used"] = False
    by_file = defaultdict(list)
    for h in hits:
        by_file[h["file"]].append(h)

    def dist(f, h):
        """0 when the hit is inside the expected span, else lines outside it; None if out of tolerance."""
        if f["line"] is None:
            return 0
        if h["line"] is None:
            return None
        if f["line"] <= h["line"] <= f["line_end"]:
            return 0
        d = f["line"] - h["line"] if h["line"] < f["line"] else h["line"] - f["line_end"]
        return d if d <= tol else None

    def want_refs(f):
        s = set(f["cves"])
        if f["ref"]:
            s.add(f["ref"].upper())
        return s

    # One-to-one assignment. Order: nearest line first, then CWE/CVE match.
    # Each hit explains at most one expected finding so that a neighbouring
    # line's detection cannot silently cover a miss.
    # Tie-breaks: narrowest expected span wins (an exact-line finding beats the
    # block that contains it), then slug/rule-name similarity for findings that
    # share both line and CWE.
    def span_size(f):
        return 10 ** 6 if f["line"] is None else f["line_end"] - f["line"] + 1

    def slug_score(f, h):
        toks = {t for t in re.split(r"[^a-z0-9]+", f["slug"].lower()) if len(t) > 2}
        text = (h["rule"] + " " + h["message"]).lower()
        return -sum(1 for t in toks if t in text)

    pairs = []
    for fi, f in enumerate(expected):
        for h in by_file.get(f["file"], []):
            d = dist(f, h)
            if d is None:
                continue
            strict = bool(h["refs"] & want_refs(f))
            pairs.append((d, 0 if strict else 1, span_size(f), slug_score(f, h), fi, h))
    pairs.sort(key=lambda t: t[:4])
    assigned = {}
    for d, strict_rank, _, _, fi, h in pairs:
        if fi in assigned or h["used"]:
            continue
        assigned[fi] = (h, "TP-strict" if strict_rank == 0 else "TP-loose")
        h["used"] = True

    rows = []
    for fi, f in enumerate(expected):
        chosen, outcome = assigned.get(fi, (None, "FN"))
        rows.append({"id": f["id"], "category": f["category"], "file": f["file"], "line": f["line"],
                     "line_end": f["line_end"], "ref": f["ref"], "outcome": outcome,
                     "hit_rule": chosen["rule"] if chosen else None, "hit_line": chosen["line"] if chosen else None})

    fp_control = []
    for c in controls:
        for h in by_file.get(c["file"], []):
            if not h["used"] and dist(c, h) is not None:
                h["used"] = True
                fp_control.append({"control": c["id"], "file": c["file"], "line": h["line"], "rule": h["rule"], "message": h["message"][:120]})

    # Leftover hits sitting exactly on an already-matched span are duplicates (second rule on
    # the same sink), not false positives. Anything else is unlisted.
    duplicates, unlisted = [], []
    for h in hits:
        if h["used"]:
            continue
        if any(dist(expected[fi], h) == 0 for fi in assigned if expected[fi]["file"] == h["file"]):
            duplicates.append(h)
        else:
            unlisted.append({"file": h["file"], "line": h["line"], "rule": h["rule"], "message": h["message"][:120]})

    n = len(expected)
    ts = sum(r["outcome"] == "TP-strict" for r in rows)
    tl = sum(r["outcome"] == "TP-loose" for r in rows)
    fn = n - ts - tl
    fpc = len(fp_control)
    prec_den = ts + tl + fpc
    report = {
        "results_file": a.results, "hits_total": len(hits), "expected": n, "controls": len(controls), "tolerance": tol,
        "tp_strict": ts, "tp_loose": tl, "fn": fn, "fp_control": fpc, "duplicates": len(duplicates), "unlisted": len(unlisted),
        "recall_strict": round(ts / n, 4) if n else None,
        "recall_loose": round((ts + tl) / n, 4) if n else None,
        "precision_vs_controls": round((ts + tl) / prec_den, 4) if prec_den else None,
        "per_category": {},
        "rows": rows, "fp_control": fp_control, "unlisted": unlisted,
    }
    cats = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        c = cats[r["category"]]
        c[0] += 1
        c[1] += r["outcome"] == "TP-strict"
        c[2] += r["outcome"] == "TP-loose"
    for k, (t, s, l) in sorted(cats.items()):
        report["per_category"][k] = {"expected": t, "tp_strict": s, "tp_loose": l, "fn": t - s - l,
                                     "recall_strict": round(s / t, 4), "recall_loose": round((s + l) / t, 4)}

    print(f"scanner hits: {len(hits)}   expected: {n}   controls: {len(controls)}   line tolerance: ±{tol}\n")
    print(f"{'category':18s} {'expected':>8s} {'strict':>7s} {'loose':>6s} {'missed':>7s} {'recall(strict)':>15s} {'recall(loose)':>14s}")
    for k, v in report["per_category"].items():
        print(f"{k:18s} {v['expected']:8d} {v['tp_strict']:7d} {v['tp_loose']:6d} {v['fn']:7d} {v['recall_strict']:15.1%} {v['recall_loose']:14.1%}")
    print(f"{'TOTAL':18s} {n:8d} {ts:7d} {tl:6d} {fn:7d} {report['recall_strict']:15.1%} {report['recall_loose']:14.1%}")
    print(f"\nfalse positives on negative controls: {fpc} / {len(controls)} controls"
          + (f"   (precision vs controls {report['precision_vs_controls']:.1%})" if prec_den else ""))
    print(f"duplicate hits on already-matched sinks: {len(duplicates)}")
    print(f"unlisted hits (not in manifest, review manually): {len(unlisted)}")
    if fp_control:
        print("\nFP on controls:")
        for x in fp_control:
            print(f"  {x['control']:9s} {x['file']}:{x['line']}  {x['rule']}  {x['message']}")
    missed = [r for r in rows if r["outcome"] == "FN"]
    if missed:
        print(f"\nmissed ({len(missed)}):")
        for r in missed:
            span = f"{r['line']}" + (f"-{r['line_end']}" if r["line_end"] and r["line_end"] != r["line"] else "") if r["line"] else "file"
            print(f"  {r['id']:9s} {r['file']}:{span}  {r['ref'] or ''}")
    loose = [r for r in rows if r["outcome"] == "TP-loose"]
    if loose:
        print(f"\nlocation matched but CWE/CVE not reported ({len(loose)}):")
        for r in loose:
            print(f"  {r['id']:9s} {r['file']}:{r['line']}  expected {r['ref']}  got rule={r['hit_rule']}")
    if a.show_unlisted and unlisted:
        print("\nunlisted:")
        for x in unlisted:
            print(f"  {x['file']}:{x['line']}  {x['rule']}  {x['message']}")
    if a.json:
        json.dump(report, open(a.json, "w"), indent=2)
        print(f"\nreport written to {a.json}")


if __name__ == "__main__":
    main()
