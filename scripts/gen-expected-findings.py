#!/usr/bin/env python3
"""
Generate the ground-truth manifest (expected-findings.json + EXPECTED_FINDINGS.md)
from inline markers in the fixture files.

Marker grammar (any comment syntax):
    FINDING: <ID> <CWE-n|CVE-y-n> <slug> [(free-text note)]
    SAFE:    <ID> <slug> [(note)]            -- negative control, must NOT be reported

If the marker is on a comment-only line the sink is the next non-blank,
non-comment line (Dockerfile, .properties, .env, "absent attribute" cases);
otherwise the sink is the marker line itself.

Usage:
    scripts/gen-expected-findings.py            # rewrite both outputs
    scripts/gen-expected-findings.py --check    # exit 1 if outputs are stale
"""
import json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_OUT = os.path.join(ROOT, "expected-findings.json")
MD_OUT = os.path.join(ROOT, "EXPECTED_FINDINGS.md")

MARK = re.compile(r"(FINDING|SAFE):\s+([A-Z]+-\d{3})\s+(\S+)(?:\s+(.*?))?\s*(?:-->|\*/)?\s*$")
COMMENT_ONLY = re.compile(r"^\s*(#|//|/\*|\*|<!--|--)")
CVE = re.compile(r"CVE-\d{4}-\d+")
SKIP_DIRS = {".git", "target", "node_modules", ".terraform"}
SKIP_FILES = {"expected-findings.json", "EXPECTED_FINDINGS.md", "SECURITY_FIXTURES.md", "README.md"}
SKIP_SUFFIX = (".pem", ".png", ".jar", ".class")

CATEGORY = {
    "SAST": "SAST", "SEC": "Secrets", "IAC": "IaC", "SCA": "SCA", "SBOM": "SBOM", "CTRL": "Negative control",
}

# File-level findings that have no line to mark (binary keys, JSON without comments, SBOM diffs).
FILE_LEVEL = [
    ("SEC-043", "Secrets", "config/fixture_deploy_key.pem", "CWE-798", "committed-rsa-private-key", "PKCS#8 RSA private key file"),
    ("SEC-044", "Secrets", "config/fixture_ec_key.pem", "CWE-798", "committed-ec-private-key", "EC private key file"),
    ("SEC-045", "Secrets", "config/gcp-service-account.json", "CWE-798", "gcp-service-account-key-json", "private_key field holds a PEM"),
    ("SBOM-001", "SBOM", "sbom/bom-stale.cdx.json", "CWE-1395", "sbom-version-understated", "log4j-core listed as 2.17.1; build resolves 2.14.1 (CVE-2021-44228 hidden)"),
    ("SBOM-002", "SBOM", "sbom/bom-stale.cdx.json", "CWE-1395", "sbom-component-omitted", "jackson-databind 2.9.8 present in build, absent from SBOM"),
    ("SBOM-003", "SBOM", "sbom/bom-stale.cdx.json", "CWE-1395", "sbom-phantom-component", "com.example:phantom-lib 1.0.0 in SBOM, not in build"),
    ("SBOM-004", "SBOM", "sbom/bom.cdx.json", "CVE-2021-44228", "sbom-ingest-known-vulnerable", "Scanning the accurate SBOM alone must surface every SCA-0xx CVE without access to pom.xml"),
    ("SBOM-005", "SBOM", "sbom/bom.spdx.json", "CVE-2021-44228", "spdx-ingest-known-vulnerable", "Same expectation for the SPDX rendition"),
    ("SCA-016", "SCA", "sbom/bom.cdx.json", "CVE-2017-5638", "transitive-ognl", "ognl 3.1.29 pulled in by struts2-core; transitive CVE must be attributed to the struts2-core root"),
    ("SCA-017", "SCA", "sbom/bom.cdx.json", "CVE-2022-22965", "transitive-spring-core", "spring-core 5.3.17 pulled in by spring-beans"),
    ("SCA-018", "SCA", "Dockerfile", "CWE-1104", "container-base-image-cves", "openjdk:8-jdk-alpine (alpine 3.9) has hundreds of OS-package CVEs; image scanning must report them"),
    ("SCA-019", "SCA", "docker-compose.yml", "CWE-1104", "container-postgres-9.6-eol", "postgres:9.6 image is end-of-life"),
]


def tracked_files():
    try:
        out = subprocess.check_output(["git", "-C", ROOT, "ls-files", "--cached", "--others", "--exclude-standard"], text=True)
        files = [f for f in out.splitlines() if f]
    except Exception:
        files = []
        for d, dn, fn in os.walk(ROOT):
            dn[:] = [x for x in dn if x not in SKIP_DIRS]
            files += [os.path.relpath(os.path.join(d, f), ROOT) for f in fn]
    return sorted(f for f in files if f not in SKIP_FILES and not f.endswith(SKIP_SUFFIX)
                  and not any(f.startswith(s + "/") for s in SKIP_DIRS))


CLOSING = re.compile(r"^\s*([}\]\)]|EOT|---)\s*$")


def _indent(s):
    return len(s) - len(s.lstrip())


def _is_code(s):
    return bool(s.strip()) and not COMMENT_ONLY.match(s)


def sink_span(lines, i, note):
    """i is 0-based marker index. Returns (kind, line, line_end) 1-based.

    exact : marker shares the line with the sink.
    next  : comment-only marker; sink is the next code line (Dockerfile, .env, ...).
    block : comment-only marker describing an ABSENT attribute; sink is the
            enclosing block, opener..closer, which is where scanners anchor
            missing-attribute findings.
    """
    if not COMMENT_ONLY.match(lines[i]):
        return "exact", i + 1, i + 1
    j = i + 1
    while j < len(lines) and not _is_code(lines[j]):
        j += 1
    nxt = j + 1 if j < len(lines) else i + 1
    ind = _indent(lines[i])
    absent = "absent" in note.lower() or (j < len(lines) and CLOSING.match(lines[j]))
    if ind == 0 or not absent:
        return "next", nxt, nxt
    k = i - 1
    while k >= 0 and not (_is_code(lines[k]) and _indent(lines[k]) < ind):
        k -= 1
    if k < 0:
        return "next", nxt, nxt
    bind = _indent(lines[k])
    e = k + 1
    while e < len(lines) and not (_is_code(lines[e]) and _indent(lines[e]) <= bind):
        e += 1
    # HCL/JSON closers sit at the opener's indent; YAML has no closer, so back up to the last code line.
    end = e + 1 if e < len(lines) and CLOSING.match(lines[e]) else e
    while end - 1 > k and not _is_code(lines[end - 1]):
        end -= 1
    return "block", k + 1, end


def scan():
    findings = []
    for rel in tracked_files():
        path = os.path.join(ROOT, rel)
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except (OSError, IsADirectoryError):
            continue
        for i, line in enumerate(lines):
            m = MARK.search(line)
            if not m:
                continue
            kind, fid, ref, rest = m.groups()
            rest = (rest or "").strip()
            note = ""
            if kind == "SAFE":
                slug, ref = ref, None
            else:
                mm = re.match(r"(\S+)\s*(?:\((.*)\))?$", rest)
                slug, note = (mm.group(1), mm.group(2) or "") if mm else (rest, "")
            if kind == "FINDING":
                nm = re.match(r"(\S+)\s*\((.*)\)\s*$", rest)
                if nm:
                    slug, note = nm.group(1), nm.group(2)
            else:
                nm = re.match(r"\((.*)\)\s*$", rest)
                note = nm.group(1) if nm else rest
            prefix = fid.split("-")[0]
            lk, ln, le = sink_span(lines, i, note)
            findings.append({
                "id": fid,
                "category": CATEGORY.get(prefix, prefix),
                "expected": kind == "FINDING",
                "file": rel,
                "marker_line": i + 1,
                "line": ln,
                "line_end": le,
                "line_kind": lk,
                "ref": ref,
                "cves": list(dict.fromkeys(CVE.findall(line))) if kind == "FINDING" else [],
                "slug": slug,
                "note": note,
            })
    for fid, cat, rel, ref, slug, note in FILE_LEVEL:
        findings.append({"id": fid, "category": cat, "expected": True, "file": rel, "marker_line": None,
                         "line": None, "line_end": None, "line_kind": "file", "ref": ref,
                         "cves": list(dict.fromkeys(CVE.findall(ref + " " + note))), "slug": slug, "note": note})
    ids = [f["id"] for f in findings]
    dups = sorted({x for x in ids if ids.count(x) > 1})
    if dups:
        sys.exit(f"duplicate finding ids: {dups}")
    findings.sort(key=lambda f: (f["category"], f["id"]))
    return findings


def render_md(findings):
    exp = [f for f in findings if f["expected"]]
    ctl = [f for f in findings if not f["expected"]]
    cats = {}
    for f in exp:
        cats.setdefault(f["category"], []).append(f)
    out = ["# Expected findings (ground truth)", "",
           "Generated by `scripts/gen-expected-findings.py` from inline `FINDING:` / `SAFE:` markers. "
           "Do not edit by hand. Machine-readable copy: `expected-findings.json`. "
           "Score a scanner run with `scripts/score.py`.", "",
           "| Category | Expected findings |", "|---|---|"]
    out += [f"| {c} | {len(v)} |" for c, v in sorted(cats.items())]
    out += [f"| **Total** | **{len(exp)}** |", f"| Negative controls (must not fire) | {len(ctl)} |", ""]
    for c, v in sorted(cats.items()):
        out += [f"## {c} ({len(v)})", "", "| ID | Location | CWE / CVE | Description | Note |", "|---|---|---|---|---|"]
        for f in v:
            if not f["line"]:
                loc = f"`{f['file']}` (file)"
            elif f["line_end"] != f["line"]:
                loc = f"`{f['file']}:{f['line']}-{f['line_end']}`"
            else:
                loc = f"`{f['file']}:{f['line']}`"
            out.append(f"| {f['id']} | {loc} | {f['ref']} | {f['slug']} | {f['note']} |")
        out.append("")
    out += ["## Negative controls", "", "Correctly written code/config. Any finding reported at these locations is a **false positive**.", "",
            "| ID | Location | Description |", "|---|---|---|"]
    out += [f"| {f['id']} | `{f['file']}:{f['line']}` | {f['slug']} {('— ' + f['note']) if f['note'] else ''} |" for f in ctl]
    out.append("")
    return "\n".join(out)


def main():
    findings = scan()
    js = json.dumps({"schema": 1, "repo": "tigergate-test-java", "line_tolerance": 2, "findings": findings}, indent=2) + "\n"
    md = render_md(findings)
    if "--check" in sys.argv:
        cur_js = open(JSON_OUT).read() if os.path.exists(JSON_OUT) else ""
        cur_md = open(MD_OUT).read() if os.path.exists(MD_OUT) else ""
        if cur_js != js or cur_md != md:
            sys.exit("expected-findings.json / EXPECTED_FINDINGS.md are stale; run scripts/gen-expected-findings.py")
        print(f"manifest in sync: {sum(f['expected'] for f in findings)} expected, "
              f"{sum(not f['expected'] for f in findings)} controls")
        return
    open(JSON_OUT, "w").write(js)
    open(MD_OUT, "w").write(md)
    n = sum(f["expected"] for f in findings)
    print(f"wrote {n} expected findings + {len(findings) - n} negative controls")
    for c in sorted({f["category"] for f in findings}):
        print(f"  {c:18s} {sum(1 for f in findings if f['category'] == c)}")


if __name__ == "__main__":
    main()
