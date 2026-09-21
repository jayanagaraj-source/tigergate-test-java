# Deliberately insecure test fixtures

This repository validates security scanners (SCA, SAST, secret, IaC, SBOM,
container and CI/CD scanning). It deliberately contains outdated dependencies,
unsafe code patterns, fake hard-coded credentials, and insecure infrastructure
settings. **Do not deploy, apply, or reuse anything in it.**

Every credential is fabricated. The AWS keys are the official AWS documentation
example values; the private keys under `config/` were generated for this fixture
and have never been used anywhere.

## Ground truth

Every planted issue is tagged inline:

```
... sink ...   // FINDING: SAST-001 CWE-89 sqli-statement-concat
... safe ...   // SAFE: CTRL-001 parameterised-query
```

`scripts/gen-expected-findings.py` turns the markers into
[expected-findings.json](expected-findings.json) and
[EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md). `SAFE:` markers are negative
controls: correct code that must **not** be reported.

| Category | Where | What it exercises |
|---|---|---|
| SCA | `pom.xml`, `sbom/`, `Dockerfile`, `docker-compose.yml` | 15 direct deps with published CVEs, transitive attribution (ognl via struts, spring-core via spring-beans), scope handling (test / provided), EOL base images, old Terraform provider |
| SAST | `src/*.java` | SQLi, command injection, path traversal, Zip Slip, XXE (5 APIs), deserialization (4 libs), weak crypto, TLS bypass, SSRF, XSS, open redirect, header/log injection, LDAP/XPath/JNDI/script injection, unsafe reflection, ReDoS, TOCTOU, temp files, cleartext storage/transmission, hard-coded credentials, reachability of Log4Shell/Text4Shell sinks |
| Secrets | `src/Secrets.java`, `config/`, `.env`, `tests/`, IaC, CI | AWS, GitHub, Slack, Stripe (test + live), Google, SendGrid, Twilio, OpenAI, JWT, connection strings, basic-auth URLs, RSA/EC private keys, GCP service-account JSON, netrc, Azure storage, base64 in k8s Secret, Dockerfile ENV/ARG, workflow env |
| IaC | `terraform/`, `kubernetes/`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/` | AWS (S3, EC2, RDS, IAM, KMS, CloudTrail, EKS, ALB, Lambda, SQS/SNS, ECR, EFS, DynamoDB), Kubernetes (privileged, hostPath, RBAC, secrets, ingress), Docker, Compose, GitHub Actions (pull_request_target, expression injection, unpinned actions) |
| SBOM | `sbom/` | CycloneDX 1.4 JSON+XML and SPDX 2.3 of the real dependency tree; `bom-stale.cdx.json` carries three deliberate drifts (understated version, omitted component, phantom component) |

## Scoring a scanner

```
scripts/score.py tigergate-output.sarif            # SARIF 2.1.0
scripts/score.py results.json --format json        # [{"file","line","cwe"|"ref","rule","message"}]
scripts/score.py results.csv  --format csv         # file,line,ref,message
scripts/score.py out.sarif --category SAST --tolerance 0 --json report.json
```

Outcome classes: `TP-strict` (location + CWE/CVE), `TP-loose` (location only),
`FN`, `FP-control` (hit on a `SAFE:` location – a definite false positive),
`duplicate` (second rule on an already-matched sink), `unlisted` (a hit the
manifest does not know about — review it; it may be a genuine extra detection
worth adding a marker for).

## Keeping the manifest honest

* Adding a fixture = add a marker; run `scripts/gen-expected-findings.py`.
* Changing `pom.xml` = run `./mvnw cyclonedx:makeAggregateBom`, copy `target/bom.json`
  to `sbom/bom.cdx.json` (and `.xml`), regenerate `sbom/bom.spdx.json`, and
  re-apply the three drifts to `sbom/bom-stale.cdx.json`.
* CI (`.github/workflows/test.yml`) fails if either the SBOM or the manifest is stale.
