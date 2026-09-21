# tigergate-test-java

Security-scanner validation fixture for Java: deliberately vulnerable code,
dependencies, secrets, infrastructure and SBOMs, with a machine-readable
ground-truth manifest so scanner precision/recall can be measured exactly.

See [SECURITY_FIXTURES.md](SECURITY_FIXTURES.md) for the layout and
[EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md) for the full list of planted findings.

```
./mvnw -q compile test-compile                      # builds all fixtures against the real deps (wrapper: no local Maven needed)
java -ea -cp target/classes:target/test-classes AppTest
scripts/gen-expected-findings.py                    # regenerate ground truth from markers
scripts/score.py <scanner-output.sarif>             # score a scanner run
```

**Nothing here is safe to deploy.** `.github/workflows/insecure-ci.yml` is guarded
with `if: false` so it can never execute.

The wrapper also self-heals a missing or broken `JAVA_HOME` (a common scanner-runner
misconfiguration): it falls back to `java` on `PATH`, then standard JDK install roots,
and only fails if no JDK exists on the machine at all.
# tigergate-test-java
