#!/usr/bin/env bash
# Verifies sbom/bom.cdx.json still matches what the build actually resolves.
# Compares the component set (purl) only; serial number / timestamp differ by design.
set -euo pipefail
cd "$(dirname "$0")/.."
MVN=./mvnw; command -v "$MVN" >/dev/null 2>&1 || MVN=mvn
[ -f target/bom.json ] || "$MVN" -B -q cyclonedx:makeAggregateBom
diff <(jq -r '.components[].purl' target/bom.json | sort) \
     <(jq -r '.components[].purl' sbom/bom.cdx.json | sort) \
  && echo "SBOM in sync ($(jq '.components|length' sbom/bom.cdx.json) components)"
