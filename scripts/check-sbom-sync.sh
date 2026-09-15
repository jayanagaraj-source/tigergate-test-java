#!/usr/bin/env bash
# Verifies sbom/bom.cdx.json still matches what the build actually resolves.
# Compares the component set (purl) only; serial number / timestamp differ by design.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f target/bom.json ] || mvn -B -q cyclonedx:makeAggregateBom
diff <(jq -r '.components[].purl' target/bom.json | sort) \
     <(jq -r '.components[].purl' sbom/bom.cdx.json | sort) \
  && echo "SBOM in sync ($(jq '.components|length' sbom/bom.cdx.json) components)"
