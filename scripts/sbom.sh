#!/bin/bash
# SBOM Generator for PolkitGuard

VERSION="${1:-1.6.0}"
OUTPUT="${2:-sbom.json}"

echo "Generating SBOM for PolkitGuard v$VERSION..."

cat > "$OUTPUT" << EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:$(uuidgen 2>/dev/null || echo random)",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [
      {
        "name": "PolkitGuard",
        "version": "$VERSION"
      }
    ]
  },
  "components": [
    {
      "type": "application",
      "name": "polkitguard",
      "version": "$VERSION",
      "description": "Security scanner for Linux Polkit configurations",
      "licenses": [{"license": {"id": "MIT"}}],
      "externalReferences": [
        {"type": "vcs", "url": "https://github.com/Ghostalex07/PolkitGuard"}
      ]
    }
  ],
  "dependencies": []
}
EOF

echo "SBOM written to: $OUTPUT"