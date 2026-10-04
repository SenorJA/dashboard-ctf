---
name: supply-chain-security
description: "Software supply chain security: SBOM generation (syft/cdxgen), vulnerability triage of dependencies (grype/trivy), dependency-confusion and typosquatting detection, registry/package-manager attacks (npm/pip/pypi), provenance verification and artifact signing (cosign/SLSA), lockfile and transitive-dependency review, malicious package analysis."
category: supply-chain
allowed_tools:
  - syft
  - grype
  - trivy
  - cosign
  - slsa-verifier
  - cdxgen
  - npm
  - pip
  - git
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Supply Chain / SBOM Security Methodology

## 1. Inventory (SBOM)
- `syft packages dir:. -o spdx-json` / `cdxgen` → CycloneDX/SPDX; pin the tool + versions in the report.
- Include base images, toolchains and CI caches, not just runtime deps.

## 2. Vulnerability triage
- `grype .` / `trivy fs .` → rate by CVSS + reachability (call-graph-aware where possible).
- Separate OSS vs commercial: only actionable build-time findings belong in the final assessment.

## 3. Attack-surface analysis
- **Dependency confusion**: does an internal-named package exist publicly with a higher version?
- **Typosquatting / namespace confusion**: compare the resolved tarball hash (registry) against expected.
- **Provenance/signing**: `cosign verify`/`slsa-verifier` on images/artifacts; flag unsigned production artifacts.
- **Malicious packages**: deobfuscate install scripts (`npm`/`pip` postinstall), suspicious domains, prebuilt binaries.

## 4. Remediation & policy
- Suggest lockfile pinning + hash verification, attestation (SLSA L3), signed publishes, registry scoping.
- Score the chain posture A–F and attach reproducible evidence (SBOM + diff).

## 5. Findings
- Evidence: SBOM extract + finding-specific diff (package/hash/version) + invocation log.
- Reproducible PoC: re-run command + lockfile diff; never include private registry tokens.