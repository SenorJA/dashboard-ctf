---
name: k8s-rbac-audit
description: "Kubernetes RBAC audit. Cluster privilege escalation, service account tokens, Pod security."
category: cloud
allowed_tools:
  - kubectl
  - kube-bench
  - kubiscan
  - curl
  - python
version: "1.0.0"
author: "MIRV"
---

# Kubernetes RBAC Audit Methodology

## 1. When to Use
- Hardening a Kubernetes cluster before production or as part of a periodic security review.
- A pod was compromised and you must check whether its service account could escalate to cluster-admin.
- A CSPM (Kubescape, Aqua) reports findings and you must validate, prioritise, and remediate.
- Compliance audit (CIS Kubernetes Benchmark, SOC2) requires evidence of RBAC posture.
- After onboarding a new namespace or team, to detect privilege drift from baseline.

## 2. Prerequisites
- `kubectl` configured with a kubeconfig that has `cluster-admin` (audit) or `view` (read-only) on the target cluster.
- Cluster access (network reachability to the API server, port 6443).
- `kube-bench` for CIS Kubernetes Benchmark node/control-plane checks.
- `kubiscan` (Python) for RBAC risk scoring; `kubectl-who-can` as an alternative.
- `curl` for anonymous API endpoint verification (e.g. `/metrics`, `/debug/pprof`).
- `python` with `kubernetes` client for custom queries.
- Authorisation to run read-only checks; never mutate RBAC without change control.
- A baseline of expected Roles/ClusterRoles and service accounts for diffing.

## 3. Workflow
1. **Cluster context & version**
   - `kubectl config current-context` and `kubectl version --short` → confirm target and supported API version.
   - `kubectl get nodes -o wide` → node OS, kubelet version; flag any node on an unsupported/EOL kubelet.
2. **RBAC enumeration**
   - `kubectl get clusterrole -o json | jq '.items[] | {name:.metadata.name, rules:.rules}'` → enumerate all ClusterRoles.
   - `kubectl get clusterrolebinding -o json | jq '.items[] | {name:.metadata.name, role:.roleRef.name, subjects:.subjects}'` → who is bound to what.
   - Flag any subject bound to `cluster-admin` that is not a known platform component.
   - `kubectl auth can-i --list --as=system:serviceaccount:{ns}:{sa}` → enumerate effective permissions of a given service account.
3. **Privilege-escalation paths**
   - `kubiscan -r "/path/to/cluster_rbac.json" -c "priv-escalation"` → score RBAC for escalation paths.
   - High-risk verbs to flag: `escalate`, `bind`, `impersonate`, `*` on `roles`/`clusterroles`.
   - `pods/exec`, `pods/attach`, `nodes/proxy` — allow an SA to escape its pod.
   - `kubectl auth can-i create pods --as=system:serviceaccount:{ns}:{sa}` → if yes + hostPath/PSP bypass, full node compromise is possible.
4. **Service account token audit**
   - `kubectl get sa -A -o json | jq '.items[] | {ns:.metadata.namespace, name:.metadata.name, automount:.automountServiceAccountToken}'` → flag SAs with `automount: true` that do not need API access.
   - Long-lived tokens: `kubectl get secret -A -o json | jq '.items[] | select(.type=="kubernetes.io/service-account-token")'` → in 1.24+ tokens are bound and expire; pre-1.24 secrets are permanent — flag clusters below 1.24.
   - Per-pod: `kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.spec.serviceAccountName}{"\n"}{end}'` → map pods to SAs and validate least privilege.
5. **Pod Security & admission**
   - `kubectl get psp -o json` (deprecated in 1.25) → flag privileged PSPs bound to all SAs.
   - Pod Security Admission (1.25+): `kubectl get namespace {ns} -o jsonpath='{.metadata.labels}'` → confirm `pod-security.kubernetes.io/enforce=restricted`.
   - `kube-bench --check=CIS-5.1.*` → Pod Security Standards compliance per namespace.
6. **Network policies & API exposure**
   - `kubectl get networkpolicy -A` → namespaces without a default-deny policy are open east-west.
   - `kubectl get svc -A | grep LoadBalancer` → flag LB services exposed to `0.0.0.0/0`.
   - API server: `curl -k https://{apiserver}/healthz` and `/metrics` → confirm `/debug/pprof` is disabled and `--anonymous-auth=false`.
7. **Secrets hygiene**
   - `kubectl get secrets -A -o json | jq '.items[] | {ns:.metadata.namespace, name:.metadata.name, type:.type}'` → flag secrets of type `Opaque` containing DB/app credentials not backed by an external secrets store (Vault, CSI Secrets Store).
   - etcd encryption at rest: `kubectl get --raw=/api/v1/namespaces/kube-system/secrets/cluster-info` is not enough — check the API server `--encryption-provider-config` flag.
8. **Decision point**: any SA bound to `cluster-admin` (not a platform component), any RBAC rule with `escalate`/`impersonate`, or any namespace with `pod-security=enforce=privileged` is a critical finding requiring same-day remediation under change control.

## 4. Verification
- Cross-check `kubiscan` / `who-can` output with raw `kubectl auth can-i` for the same subject to avoid false positives.
- Map findings to **CIS Kubernetes Benchmark** (e.g. `5.1.1` no privileged PSP, `5.1.5` default deny network policy, `5.3.2` hostPath not mounted).
- Map to MITRE ATT&CK Containers:
  - **T1611** Escape to Host — privileged pods, hostPath.
  - **T1613` Container and Resource Discovery — RBAC enumeration by attacker.
  - **T1610` Deploy Container — anonymous image pull / untrusted registry.
  - **T1525` Implant Internal Image — tampered images in the registry.
- Re-run `kube-bench` and `kubiscan` after remediation; confirm failing checks now `PASS`.
- Generate a per-control evidence pack: `{control_id, finding, resource, status_before, status_after, remediation_action, timestamp}`.

## IMPORTANT
- Audit only Kubernetes clusters you are authorised to assess (owned, engagement scope, explicit approval).
- Use read-only RBAC (`view` / `cluster-reader`); never apply RoleBindings/ClusterRoleBindings without change control.
- Treat `{target}` / `{ns}` / `{sa}` placeholders literally — never substitute unvalidated values into kubectl.
- Service-account tokens are bearer credentials — never log them; MIRV redaction masks them on mission save.
- Rotate any long-lived SA tokens you create for the audit; prefer short-lived bound tokens (1.24+).
- A `kubectl auth can-i` "yes" does not always mean exploitable — verify the path with a non-mutating test.
- Pod Security Admission replaced PSP in 1.25 — adapt checks to the cluster's kubelet/API version.
