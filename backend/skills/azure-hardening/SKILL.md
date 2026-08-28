---
name: azure-hardening
description: "Azure cloud security hardening. Entra ID, conditional access, Azure AD configuration audit."
category: cloud
allowed_tools:
  - az-cli
  - azure-cli
  - python
  - curl
version: "1.0.0"
author: "MIRV"
---

# Azure Security Hardening Methodology

## 1. When to Use
- Hardening an Azure tenant / Entra ID (formerly Azure AD) before production or as part of a periodic review.
- A CSPM (Defender for Cloud) reports findings and you must validate, prioritise, and remediate.
- A compliance audit (SOC2, ISO 27001, CIS Microsoft Azure) requires evidence of control posture.
- After onboarding a new subscription or guest users, to detect drift from baseline.
- A suspected exposure (public storage account, privileged guest) requires fast scoping and remediation.

## 2. Prerequisites
- Azure credentials with `Global Reader` (or equivalent read) role at the tenant root management group.
- `az-cli` installed and logged in (`az login` with MFA; `az account set --subscription {sub}`).
- `python` with `azure-mgmt-*` SDKs or `azure-cli-core` for custom queries.
- `curl` for anonymous public-endpoint verification (storage blobs, function endpoints).
- A baseline of expected conditional-access policies, privileged principals, and guest users.
- Authorisation for read-only checks across the tenant; never run mutating actions without change control.

## 3. Workflow
1. **Entra ID (Azure AD) identity posture**
   - `az ad user list --query "[].{u:userPrincipalName,created:createdDateTime}" -o table` → enumerate users; flag dormant accounts (>90d no sign-in).
   - `az ad signed-in-user show` is for the operator; for tenant-wide use Microsoft Graph: `az rest --method get --url https://graph.microsoft.com/v1.0/users`.
   - Guest accounts: `az ad user list --query "[?userType=='Guest']"` → review each guest's last sign-in and app access.
   - Privileged roles: `az rest --method get --url https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments` → flag `Global Administrator`, `Privileged Role Administrator`, `Exchange Administrator`.
   - Confirm PIM (Privileged Identity Management) is enabled for all Global Admins — eligible, not permanently active.
2. **Conditional access & MFA**
   - `az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies` → list every CA policy.
   - Validate coverage: a policy requiring MFA for all admins, a policy requiring MFA for all users, a policy blocking legacy auth, a policy requiring compliant device for admin.
   - Legacy auth block: confirm `clientAppTypes` excludes `exchangeActiveSync`/`imap`/`pop`/`smtp`.
   - Sign-in risk policy: a `high`-risk sign-in should block or require MFA + password change.
3. **Application & service principal audit**
   - `az ad app list --query "[].{app:displayName,id:appId,created:createdDateTime}"` → flag apps older than 1 year with no recent sign-in.
   - `az ad sp list --query "[].{sp:displayName,id:appId}"` → for each SP, `az rest .../servicePrincipals/{id}/appRoleAssignments` to find SPs with `Mail.Read` or `Directory.Read.All` overbroad perms.
   - Certificate/secret expiry: `az ad app credential list --id {appId}` → flag secrets > 2 years old or expiring < 30 days.
4. **Subscription & resource posture**
   - `az account list -o table` → enumerate subscriptions; confirm none are in an unmanaged orphan state.
   - `az security assessment list` → Defender for Cloud findings; filter `status.code == "Unhealthy"`.
   - Storage accounts: `az storage account list` → for each, `az storage account show --name {name} --query "allowBlobPublicAccess"` must be `false`.
   - Anonymous verify: `curl -I https://{account}.blob.core.windows.net/{container}/` → `200` confirms public blob.
   - Key Vault: `az keyvault list` → `enableRbacAuthorization` should be `true`; purge-protection and soft-delete enabled.
5. **Network exposure**
   - `az network nsg list` → flag NSGs with `0.0.0.0/0` ingress on 22, 3389, 1433, 5432, 3306.
   - `az vm list-ip-addresses` → flag VMs with public IP and no JIT (Just-In-Time) access enabled.
   - `az network public-ip list` → orphaned public IPs (not attached) for cleanup.
6. **Logging & monitoring**
   - `az monitor log-profiles list` → confirm a profile exists capturing all regions, all log categories, retaining > 90 days.
   - `az activity-log alert list` → verify alerts for `ServiceHealth`, `ResourceHealth`, and admin actions.
   - `az rest .../providers/Microsoft.Insights/diagnosticSettings` → confirm Diagnostic Settings send to a Log Analytics workspace for key resources.
7. **Decision point**: any Global Admin without PIM, any storage account with public blob access, or any CA policy gap (no MFA for admins) is a critical finding requiring same-day remediation under change control.

## 4. Verification
- Cross-check each Defender-for-Cloud finding with raw `az-cli` / Microsoft Graph output to avoid false positives.
- Map findings to **CIS Microsoft Azure Foundations Benchmark** (e.g. `1.1` Ensure no root/tenant admin without MFA, `3.1` Storage public access disabled, `6.5` Key Vault soft-delete).
- Map to MITRE ATT&CK Cloud:
  - **T1078.004** Valid Accounts: Cloud Accounts — dormant users, no MFA.
  - **T1098.001** Additional Cloud Credentials — over-privileged SPs.
  - **T1525** Implant Internal Image — tampered VM images / custom images.
- Re-run the benchmark tool (Azure Security Center / CIS-CAT) after remediation and confirm `PASS`.
- Generate a per-control evidence pack: `{control_id, finding, resource, status_before, status_after, remediation_action, timestamp}`.

## IMPORTANT
- Audit only Azure tenants you are authorised to assess (owned, engagement scope, explicit approval).
- Use read-only roles (`Global Reader`, `Reader`); never run mutating commands without change control.
- Rotate any service-principal secrets you create for the audit; store them in Key Vault, not in scripts.
- Treat `{target}` / `{subscription}` placeholders literally — never substitute unvalidated IDs.
- Redact user UPNs, secrets, and PII in shared reports; MIRV redaction applies on mission save.
- A "no findings" result from one tool is not proof of security — combine Defender for Cloud + CIS + manual checks.
- Entra ID changes propagate slowly (directory replication) — re-test after a wait, not immediately.
