---
name: aws-audit
description: "AWS cloud security audit. S3 permissions, IAM policies, CloudTrail, CSPM findings."
category: cloud
allowed_tools:
  - aws-cli
  - prowler
  - scout
  - curl
  - python
version: "1.0.0"
author: "MIRV"
---

# AWS Cloud Security Audit Methodology

## 1. When to Use
- Hardening an AWS account before production go-live or as part of a periodic security review.
- A CSPM (Security Hub, Prowler) reports findings and you must validate, prioritise, and remediate.
- An audit/compliance requirement (SOC2, ISO 27001, CIS AWS) needs evidence of control posture.
- After a permissions change or new account in the organisation, to detect drift from baseline.
- A suspected exposure (public S3, leaked key) requires fast scoping and remediation.

## 2. Prerequisites
- AWS credentials with `SecurityAudit` (or equivalent read) IAM policy attached.
- `aws-cli` configured (`aws configure`) with MFA-enforced role assumption.
- `prowler` (Python) for CIS AWS + extra checks; `scout-suite` for a full visual report.
- `curl` for S3 public bucket verification (anonymous, no creds).
- `python` with `boto3` for custom queries and CSV/report generation.
- Authorisation to run read-only checks against the target AWS account(s); never run mutating actions without change control.
- A baseline of expected public resources and IAM principals for diffing.

## 3. Workflow
1. **Identity & access posture**
   - `aws iam list-users`, `aws iam list-roles`, `aws iam list-groups` → enumerate principals.
   - `aws iam get-credential-report --output text > cred_report.csv` → check `password_enabled`, MFA active, key last-rotation age > 90d.
   - Flag root account: `aws iam get-account-summary` → `AccountMFAEnabled` should be 1; root access keys should not exist.
   - `aws iam get-account-password-policy` → confirm minimum length 14, complexity, reuse prevention.
   - For each role: `aws iam list-attached-role-policies` + `aws iam list-inline-role-policies` → flag `AdministratorAccess` and `*:*` inline policies.
2. **S3 exposure audit**
   - `aws s3api list-buckets --query 'Buckets[].Name'` → enumerate buckets.
   - For each bucket: `aws s3api get-bucket-acl`, `get-bucket-policy`, `get-public-access-block`.
   - A bucket is public if `AllUsers` or `AuthenticatedUsers` grantee appears in ACL OR policy allows `Principal: "*"`.
   - Anonymous verify: `curl -I https://{bucket}.s3.amazonaws.com/` without creds — a `200` confirms public read.
   - Block Public Access must be enabled at account AND bucket level (`aws s3api put-public-access-block` to remediate).
3. **CloudTrail & monitoring**
   - `aws cloudtrail describe-trails` → confirm a multi-region trail exists with log file validation enabled.
   - `aws cloudtrail get-trail-status` → `IsLogging` must be `true`; logs ship to a bucket with object-lock.
   - `aws logs describe-metric-filters --log-group-name {trail}` → verify alarms for `ConsoleLoginWithoutMFA`, `RootAccess`, `IAMUserChanged`.
   - Confirm CloudTrail insights is enabled for anomaly detection on management events.
4. **Network exposure**
   - `aws ec2 describe-security-groups` → flag SGs with `0.0.0.0/0` ingress on 22, 3389, 3306, 5432, 27017.
   - `aws ec2 describe-instances` → flag instances with public IPv4 and no SG restriction.
   - `aws ec2 describe-vpc-endpoints` → confirm private endpoints for S3/DynamoDB to avoid public internet.
   - `aws rds describe-db-instances` → `PubliclyAccessible` must be `false`.
5. **CSPM & automated checks**
   - `prowler aws -q -M csv -o prowler_out/` → CIS AWS Benchmark + 300+ extra checks.
   - `aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"HIGH","Comparison":"EQUALS"}]}'` → review high/critical Security Hub findings.
   - Triage Prowler output by `CHECK_ID` and `LEVEL` (FAIL/WARNING); map each to a CIS control ID and remediation runbook.
6. **Secrets & keys hygiene**
   - `aws iam list-access-keys --user-name {user}` → flag keys older than 90 days or last-used > 30 days.
   - `aws secretsmanager list-secrets` → confirm rotation configured; flag secrets without KMS CMK.
   - Search code repos and public S3 for leaked keys; if found, rotate immediately and audit CloudTrail for the leaked-key access window.
7. **Decision point**: any publicly-exposed data store (S3/RDS) or IAM principal with `AdministratorAccess` + no MFA is a critical finding requiring same-day remediation under change control.

## 4. Verification
- Cross-check each Prowler finding with the raw `aws-cli` output to avoid false positives from stale credentials.
- Map findings to **CIS AWS Foundations Benchmark** control IDs (e.g. `1.3` IAM root MFA, `2.1` CloudTrail multi-region, `2.3` S3 public access block).
- Map to MITRE ATT&CK Cloud matrix where relevant:
  - **T1078.004** Valid Accounts: Cloud Accounts — unused keys, no MFA.
  - **T1530** Data from Cloud Storage — public S3.
  - **T1525** Implant Internal Image — tampered AMIs/launch templates.
- Re-run Prowler after remediation and confirm the failing checks now `PASS`.
- Generate a per-control evidence pack: `{control_id, finding, resource, status_before, status_after, remediation_action, timestamp}`.

## IMPORTANT
- Audit only AWS accounts you are authorised to assess (owned, engagement scope, explicit approval).
- Use read-only credentials (`SecurityAudit` / `ViewOnlyAccess`); never run mutating commands without change control.
- Rotate any keys you create for the audit immediately afterwards; store them in Secrets Manager, not in scripts.
- Treat `{target}` / `{account}` placeholders literally — never substitute unvalidated account IDs.
- Redact access-key IDs, secret values, and PII in shared reports; MIRV redaction applies on mission save.
- A "no findings" result from one tool is not proof of security — combine Prowler + Security Hub + manual checks.
- Public S3 exposure can leak data within minutes of detection by opportunistic scanners; remediate first, report second.
