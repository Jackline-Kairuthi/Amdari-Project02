# Security Gate Policy

## 1. Purpose

This document defines how our **security gate** works in CI/CD:
- Who owns each security scanner (DevSecOps vs AppSec).
- Which findings **block** a merge (hard‑fail) and which only **warn** (soft‑fail).
- How to request a **temporary security exception**.
- How to hand off findings to **AppSec** using a simple intake template.

The goal is to make security checks predictable, fair, and easy to understand.

---

## 2. Scope

This policy applies to all repositories that use the shared CI pipeline and run the following scanners:

- `secret-scan` – secrets in code and configs.
- `sast-scan` – static analysis of application code.
- `image-scan` – container image vulnerability scanning.
- `iac-scan` – infrastructure‑as‑code scanning (e.g., Terraform via Checkov).

---

## 3. Ownership Matrix

| Scanner     | Owner      | Description                                  | Default Enforcement          |
|------------|------------|----------------------------------------------|------------------------------|
| secret-scan| DevSecOps  | Finds secrets in code and configs            | **Hard‑fail on CRITICAL**    |
| sast-scan  | AppSec     | Static analysis of application code          | **Soft‑fail** (warn only)    |
| image-scan | DevSecOps  | Scans container images for CVEs              | **Hard‑fail on CRITICAL**    |
| iac-scan   | DevSecOps  | Scans Terraform/IaC for misconfigurations    | **Hard‑fail on CRITICAL**    |

---

## 4. Hard‑fail vs Soft‑fail Rules

### 4.1 Definitions

- **Hard‑fail (blocking):**  
  The pipeline fails and the PR **cannot be merged** until the issue is fixed or an exception is approved.

- **Soft‑fail (warning):**  
  The pipeline passes, but the finding appears in the PR comment and should be tracked.

- **Audit only:**  
  Logged for visibility but does not affect the pipeline.

### 4.2 Severity → Action Mapping

| Severity  | DevSecOps Scanners (secret, image, iac) | AppSec Scanner (sast) |
|----------|-------------------------------------------|------------------------|
| CRITICAL | **Hard‑fail**                             | **Hard‑fail in prod**, warn in non‑prod |
| HIGH     | Warn                                      | Warn                   |
| MEDIUM   | Audit                                     | Audit                  |
| LOW      | Audit                                     | Audit                  |

---

## 5. Differentiated Gate Behaviour

- **DevSecOps‑owned findings:**  
  - CRITICAL → **block merge**  
  - HIGH/MEDIUM/LOW → warn or audit

- **AppSec‑owned findings:**  
  - Non‑prod: HIGH/CRITICAL → warn  
  - Prod: CRITICAL → block; HIGH → may block based on AppSec decision

PR comments always show **two sections**:
1. DevSecOps findings (blocking when CRITICAL)  
2. AppSec findings (non‑blocking, with intake link)

---

## 6. Security Exception Process

Sometimes a team needs to ship with a known issue. They may request a **temporary exception**.

### 6.1 How to Request an Exception

Comment on the PR:

```text
/security-exception <ticket-id> "<short reason>" expiry=2026-12-31
```

### 6.2 Approval Requirements

An exception must be approved by:

- **One security owner**  
  - DevSecOps lead for secret/image/iac issues  
  - AppSec lead for SAST issues  

- **One engineering manager**

Approvers comment:

```text
/approve-exception <ticket-id>
```

### 6.3 Expiry

- Exceptions must include an expiry date (max 30 days).  
- After expiry, the exception becomes invalid and the gate will block again.  
- All exceptions are tracked in an exceptions register.

---

## 7. AppSec Intake Template (Handoff)

When handing off a finding to AppSec, use the template below.

```text
Title:
[Repo] [PR#] Short description of the issue

Owner/Team:
Scanner:
Finding ID:
Severity:
File / Line:

Description:
- One or two sentences describing the issue.

Reproduction Steps:
- How to reproduce locally or in a test environment.

Business Impact:
- What could go wrong if this is exploited?

Suggested Fix:
- Short suggestion (e.g., "Use parameterized queries", "Move resource to private subnet").

Attachments:
- Screenshot of PR comment or scanner report
- Relevant logs or code snippets

Requested SLA:
- CRITICAL: 48 hours
- HIGH: 5 business days
```

---

## 8. Change Control

- This policy lives in `docs/security-gate-policy.md`.  
- Changes require a PR approved by DevSecOps and AppSec leads.
