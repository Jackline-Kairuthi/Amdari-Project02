# SecureFlow — Secured Version (DevSecOps Case Study Project)
SecureFlow is a deliberately vulnerable banking platform used as the foundation for a full DevSecOps transformation.
The original upstream repository is intentionally insecure and should never be deployed to a real cloud account.
This fork contains my secured implementation, including infrastructure hardening, CI/CD security gates, secrets management, policy enforcement, runtime monitoring, and observability.

This project demonstrates the full lifecycle of securing an insecure microservices application using modern DevSecOps practices.

<h1/> Project Overview</h1>

This repository represents the secured “after” state of the SecureFlow platform.
The upstream project provides an intentionally vulnerable baseline; my work implements the complete remediation pipeline described in the project brief.

Key security enhancements implemented in this fork
- Hardened Infrastructure as Code (Terraform)

- Checkov Stage 4 compliance (zero CRITICAL findings)

- HashiCorp Vault for secrets management and dynamic credentials

- OPA Gatekeeper for Kubernetes policy enforcement

- Falco for runtime threat detection (eBPF)

- Gitleaks, Trivy, Bandit, pip-audit, and OWASP ZAP integrated into CI

- GitHub Actions 7‑stage security pipeline

- Signed container images with SBOM attestations

- Zero committed secrets

- Zero CRITICAL CVEs in service images

- NetworkPolicies, hardened Kustomize overlays, and secure defaults

This fork is designed to be a portfolio‑ready demonstration of practical DevSecOps skills.

---

## Architecture
SecureFlow is a microservices banking application consisting of:
```
                     ┌────────────────────┐
                     │     frontend       │  Flask + Jinja2 on :5000
                     │  (server-rendered) │
                     └──────┬───────┬─────┘
                            │       │
                 calls       │       │  calls
                            ▼       ▼
            ┌─────────────────┐  ┌──────────────────────┐
            │  auth-service   │  │ transaction-service  │
            │   Flask :5001   │  │    Flask :5002       │
            └────────┬────────┘  └──────────┬───────────┘
                     │                      │
                     ▼                      ▼
              ┌────────────┐          ┌────────────────┐
              │  auth-db   │          │ transaction-db │
              │ postgres   │          │   postgres     │
              └────────────┘          └────────────────┘
```

Each service has its own database to support least privilege and per‑service Vault policies.

---

## Quick Start — Docker Compose

The insecure baseline can be run locally to observe vulnerabilities before remediation.

```bash
docker-compose up --build

```
## Kubernetes (Base Manifests)

These manifests deploy because they contain no security controls.
In the secured version, Gatekeeper will reject them.

```bash
kubectl apply -k infra/kubernetes/base
kubectl get pods -n secureflow -w

```

## Quick Start — Kubernetes (base manifests)

```bash
kubectl apply -k infra/kubernetes/base

# Everything will apply because there is no admission controller in the way.
# That is the point. One of your tasks is to install OPA Gatekeeper and watch
# the base manifests get rejected.

kubectl get pods -n secureflow -w
```
## Example Vulnerabilities (Baseline Only)
The baseline is intentionally vulnerable to:

- SQL injection

- IDOR

- Negative transfers

- Reflected XSS

- Hardcoded secrets

- Insecure Dockerfiles

- Publicly exposed databases

- Over‑privileged IAM

- Missing NetworkPolicies

- No admission control

- No runtime monitoring

All of these are remediated in this fork.
---


## What's In This Repository

```
secureflow/
├── .env                              
├── docker-compose.yml                
├── .gitignore                        # Excludes .env and sensitive files
├──  .github/workflows/               # Full CI/CD security pipeline
├── README.md                         # this file
├── VULNERABILITIES.md                # Vulnerability index from the baseline
├── services/
│   ├── auth-service/                 # Flask microservices
│   ├── transaction-service/         
│   └── frontend/                     
├── db/                               # Database schemas + seeds
│   ├── auth/init.sql                 
│   └── transaction/init.sql         
└── infra/
    ├── kubernetes/
    |   ├── base/                      # Insecure baseline (for comparison)
    |    ├── overlays/secure/          # Hardened manifests (OPA, Vault, NetworkPolicies)
    └── terraform/                     # Remediated IaC modules (Checkov Stage 4)
```

---
## DevSecOps Pipeline (7 Stages)

The GitHub Actions pipeline includes:

- Secret Scanning (Gitleaks)

- Dependency & Image Scanning (Trivy)

- IaC Scanning (Checkov)

- Policy Enforcement (OPA Gatekeeper)

- Dynamic Testing (OWASP ZAP)

- Build, Sign & Publish (Cosign + SBOM)

All stages must pass for a merge to be allowed.

---
## Secrets Management with Vault
This fork integrates:

- Kubernetes auth method

- Vault Agent Injector

- Per‑service policies

- Dynamic PostgreSQL credentials

- Secret rotation

- No plaintext secrets in GitHub or Kubernetes

Vault ensures zero hardcoded secrets across the stack.
---

## Policy Enforcement with OPA Gatekeeper
The secured overlay includes:

- ConstraintTemplates

- Constraints

- Required labels

- Disallowed images

- No privileged pods

- No hostPath volumes

- Mandatory resource limits

- Mandatory NetworkPolicies

Insecure manifests from base/ are rejected automatically.
---

## Runtime Security with Falco
Falco monitors:

- Suspicious syscalls

- Unexpected network activity

- Shells spawned in containers

- File system tampering

- Privilege escalation attempts

- Custom rules are included for SecureFlow’s threat model.
---
## What's NOT In This Repository

Everything in this list is your job to build, based on the project brief:

- `.github/workflows/*` — the GitHub Actions pipeline
- `.gitleaks.toml` — custom Gitleaks rules for Flask/JWT/DB patterns
- `sonar-project.properties` — SonarQube configuration
- `pipeline/scripts/security-gate.sh` — the aggregation script
- Cosign keys and signing workflow
- OPA Gatekeeper ConstraintTemplates and Constraints
- Falco custom rules
- HashiCorp Vault policies, roles, and Agent Injector annotations
- Kubernetes NetworkPolicies
- Hardened Kustomize overlays (the `base/` here is the broken version)
- Prometheus configuration and Grafana dashboards
- OWASP ZAP scan configuration

If you find yourself adding a file and wondering whether it belongs in the
baseline or the solution — it's in the solution. The baseline is broken; you
are what fixes it.

---

## Success Criteria

This secured fork meets all requirements from Section 9 of the project brief:

✔ Zero committed secrets

✔ Zero CRITICAL CVEs in images

✔ Zero CRITICAL Checkov findings

✔ All OPA Gatekeeper policies enforced

✔ All baseline exploits return 400/403

✔ Vault-injected secrets working

✔ Falco alerts trigger on test events

✔ Signed images + SBOM attestations

✔ Full 7‑stage CI/CD pipeline green
