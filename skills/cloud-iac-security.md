---
name: cloud-iac-security
description: Cloud and infrastructure-as-code hardening - IAM, network, storage, metadata, drift, posture scanning.
tags: cloud, infra
---
- Identity first: no root/owner for daily use; MFA (phishing-resistant) on all humans; SSO; workload identity instead of static keys; least-privilege roles; no `*:*`; permission boundaries/SCPs; break-glass accounts monitored.
- Network: default-deny security groups; private subnets for data stores; no public SSH/RDP/DB ports; egress filtering; WAF/DDoS protection at the edge; private endpoints for managed services.
- Storage: block public access at account level; encryption with customer-managed keys for sensitive data; versioning + object lock for backups; access logs.
- Instance metadata: enforce IMDSv2 (or equivalent), hop limit 1, to blunt SSRF credential theft.
- Secrets in a manager, not in user-data, env dumps, or AMIs (secrets-management).
- IaC (Terraform/CloudFormation/Pulumi/Bicep): code review, policy-as-code (OPA/Conftest, Checkov, Trivy config scan - pinned, see vetted-open-source-tools), remote state encrypted with restricted access, no secrets in state where avoidable, plan-then-apply pipelines with approvals, drift detection.
- Logging: CloudTrail/Activity Log/Audit Logs on in all regions, immutable, alerting on root use, policy changes, disabled logging, new access keys.
- Posture: continuous CSPM scanning; tag ownership; auto-remediate public exposure; delete unused resources and identities (shadow IT, orphaned keys).
- Patch and image hygiene: minimal base images, auto-patch, SBOM. Backups: 3-2-1 with an immutable/offline copy and restore tests (ransomware-resilience).
- Blast radius: separate accounts/projects per environment and per sensitivity; segregate prod from CI and from corporate IT.
