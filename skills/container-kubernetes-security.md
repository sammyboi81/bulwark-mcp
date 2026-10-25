---
name: container-kubernetes-security
description: Secure images, runtime, and Kubernetes clusters.
tags: cloud, containers
---
## Images
- Minimal/distroless bases, pinned by digest, rebuilt regularly; multi-stage builds; no secrets in layers or build args; non-root USER; read-only root filesystem; drop all capabilities then add back only what is needed.
- Scan images and generate an SBOM (Syft, Grype, OSV-Scanner - pinned and verified); sign images and verify at admission (Cosign/Sigstore, policy controller).
## Runtime
- No privileged containers, no hostPath/hostNetwork/hostPID unless essential; seccomp RuntimeDefault, AppArmor/SELinux; resource limits; no Docker socket mounts.
## Kubernetes
- RBAC least privilege; no cluster-admin for apps; disable automounting service-account tokens unless needed; one service account per workload; short-lived projected tokens.
- Pod Security Admission "restricted" profile; admission policies (Kyverno/OPA Gatekeeper) enforce signed images, no latest tag, required limits.
- NetworkPolicies default-deny between namespaces; encrypt in-cluster traffic (service mesh/mTLS) for sensitive paths; restrict egress.
- Secrets: external secret store with CSI/operator; enable etcd encryption at rest; never in ConfigMaps.
- API server not publicly exposed (or tightly IP-restricted + OIDC auth); audit logging on; kubelet auth/authz enforced; keep versions supported and patched.
- Supply chain: admission-time provenance (SLSA attestations), private registry, no pulling arbitrary public images in prod.
- Detect: runtime threat detection (Falco or equivalent), alert on shells in containers, unexpected egress, crypto-miner signatures.
