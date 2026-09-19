# KubeOps Sentinel 1.1.1 — Production Hardening

This release is a hardening update to the existing single-file runtime. It does not expand cluster mutation privileges: operational modes remain read-only, and the guarded developer Flux reconciliation path remains isolated.

## Hardening included

- Transport failures now distinguish `DNS_ERROR`, `TLS_ERROR`, `NETWORK_ERROR`, and `API_TIMEOUT` so troubleshooting does not collapse different failure domains into one status.
- Central text and JSON redaction now covers additional cloud/CI credential names and common token signatures, including AWS secret/session keys, GitHub/GitLab personal-access-token forms, and Slack token forms.
- `--doctor` now reports runtime source integrity metadata, rejects group/world-writable source files, validates explicit kubeconfig paths, rejects group/world-writable kubeconfig files, and warns on group/world-readable kubeconfig files.
- Developer validation now supports both native Linux and WSL. Windows Kubernetes clients remain rejected for the Linux/WSL developer workflow.
- Developer validation verifies that generated Sentinel output, validation logs, image build context, lock files, and temporary files are covered by `.gitignore` rules.
- Embedded deterministic coverage includes DNS/TLS classification, expanded redaction, JSON secret removal, and source/kubeconfig permission hygiene.
- GitHub CI now checks every tracked shell script for executable mode and Bash syntax, runs ShellCheck error-level analysis when available, applies repository artifact/secret policy checks, runs the full `--dev-validate` gate, executes TLS/GitOps loopback E2E, and finishes with `git diff --check`.
- CI checkout does not persist GitHub credentials and workflow permissions remain read-only.

## Validation boundary

The deterministic and loopback suites do not claim live Kubernetes validation. A live `--dev-smoke` run still requires a real Linux `kubectl`, kubeconfig/OIDC access, explicit context, and namespace. Flux verification remains a separate post-push check when configured.
