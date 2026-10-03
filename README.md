# KubeOps Sentinel

A single-file Bash Kubernetes operations console: health, resources, triage,
GitOps, certificates, TLS auditing, and incident evidence. Normal operational
commands are read-only; developer publishing and explicitly authorized Flux
reconciliation are separate, opt-in operations.

## Runtime requirements

Use Linux or WSL with Bash 4.4+, standard UNIX utilities and a Linux `kubectl`.
Provide an existing kubeconfig and least-privilege Kubernetes credentials.
Install `jq` for structured analysis and JSON output, OpenSSL for certificate/TLS
inspection, and optionally Helm, Flux and curl for their corresponding features.
Do not run as root merely to work around missing permissions.

Run commands from a private working directory. Reports must remain underneath
that directory. Shell scripts are stored with LF endings through `.gitattributes`.

## Operations

Invoke the absolute path to the executable with an explicit context and namespace:

```text
KubeOps_Sentinel.sh --context CONTEXT --namespace NAMESPACE --triage
KubeOps_Sentinel.sh --context CONTEXT --namespace NAMESPACE --triage-workload Deployment/NAME
KubeOps_Sentinel.sh --context CONTEXT --namespace NAMESPACE --health --json
KubeOps_Sentinel.sh --context CONTEXT --namespace NAMESPACE --doctor
KubeOps_Sentinel.sh --context CONTEXT --namespace NAMESPACE --capabilities
```

The executable name above denotes your absolute installation path. Use `--help`
and `--help-dev` for the full command surface. Interactive dashboard mode requires
a terminal. The tool does not change kubeconfig's current context.

### Automation contract

| Exit | Meaning |
|---|---|
| 0 | No observed operational failure; inspect coverage and UNKNOWN states |
| 1 | Observed operational failure |
| 2 | Usage, configuration, missing JSON dependency or report capture/emission failure |
| 3 | Authentication/API failure |
| 4 | Required data unavailable in triage modes |

`--json` is supported only for report commands and requires `jq`. Missing `jq`
fails before cluster bootstrap; it never silently substitutes plain text for JSON.
Consumers must check the process exit code, not only the report's `exit_status`.
Failed report captures discard partial output and clear the selected report so
an earlier report cannot be emitted as the result of a failed collection.
An unavailable collector is not evidence of a healthy or empty cluster.

## Validation

From the repository working directory, invoke the absolute application path with
`--dev-self-test --output ./sentinel-output` for offline fixture tests. The tests
create disposable local Git repositories but do not publish to your remote.
Permission-sensitive doctor fixtures use private files in Linux `/tmp`, so they
exercise real permission changes even when the checkout is on a Windows mount.
The live doctor still reports the permissions observed on your actual source and
kubeconfig; Windows mounts without permission metadata can report mode `777`.

Invoke Bash with the absolute path to each harness:

- `.sentinel-dev/e2e/output-contract-test.sh`: offline output regression tests.
- `.sentinel-dev/e2e/tls-live-test.sh`: real loopback TLS tests; needs OpenSSL,
  OpenBSD-compatible netcat, jq and GNU timeout. Use an outer 120-second deadline.

The TLS report is successful only when the process exits zero **and** its final
line is `Aggregate failures: 0`. Partial reports are not successful evidence.
CI installs validation dependencies and checks executable modes, syntax, LF
endings, ShellCheck errors, repository safety, output contracts, full developer
validation, and bounded loopback E2E. ShellCheck warnings are not a blocking gate.

## Security and deployment boundaries

- Use namespace-scoped RBAC where possible; cluster reports need additional reads.
- Redaction and data projection reduce exposure, but exported logs can still
  contain sensitive business data. Review evidence before sharing; set retention
  and access controls for the output directory.
- Never apply the deliberate failure fixtures to production. They assume a
  dedicated validation namespace; the baseline uses a `local-path` storage class.
- Review developer commands separately: `--dev-publish` and `--dev-release`
  commit/push. Flux reconciliation requires explicit flags and guarded checks.
- The lightweight commit helper refuses unrelated staged files, but is not a
  concurrent-publication coordinator. Prefer the application's guarded publishing
  workflow; do not run simultaneous Git writers.
- CI/fixture success is not a penetration test, production cluster certification,
  or proof that a Flux-observed revision is running in a workload.

The application version remains the released version until a release is explicitly
prepared. Local hardening changes are not automatically committed or published.
