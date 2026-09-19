# Jev automation archive import — 2026-09-19

The recovered RAR contained 451 entries: a pre-commit `.git` worktree, `KubeOps_Sentinel.sh`, hidden developer assets under `.sentinel-dev`, empty `.qodo` scaffolding, and generated `sentinel-output` validation/runtime evidence.

Repository arrangement:

- `KubeOps_Sentinel.sh` remains the single runtime source/executable.
- `.sentinel-dev/e2e/` retains reusable developer/E2E helpers, made repository-relative and portable.
- `.sentinel-dev/fixtures/` retains reusable controlled Kubernetes/resource fixtures.
- `.qodo/agents/` and `.qodo/workflows/` are preserved as hidden scaffolding via `.gitkeep`.
- `.github/workflows/kubeops-sentinel-ci.yml` runs deterministic syntax/self-test checks on GitHub.
- Historical `sentinel-output/validation` reports were analyzed but are not committed as source; the retained E2E harness regenerates current evidence.
- `sentinel-output/` and transient `.sentinel-dev/validation.*.log` files are intentionally ignored because they are generated runtime/test evidence.
- The archive's nested `.git` database was used for provenance inspection only and was not copied over the canonical repository history.

The import also fixed an offline-test portability defect: `CORE_BOOTSTRAP_CACHE_FIXTURES` previously required a real `kubectl` executable before entering its mocked wrapper. The fixture now mocks kubectl availability, so deterministic tests can run on clean CI hosts without Kubernetes installed.
