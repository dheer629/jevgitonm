# KUBEOPS SENTINEL — CONTINUOUS ENHANCEMENT DIRECTIVE

You are not merely maintaining this utility.

Your standing objective is to continuously increase the engineering potential, operational usefulness, automation depth, intelligence, reliability, safety, performance, observability, troubleshooting capability, developer experience and production readiness of:

```text
KubeOps_Sentinel.sh

```

Treat every future modification as an opportunity to improve the complete platform.

The utility must continuously evolve toward becoming a:

```text
Kubernetes Operations Command Center
+
SRE Troubleshooting Console
+
Incident Evidence Platform
+
GitOps Assurance Engine
+
Resource Intelligence System
+
Certificate/TLS Auditor
+
Splunk Audit Assistant
+
Capacity Analysis Tool
+
Deployment Validator
+
Production Readiness Auditor
+
Developer Automation Platform

```

while preserving the fundamental constraint:

```text
ONE SOURCE FILE
ONE EXECUTABLE
KubeOps_Sentinel.sh

```

---

# 1. PRIMARY CONTINUOUS-IMPROVEMENT RULE

For every requested change, do NOT only implement the literal requirement.

Perform this complete reasoning process:

```text
REQUEST
   ↓
Understand existing implementation
   ↓
Determine affected architecture
   ↓
Identify missing capabilities
   ↓
Identify reliability weaknesses
   ↓
Identify usability weaknesses
   ↓
Identify performance weaknesses
   ↓
Identify observability gaps
   ↓
Identify testing gaps
   ↓
Identify opportunities for reuse
   ↓
Implement requested change
   ↓
Implement justified adjacent improvements
   ↓
Regression test
   ↓
Integration test
   ↓
Update self-tests
   ↓
Validate full application

```

Enhancements must be directly useful.

Do not add meaningless features merely to increase code size.

---

# 2. NO FEATURE REGRESSION

The most important rule for every future enhancement is:

```text
NEVER BREAK EXISTING WORKING FUNCTIONALITY

```

Before modification:

```text
Understand existing behavior.

```

After modification:

```text
Confirm existing behavior remains functional.

```

Every enhancement must preserve:

```text
kubeconfig awareness
OIDC compatibility
context locking
namespace locking
read-only operational behavior
resource monitoring
incident evidence collection
GitOps validation
certificate auditing
TLS validation
Splunk query generation
health/readiness auditing
WSL development workflow
Git automation
Flux verification
security controls
redaction
full-output viewing
export
self-tests

```

Do not remove existing capabilities simply because a new implementation seems cleaner.

---

# 3. PRESERVE BACKWARD COMPATIBILITY

Existing CLI interfaces should continue to work.

For example:

```bash
./KubeOps_Sentinel.sh
./KubeOps_Sentinel.sh --health
./KubeOps_Sentinel.sh --resources
./KubeOps_Sentinel.sh --dev-validate
./KubeOps_Sentinel.sh --dev-watch
./KubeOps_Sentinel.sh --dev-release

```

Do not rename existing options without backward-compatible aliases unless absolutely necessary.

If behavior changes:

```text
document the change internally
preserve old semantics when practical
add migration handling

```

---

# 4. ALWAYS REVIEW THE WHOLE SCRIPT FIRST

Before changing code:

```text
Read the complete current KubeOps_Sentinel.sh.

```

Do not edit isolated fragments without understanding:

```text
global variables
function dependencies
cache engine
rendering engine
command wrappers
error handling
scope handling
developer pipeline
security controls
existing self-tests

```

Determine whether similar functionality already exists before creating another implementation.

---

# 5. DO NOT DUPLICATE LOGIC

Whenever new functionality overlaps existing logic, refactor toward reusable functions.

Prefer:

```text
one CPU parser
one memory parser
one kubectl wrapper
one timeout wrapper
one error classifier
one output formatter
one table renderer
one redaction engine
one cache engine
one Kubernetes collector architecture

```

Do NOT create:

```text
parse_cpu_1
parse_cpu_new
parse_cpu_dashboard
parse_cpu_health

```

for the same conceptual operation.

---

# 6. ALWAYS SEARCH FOR ARCHITECTURAL LEVERAGE

When implementing a feature, determine whether its collector or analyzer can enhance other modules.

Example:

```text
Certificate collector
        ↓
Certificate dashboard
        ↓
Health readiness
        ↓
Incident evidence
        ↓
GitOps correlation
        ↓
TLS diagnostics

```

A new collector should ideally become reusable infrastructure.

---

# 7. DATA-FIRST ARCHITECTURE

Prefer:

```text
COLLECT
   ↓
NORMALIZE
   ↓
CACHE
   ↓
ANALYZE
   ↓
CORRELATE
   ↓
RENDER

```

rather than embedding Kubernetes commands directly inside every dashboard screen.

Screens should consume normalized internal data where practical.

This improves:

```text
performance
consistency
testability
reuse
future extensibility

```

---

# 8. CONTINUOUSLY IMPROVE LIVE RESOURCE INTELLIGENCE

Whenever appropriate, increase the live Kubernetes tracker's ability to show:

```text
CPU usage
memory usage
CPU requests
CPU limits
memory requests
memory limits
request saturation
limit saturation
restart counts
container state
last termination reason
OOM events
node placement
pod IP
QoS class
owner/workload
image
image digest
age
readiness
resource pressure

```

Continuously seek better correlation between:

```text
pod
container
workload
node
service
endpoint
PVC
GitOps resource
certificate
event

```

---

# 9. BUILD TOWARD RELATIONSHIP-AWARE KUBERNETES INTELLIGENCE

The utility should increasingly understand relationships such as:

```text
GitRepository
     ↓
Kustomization
     ↓
HelmRelease
     ↓
Deployment
     ↓
ReplicaSet
     ↓
Pod
     ↓
Container
     ↓
Runtime Image

```

and:

```text
Service
     ↓
Selector
     ↓
Pod
     ↓
EndpointSlice

```

and:

```text
Pod
     ↓
PVC
     ↓
PV
     ↓
StorageClass

```

and:

```text
Ingress
     ↓
Service
     ↓
TLS Secret
     ↓
Certificate
     ↓
Issuer

```

and:

```text
Event
     ↓
Object
     ↓
Workload
     ↓
Owner

```

Every future enhancement should consider whether new relationships can be safely derived.

---

# 10. BUILD A RESOURCE GRAPH INTERNALLY

Where practical, move toward maintaining an internal relationship graph.

Conceptual nodes:

```text
Cluster
Namespace
Node
Deployment
StatefulSet
DaemonSet
ReplicaSet
Pod
Container
Service
EndpointSlice
Ingress
PVC
PV
StorageClass
Secret metadata
ConfigMap
Certificate
Issuer
GitRepository
Kustomization
HelmRelease
Event

```

Conceptual edges:

```text
OWNS
SELECTS
RUNS_ON
USES
MOUNTS
REFERENCES
EXPOSES
DEPENDS_ON
GENERATED_BY
RECONCILED_BY

```

This does not require an external graph database.

Use Bash-native normalized structures and cached temporary representations.

---

# 11. CONTINUOUSLY IMPROVE INCIDENT RCA CAPABILITY

The utility should evolve from:

```text
data display

```

toward:

```text
evidence correlation

```

Example:

```text
Deployment unavailable
       +
Pod Pending
       +
FailedScheduling
       +
Insufficient CPU
       =
OBSERVED CONDITION CHAIN

```

Another:

```text
Application TLS failure
       +
Certificate expired
       +
Secret mounted
       =
OBSERVED CERTIFICATE FAILURE CHAIN

```

Important:

Never fabricate root cause.

Use explicit levels:

```text
OBSERVED
CORRELATED
LIKELY
POSSIBLE
NOT VERIFIED

```

Do not promote `LIKELY` or `POSSIBLE` to fact.

---

# 12. BUILD A FINDINGS ENGINE

Every subsystem should eventually emit normalized findings.

Structure:

```text
ID
CATEGORY
SEVERITY
RESOURCE
OBSERVATION
EVIDENCE
TIMESTAMP
CONFIDENCE
RECOMMENDED NEXT CHECK

```

Examples:

```text
K8S-POD-001
CERT-EXP-002
FLUX-SYNC-003
HELM-FAIL-004
NET-ENDPOINT-005
RES-CPU-006
PVC-STATE-007
TLS-HANDSHAKE-008

```

Deduplicate findings.

Do not flood the user with hundreds of duplicates.

---

# 13. PRIORITIZE ACTIONABLE OUTPUT

Every warning/failure should ideally answer:

```text
What is wrong?
Which object?
What evidence supports this?
How serious is it?
What should I inspect next?

```

Example:

```text
[WARN] deployment/example

Available replicas
2 / 3

Related pod
example-7fdd68b5dd-5rm9z

Observed event
FailedScheduling

Message
Insufficient CPU

NEXT CHECK
Node & Capacity View

```

---

# 14. CONTINUOUSLY IMPROVE RESOURCE CAPACITY ANALYSIS

Expand toward accurate calculations for:

```text
Cluster capacity
Node capacity
Allocatable capacity
Requested CPU
Limited CPU
Actual CPU
Requested memory
Limited memory
Actual memory
Available headroom
Pod density
Namespace share
Workload share
Node-pool share

```

Never calculate:

```text
0

```

when data is actually:

```text
unavailable
denied
unset
parse failed

```

Use explicit states.

---

# 15. BUILD RESOURCE EFFICIENCY ANALYSIS

Where sufficient evidence exists, calculate:

```text
CPU actual/request ratio
Memory actual/request ratio
CPU actual/limit ratio
Memory actual/limit ratio

```

Detect possible:

```text
over-requesting
under-requesting
resource saturation
missing requests
missing limits

```

Use cautious wording.

For example:

```text
POTENTIAL OVER-REQUEST

```

not:

```text
RESOURCE WASTED

```

unless sufficient historical evidence exists.

---

# 16. ADD HISTORICAL COMPARISON WHERE POSSIBLE

Without introducing an external database, support local snapshots.

Example:

```text
snapshot-20260919-090000
snapshot-20260919-120000

```

Compare:

```text
CPU
memory
pod counts
restarts
images
Git revisions
certificate days remaining
events
failures

```

Enable:

```text
TREND
CHANGE
REGRESSION
IMPROVEMENT

```

based on actual snapshots.

---

# 17. CONTINUOUSLY IMPROVE CHANGE DETECTION

Enhance snapshot diffing toward:

```text
new pod
removed pod
changed image
restart increase
request change
limit change
replica change
service endpoint change
PVC state change
certificate change
Flux revision change
Helm revision change
new warning event

```

Highlight only meaningful changes.

Avoid noise from transient timestamps.

---

# 18. ADD BASELINE COMPARISON

Where useful, allow:

```text
Create Baseline
Compare Current vs Baseline

```

Baseline may represent:

```text
known-good production state
pre-change state
post-deployment state

```

Use it for:

```text
incident comparison
change validation
regression detection

```

---

# 19. CONTINUOUSLY IMPROVE GITOPS INTELLIGENCE

Enhance GitOps analysis toward:

```text
source readiness
source revision
artifact revision
Kustomization readiness
applied revision
attempted revision
generation
observed generation
HelmRelease readiness
chart version
revision
suspension
dependency health
controller errors

```

Clearly differentiate:

```text
source not synchronized
source synchronized but reconciliation pending
reconciliation failed
runtime unhealthy

```

---

# 20. IMPROVE GITOPS DRIFT ANALYSIS

Whenever possible correlate:

```text
Git desired state
Flux observed state
Helm state
Kubernetes workload state
Container runtime state

```

Classify:

```text
SOURCE_DRIFT
RECONCILIATION_DRIFT
GENERATION_DRIFT
HELM_DRIFT
IMAGE_VARIANCE
RUNTIME_VARIANCE
NO_DRIFT
UNKNOWN

```

Never claim confirmed drift without evidence.

---

# 21. CONTINUOUSLY IMPROVE CERTIFICATE INTELLIGENCE

Build toward complete certificate lifecycle visibility:

```text
certificate source
subject
issuer
SAN
serial
fingerprint
valid from
valid until
days remaining
secret
mount
pod
service
ingress
issuer
renewal state

```

Provide relationship navigation.

---

# 22. CONTINUOUSLY IMPROVE TLS TESTING

Enhance TLS analysis with:

```text
DNS
TCP
TLS handshake
TLS version
cipher
certificate chain
SAN match
hostname verification
expiry
issuer
chain errors

```

Distinguish:

```text
DNS failure
TCP failure
TLS failure
certificate failure
hostname mismatch

```

Do not collapse all failures into:

```text
TLS ERROR

```

---

# 23. CONTINUOUSLY IMPROVE SPLUNK CAPABILITY

The Splunk module should evolve toward:

```text
field discovery
index discovery
sourcetype discovery
query generation
query validation
match counts
query catalog
coverage matrix
audit categories
incident-focused searches

```

Never invent:

```text
field
index
sourcetype
count
validation status

```

---

# 24. BUILD CONTEXT-AWARE SPLUNK QUERIES

Where available, generate filters using discovered Kubernetes values such as:

```text
cluster
namespace
pod
container
node
workload
application

```

Example:

```text
current selected namespace

```

should automatically become a query parameter when the corresponding Splunk field exists.

---

# 25. CONTINUOUSLY IMPROVE HEALTH AUDITING

Health should increasingly cover:

```text
API
authentication
RBAC
nodes
pods
deployments
statefulsets
daemonsets
jobs
cronjobs
services
endpoints
EndpointSlices
Ingress
PVC
events
resources
GitOps
certificates
TLS
storage
network relationships

```

Avoid a meaningless single health percentage.

Use explicit categories.

---

# 26. ADD READINESS PROFILES

Allow different readiness modes:

```text
STANDARD
PRE-CHANGE
POST-CHANGE
INCIDENT
PRODUCTION-READINESS
GITOPS-READINESS
CERTIFICATE-READINESS

```

Each profile may emphasize different checks.

Do not duplicate the underlying collectors.

---

# 27. CONTINUOUSLY IMPROVE INCIDENT EVIDENCE

Every useful new collector should be considered for inclusion in:

```text
Incident Evidence Collector

```

Evidence should progressively include:

```text
scope
health
workloads
metrics
events
services
endpoints
network relationships
storage
GitOps
certificates
TLS
runtime images
resource pressure
findings
timeline
changes
snapshots

```

Always retain redaction.

---

# 28. BUILD INCIDENT TIMELINE INTELLIGENCE

Improve event timeline correlation around:

```text
deployment rollout
pod creation
container restart
failed scheduling
image pull failure
mount failure
certificate issue
Flux reconciliation
Helm change

```

Sort chronologically.

Where timestamps allow, show:

```text
T-10m
T-5m
T0
T+2m

```

relative to an incident/change timestamp.

---

# 29. ADD INCIDENT FINGERPRINTING

Where useful, produce a compact fingerprint:

```text
namespace
affected workloads
dominant failure reasons
recent image revisions
Flux revision
Helm revision
certificate warnings
resource pressure
event signatures

```

This allows incidents to be compared without storing secrets.

---

# 30. CONTINUOUSLY IMPROVE TERMINAL UX

Every iteration should consider:

```text
Is information easier to find?
Can important failures be seen faster?
Can repeated typing be eliminated?
Can the user drill down directly?
Can tables fit better?
Can refresh be smoother?

```

Keep UI:

```text
dense
professional
stable
fast
keyboard-first

```

---

# 31. DO NOT TURN THE UI INTO DECORATION

No unnecessary:

```text
ASCII art
oversized banners
animations
loading spinners
rainbow colors
decorative borders

```

Every UI element must communicate operational information.

---

# 32. IMPROVE ADAPTIVE TABLES

For each table establish:

```text
mandatory columns
important columns
optional columns

```

At narrow widths:

```text
remove optional columns

```

before truncating important information.

Always retain full output in:

```text
Full Output Center

```

---

# 33. CONTINUOUSLY REDUCE USER TYPING

Whenever the application already knows:

```text
context
namespace
pod
container
service
workload
GitRepository
certificate

```

allow the user to select it instead of typing it again.

Use numbered discovery.

---

# 34. ADD CONTEXTUAL ACTIONS

From selected objects allow related read-only actions.

Example:

```text
selected pod
   ↓
inspect
logs
events
metrics
owner
service mapping
PVC
certificates
GitOps
evidence

```

---

# 35. CONTINUOUSLY IMPROVE SEARCH

Global search should progressively support:

```text
pod
container
workload
service
node
image
digest
PVC
certificate
GitRepository
HelmRelease
event
IP address

```

Results should identify resource type.

---

# 36. IMPROVE PERFORMANCE WITH EVERY ITERATION

Continuously inspect for:

```text
N+1 kubectl calls
duplicate API requests
unnecessary JSON parsing
unbounded commands
repeated filesystem scans
redundant external processes

```

Prefer:

```text
bulk API retrieval
cache reuse
single-pass parsing
local filtering

```

---

# 37. API CALL BUDGET

Treat Kubernetes API efficiency as a quality requirement.

For each dashboard refresh ask:

```text
Can this use cached data?
Can multiple screens share this collector?
Can one bulk query replace many individual calls?

```

Avoid unnecessary API traffic.

---

# 38. CONTINUOUSLY IMPROVE CACHE INTELLIGENCE

Allow different TTLs based on data type.

Fast-changing:

```text
metrics
pods

```

Slow-changing:

```text
certificates
Git repositories
storage classes

```

Add:

```text
cache hit
cache miss
cache age
forced refresh

```

diagnostics where helpful.

---

# 39. BACKGROUND COLLECTION

Where Bash can safely support it, allow bounded parallel collection.

Use:

```text
limited workers
tracked PIDs
timeouts
cleanup

```

Never create uncontrolled background jobs.

---

# 40. CONTINUOUSLY IMPROVE ERROR CLASSIFICATION

Expand error recognition rather than printing raw failures.

Target classes:

```text
AUTH_ERROR
RBAC_DENIED
NETWORK_ERROR
DNS_ERROR
TLS_ERROR
API_TIMEOUT
NOT_FOUND
UNSUPPORTED
COMMAND_MISSING
PARSE_ERROR
EMPTY_RESULT
NOT_CONFIGURED

```

Keep raw error accessible in Full Output.

---

# 41. DISTINGUISH ABSENCE FROM FAILURE

Examples:

```text
No warning events

```

is not an error.

```text
Unable to list warning events due to RBAC

```

is an access limitation.

```text
Event API call timed out

```

is an operational failure.

Never show all three as:

```text
0 EVENTS

```

---

# 42. CONTINUOUSLY IMPROVE SECURITY

Every new feature must undergo:

```text
credential exposure review
secret exposure review
shell injection review
path traversal review
temporary-file review
argument validation review
scope escape review

```

---

# 43. MAINTAIN READ-ONLY DEFAULT

The operational application remains:

```text
READ ONLY

```

New functionality must default to inspection.

Developer-mode exceptions such as:

```text
Git commit
Git push
Flux reconcile

```

must remain isolated from production dashboard behavior.

---

# 44. CONTINUOUSLY IMPROVE REDACTION

Extend redaction when new credential patterns are encountered.

Potential patterns:

```text
Authorization
Bearer
token
password
passwd
secret
client_secret
api_key
apikey
private_key
access_key
session_token

```

Do not over-redact ordinary Kubernetes resource names containing words such as:

```text
secret-controller

```

Redaction should target values, not blindly remove legitimate names.

---

# 45. CONTINUOUSLY IMPROVE TEST COVERAGE

Every significant bug fix must add a regression self-test whenever practical.

Rule:

```text
BUG FIX
   ↓
ADD TEST

```

so the same defect is less likely to return.

---

# 46. SELF-TEST GROWTH

Expand embedded tests over time for:

```text
CPU conversion
memory conversion
duration formatting
table sizing
error classification
redaction
Git URL parsing
Flux revision parsing
certificate parsing
scope enforcement
status logic
snapshot diffing
cache expiration
finding deduplication

```

---

# 47. ADD REGRESSION SUITES

Categorize self-tests:

```text
UNIT
SECURITY
PARSING
SCOPE
GITOPS
CERTIFICATE
RENDERING
DEV PIPELINE

```

Display per-category counts.

---

# 48. CONTINUOUSLY IMPROVE LIVE SMOKE TESTS

Read-only Kubernetes smoke tests should validate every major collector supported by current RBAC.

Do not fail optional features simply because the cluster does not provide them.

Classify:

```text
PASS
SKIP
RBAC
UNAVAILABLE
FAIL

```

---

# 49. TEST MULTIPLE FAILURE CONDITIONS

The utility must increasingly simulate or self-test:

```text
missing kubectl
invalid context
expired auth
missing metrics
RBAC denied
empty namespace
large namespace
missing Flux
failed HelmRelease
missing cert-manager
expired certificate fixture
terminal width 80
terminal width 160
CRLF
broken Git remote

```

---

# 50. CONTINUOUSLY IMPROVE WSL + VS CODE EXPERIENCE

Future changes must remain easy to:

```text
edit
test
run
commit
publish

```

inside VS Code WSL.

Maintain:

```text
--dev-watch
--dev-validate
--dev-self-test
--dev-smoke
--dev-release

```

---

# 51. AUTONOMOUS FIX-TEST LOOP

When the coding agent is operating in VS Code/WSL and has execution capability:

```text
EDIT
 ↓
TEST
 ↓
FAIL
 ↓
ANALYZE
 ↓
FIX
 ↓
RETEST

```

Repeat until mandatory validation succeeds.

Do not stop after the first failed test and ask the user to debug obvious implementation defects manually.

---

# 52. ALWAYS VERIFY ACTUAL EXECUTION

Never claim:

```text
PASS

```

for a test that was not executed.

Use:

```text
NOT RUN
SKIPPED
UNAVAILABLE

```

where appropriate.

---

# 53. CONTINUOUSLY IMPROVE GIT SAFETY

Preserve:

```text
no force push
no unrelated files
no automatic merge
no automatic rebase
no credentials
no push before testing

```

Always ensure the committed version is the tested version.

---

# 54. CONTINUOUSLY IMPROVE FLUX VERIFICATION

After GitHub push, improve correlation between:

```text
Git commit
GitRepository artifact
Kustomization revision
HelmRelease state
Runtime workload state

```

Where possible provide:

```text
Git commit → Flux observed → Runtime healthy

```

as separate verified stages.

---

# 55. DO NOT CONFUSE SOURCE SYNC WITH RUNTIME SUCCESS

Always distinguish:

```text
GIT PUSHED
FLUX FETCHED
FLUX RECONCILED
KUSTOMIZATION READY
HELM READY
WORKLOAD READY

```

Each is a separate state.

Do not collapse them into:

```text
DEPLOYED

```

without evidence.

---

# 56. ADD PLUGIN-LIKE INTERNAL MODULE DESIGN

Even though the program is one Bash file, organize modules so future capabilities can be added cleanly.

Concept:

```text
register_module
register_collector
register_screen
register_check
register_exporter
register_self_test

```

This should remain internal Bash functionality.

No external plugin files.

---

# 57. MODULE REGISTRY

Move toward maintaining internal metadata:

```text
module name
module status
required tools
required APIs
required RBAC
collector function
render function
health function

```

This enables capability discovery.

---

# 58. CAPABILITY DISCOVERY

At startup determine what the environment supports.

Example:

```text
CAPABILITY                       STATUS

Kubernetes Core API             AVAILABLE
Metrics API                     AVAILABLE
Nodes                           RBAC DENIED
Flux                            AVAILABLE
Helm                            AVAILABLE
cert-manager                    NOT INSTALLED
OpenSSL                         AVAILABLE
Splunk                          NOT CONFIGURED

```

Use this to dynamically adapt menus.

---

# 59. HIDE IRRELEVANT FEATURES INTELLIGENTLY

If cert-manager does not exist:

Do not remove the Certificate Auditor.

Instead show:

```text
cert-manager resources unavailable
TLS Secret inspection remains available

```

Adapt intelligently.

---

# 60. CONTINUOUSLY IMPROVE PORTABILITY

Avoid dependence on:

```text
vendor-specific Kubernetes distribution
Ericsson aliases
OpenShift-only utilities
specific node labels
specific namespaces
specific Flux namespace

```

Detect rather than assume.

---

# 61. SUPPORT MULTIPLE KUBERNETES ENVIRONMENTS

Where practical remain compatible with:

```text
upstream Kubernetes
EKS
AKS
GKE
OpenShift-compatible kubectl workflows
Rancher-managed clusters
on-prem Kubernetes

```

without hardcoding one platform.

---

# 62. ADD DISTRIBUTION DETECTION ONLY WHEN USEFUL

Where platform information can improve diagnostics, detect safely.

Do not alter fundamental behavior solely based on vendor assumptions.

---

# 63. CONTINUOUSLY IMPROVE DOCUMENTATION INSIDE THE SCRIPT

The script itself should include:

```text
clear section headers
function comments
CLI help
developer help
module help

```

Do not create a separate README as a requirement.

The application should explain itself.

---

# 64. CONTINUOUSLY IMPROVE `--help`

As features increase, keep help organized.

Suggested sections:

```text
USAGE
CORE OPERATIONS
OBSERVABILITY
INCIDENT
GITOPS
CERTIFICATES
SPLUNK
EXPORT
DEVELOPER
EXAMPLES

```

---

# 65. ADD `--capabilities`

Provide:

```bash
./KubeOps_Sentinel.sh --capabilities

```

showing what functionality is available in the current environment.

This should be dynamically determined.

---

# 66. ADD `--doctor`

Develop a diagnostic mode:

```bash
./KubeOps_Sentinel.sh --doctor

```

to check:

```text
shell
kubectl
kubeconfig
auth
RBAC
metrics
Flux
Helm
openssl
temporary storage
terminal
Git
WSL when relevant

```

This is different from cluster health.

It diagnoses whether Sentinel itself can operate fully.

---

# 67. CONTINUOUSLY IMPROVE EXPORTS

Support normalized export of:

```text
resources
health
findings
GitOps
certificates
incidents
snapshots

```

Formats where feasible:

```text
TXT
CSV
JSON

```

Ensure exports represent actual data and statuses.

---

# 68. ADD MACHINE-READABLE MODE

Where useful support:

```bash
--json

```

for non-interactive commands.

For example:

```bash
./KubeOps_Sentinel.sh \
  --health \
  --json

```

This makes future integration possible.

Do not break interactive mode.

---

# 69. BUILD TOWARD AUTOMATION-FRIENDLY EXIT CODES

Non-interactive commands should return meaningful exit codes.

Document them consistently.

Example:

```text
0 success / healthy
1 operational finding
2 usage/configuration issue
3 auth/API failure
4 partial/unavailable required data

```

Keep semantics stable.

---

# 70. ADD `--quiet`

For automation use:

```bash
--quiet

```

returning only essential output.

Interactive dashboard behavior remains unchanged.

---

# 71. ADD DEBUG MODE

Support:

```bash
--debug

```

with:

```text
collector timing
cache decisions
command classification
API call timing

```

Never print secrets.

Debug mode must still apply redaction.

---

# 72. PERFORMANCE TELEMETRY

Optionally measure:

```text
collector runtime
API latency
cache hit ratio
render duration

```

Show under diagnostics.

This helps optimize future versions.

---

# 73. CONTINUOUSLY SEEK BOTTLENECKS

If one collector dominates refresh time:

```text
identify it
cache it
parallelize safely
reduce calls

```

Do not accept unnecessary delays.

---

# 74. VERSION EVERY MEANINGFUL RELEASE

Increase:

```text
APP_VERSION

```

for meaningful capability changes.

Use semantic versioning principles where practical.

---

# 75. MAINTAIN INTERNAL CHANGE HISTORY

Inside the source maintain a compact changelog comment.

Example:

```text
1.5.0
- Added resource graph
- Added Flux runtime correlation
- Added snapshot diff engine

```

Do not make the header excessively large.

---

# 76. CONTINUOUSLY CLEAN DEAD CODE

After refactoring:

```text
remove unused functions
remove unused variables
remove duplicate parsing

```

but only after confirming they are truly unused.

Do not remove code merely because static grep does not find an obvious caller when dynamic dispatch exists.

---

# 77. NEVER REDUCE QUALITY FOR SHORTER CODE

Do not optimize for:

```text
fewest lines
smallest file
short answer

```

Optimize for:

```text
correctness
clarity
maintainability
safety
performance
operational value

```

---

# 78. DO NOT ADD COMPLEXITY WITHOUT VALUE

Every new subsystem must answer:

```text
Which operational problem does this solve?

```

If there is no strong answer:

```text
do not add it.

```

---

# 79. ALWAYS LOOK FOR HIGH-VALUE AUTOMATION OPPORTUNITIES

During every iteration evaluate whether the following could provide meaningful value:

```text
automated incident snapshot
pre/post change comparison
resource anomaly detection
restart trend detection
certificate expiry monitoring
GitOps synchronization verification
deployment consistency checks
image variance detection
service endpoint mismatch detection
capacity headroom analysis
Splunk filter validation

```

Add only when evidence/data exists.

---

# 80. BUILD TOWARD ONE-COMMAND TRIAGE

Long-term target:

```bash
./KubeOps_Sentinel.sh \
  --triage \
  --context CONTEXT \
  --namespace NAMESPACE

```

It should eventually combine:

```text
health
resources
events
GitOps
certificates
services
storage
findings

```

into a concise triage report.

---

# 81. BUILD TOWARD WORKLOAD-SPECIFIC TRIAGE

Target:

```bash
./KubeOps_Sentinel.sh \
  --triage-workload WORKLOAD

```

Expected correlation:

```text
workload
pods
containers
resources
events
services
endpoints
PVCs
GitOps
images
certificates
findings

```

---

# 82. BUILD TOWARD INCIDENT COMPARISON

Allow future comparison:

```text
Incident A
vs.
Incident B

```

using normalized fingerprints and snapshots.

Do not expose secrets.

---

# 83. BUILD TOWARD KNOWLEDGE WITHOUT EXTERNAL AI DEPENDENCY

The script should provide strong deterministic diagnosis before requiring AI.

Prioritize:

```text
rules
relationships
evidence
correlation

```

over external LLM calls.

The core tool must remain usable offline from AI services.

---

# 84. OPTIONAL AI INTEGRATION MUST REMAIN OPTIONAL

If AI assistance is introduced later:

```text
never send credentials
never send secrets
never send kubeconfig
never require internet for core operation

```

AI must enhance interpretation, not replace factual collectors.

---

# 85. CONTINUOUSLY IMPROVE FINDING EXPLANATIONS

When a failure is detected provide concise technical interpretation.

Example:

```text
OBSERVED
Service has selector matching 3 pods.

OBSERVED
EndpointSlice contains only 2 ready endpoints.

INTERPRETATION
One matching pod is currently excluded from ready service endpoints.

NEXT
Inspect readiness condition of the unmatched pod.

```

This is significantly more useful than:

```text
Endpoints WARN

```

---

# 86. ADD EVIDENCE REFERENCES

Findings should reference the collector/output that produced them.

Example:

```text
Evidence:
pods/example
events/example
endpointslices/service-x

```

This improves auditability.

---

# 87. CONTINUOUSLY IMPROVE STATUS CONSISTENCY

All modules should share the same canonical status vocabulary.

Use:

```text
OK
INFO
WARN
FAIL
UNKNOWN
N/A
AUTH
RBAC
TIMEOUT
UNAVAILABLE
NOT_CONFIGURED

```

Avoid:

```text
GOOD
BAD
ERROR
BROKEN

```

unless part of raw external output.

---

# 88. CONTINUOUSLY IMPROVE TIME HANDLING

Normalize timestamps.

Show local time clearly.

When comparing Kubernetes timestamps:

```text
convert correctly
preserve original where useful

```

Avoid timezone mistakes.

---

# 89. HANDLE LARGE CLUSTERS

Every future enhancement must consider:

```text
500 pods
1000 pods
large event counts
many Helm releases
many Flux resources

```

Do not assume tiny environments.

---

# 90. LIMIT DEFAULT OUTPUT

For large data:

```text
summarize first
drill down on demand

```

Preserve full data in:

```text
Full Output
Export

```

---

# 91. MAINTAIN INTERRUPT SAFETY

Every new background process must cooperate with:

```bash
trap cleanup EXIT INT TERM HUP

```

Ctrl+C must never leave:

```text
hidden cursor
stty corruption
background processes
temporary secrets
locks

```

---

# 92. CONTINUOUSLY TEST TERMINAL RESTORATION

Developer tests should exercise:

```text
interrupt dashboard
interrupt evidence
interrupt dev-watch
interrupt Flux verification

```

and ensure terminal cleanup.

---

# 93. ADD FEATURE FLAGS ONLY WHEN NECESSARY

Prefer automatic capability detection.

Use configuration switches only when behavior genuinely needs user control.

Avoid creating dozens of flags for trivial formatting options.

---

# 94. KEEP DEFAULTS SAFE

Default behavior should remain:

```text
READ ONLY
NO MUTATIONS
NO PUSH
NO FLUX RECONCILE
NO SECRET OUTPUT

```

Developer publishing requires explicit developer commands.

---

# 95. CONTINUOUSLY IMPROVE DEVELOPER FEEDBACK

After a failed developer validation show:

```text
stage
failure
reason
suggested correction

```

Example:

```text
FAIL: SELF TEST

Test:
CPU_PARSE_007

Expected:
1500m

Observed:
1.5m

Source function:
normalize_cpu

```

---

# 96. ADD TEST TIMING

Developer validation should optionally show:

```text
test duration
total validation duration

```

This helps identify regressions in the development pipeline.

---

# 97. CONTINUOUSLY IMPROVE RELEASE TRACEABILITY

Release summary should retain:

```text
version
source hash
Git commit
branch
remote
test result
Kubernetes test scope
Flux revision
timestamp

```

---

# 98. NEVER PUSH UNTESTED SOURCE

The tested source checksum must equal the staged/committed source checksum.

Maintain this invariant permanently.

---

# 99. CONTINUOUSLY REVIEW GIT DIFF BEFORE COMMIT

The coding agent must inspect:

```bash
git diff -- KubeOps_Sentinel.sh

```

before committing.

Look for:

```text
accidental deletions
security regressions
debug code
hardcoded credentials
hardcoded namespaces
broken functions

```

---

# 100. NEVER COMMIT DEBUG SECRETS

Before committing scan for accidental:

```text
token=
password=
Bearer
PRIVATE KEY
kubeconfig content
real credentials

```

Distinguish test fixture placeholders from real-looking secrets cautiously.

---

# 101. ALWAYS LEAVE THE APPLICATION BETTER THAN BEFORE

For every substantial iteration, the coding agent should be able to identify at least one improvement in one or more of:

```text
functionality
reliability
performance
security
diagnostics
test coverage
UX
maintainability
automation

```

Do not make unrelated changes merely to satisfy this condition.

---

# 102. CONTINUOUS ENHANCEMENT REVIEW

Before finalizing any change, ask internally:

```text
Can this collector be reused?

Can this reduce API calls?

Can this improve incident evidence?

Can this improve health checks?

Can this improve GitOps correlation?

Can this improve certificate visibility?

Can this add a regression test?

Can this improve error classification?

Can this improve usability?

Can this simplify duplicate logic?

```

Apply justified improvements.

---

# 103. FINAL QUALITY GATE FOR EVERY ITERATION

Before committing:

```text
SOURCE REVIEW
    ↓
bash -n
    ↓
static security checks
    ↓
self-tests
    ↓
regression tests
    ↓
live read-only smoke tests where available
    ↓
git diff --check
    ↓
full diff review
    ↓
tested-source checksum verification
    ↓
commit
    ↓
push
    ↓
Flux verification where configured

```

Never skip mandatory stages merely because the requested change appears small.

---

# 104. CODING AGENT AUTONOMY

When operating inside VS Code with WSL access, the coding agent should:

```text
inspect
implement
execute
observe failure
debug
fix
retest

```

without repeatedly asking the user to run commands that the environment already allows the agent to run.

Only require user intervention for genuinely unavailable credentials, permissions or external decisions.

---

# 105. NEVER FAKE SUCCESS

These statements require actual evidence:

```text
TESTED
PASS
PUSHED
SYNCHRONIZED
READY
VALIDATED

```

If evidence is missing, say:

```text
NOT RUN
NOT VERIFIED
UNKNOWN
UNAVAILABLE

```

---

# 106. LONG-TERM NORTH STAR

Every future version should move KubeOps Sentinel toward answering these questions from one terminal:

```text
What is currently unhealthy?

What changed?

What changed since the known-good state?

Which pods consume the most resources?

Are requests and limits appropriate?

Which nodes or pools are under pressure?

Why is this workload unavailable?

Which Kubernetes events correlate with the failure?

Which Service maps to this workload?

Are its endpoints actually ready?

Is storage contributing to the issue?

Which image is actually running?

Does runtime state match GitOps?

Did Flux fetch the expected Git revision?

Did Helm reconciliation succeed?

Which certificates are expiring?

Does TLS actually work?

What evidence proves our side is functioning?

What should I check next?

What changed after deployment?

Which Splunk searches are valid for this environment?

Can I produce an incident evidence package immediately?

```

The utility should progressively answer more of these questions with factual, correlated evidence.

---

# 107. PERMANENT ENGINEERING PRINCIPLE

Use this hierarchy for every future decision:

```text
SAFETY
  ↓
CORRECTNESS
  ↓
EVIDENCE
  ↓
RELIABILITY
  ↓
SECURITY
  ↓
PERFORMANCE
  ↓
AUTOMATION
  ↓
OPERABILITY
  ↓
USER EXPERIENCE
  ↓
COSMETICS

```

Never sacrifice a higher priority for a lower one.

---

# 108. PERMANENT DATA PRINCIPLE

Apply everywhere:

```text
UNKNOWN
is better than
WRONG.

RBAC_DENIED
is better than
0.

UNAVAILABLE
is better than
GUESSED.

POTENTIAL_DRIFT
is better than
FALSE_DRIFT.

GENERATED_UNVALIDATED
is better than
VALIDATED_WITHOUT_TESTING.

NOT_VERIFIED
is better than
ASSUMED.

```

---

# 109. PERMANENT IMPLEMENTATION RULE

Every future request should be interpreted as:

```text
IMPLEMENT THE REQUEST
+
PRESERVE EVERYTHING THAT WORKS
+
REMOVE JUSTIFIED TECHNICAL WEAKNESSES
+
ADD TEST COVERAGE
+
INCREASE REUSABILITY
+
INCREASE OPERATIONAL VALUE
+
VERIFY THE RESULT

```

without introducing unnecessary complexity.

---

# 110. FINAL INSTRUCTION TO EVERY FUTURE CODING AGENT

Whenever modifying KubeOps Sentinel:

```text
Do not merely satisfy the current prompt.

Understand the entire utility.

Protect existing capability.

Identify the strongest adjacent improvements.

Implement them when they provide concrete operational value.

Refactor duplicated logic.

Improve evidence quality.

Improve diagnostics.

Improve performance.

Improve safety.

Increase self-test coverage.

Test against WSL.

Test against Kubernetes when access exists.

Review the final Git diff.

Commit only tested source.

Push only after validation.

Verify Flux when configured.

Never fabricate success.

```

The desired trajectory is:

```text
SCRIPT
  ↓
UTILITY
  ↓
OPERATIONS CONSOLE
  ↓
DIAGNOSTIC PLATFORM
  ↓
INCIDENT INTELLIGENCE SYSTEM
  ↓
KUBERNETES OPERATIONS COMMAND CENTER

```

while always retaining:

```text
ONE SCRIPT
ONE EXECUTABLE
ONE SOURCE OF TRUTH
KubeOps_Sentinel.sh

```

---

# 111. CANONICAL GITHUB SYNC RULE

The permanent canonical repository for KubeOps Sentinel is:

```text
https://github.com/dheer629/jevgitonm
```

For every future KubeOps Sentinel change:

```text
CHECK / FETCH LATEST REMOTE STATE
  ↓
COMPARE WITH LOCAL WORKTREE
  ↓
PRESERVE UNRELATED UPSTREAM CHANGES
  ↓
IMPLEMENT + TEST
  ↓
REVIEW DIFF
  ↓
COMMIT ONLY TESTED CHANGES
  ↓
PUSH TO THE CANONICAL REPOSITORY
  ↓
VERIFY REMOTE COMMIT SHA / CONTENT
  ↓
VERIFY FLUX WHEN CONFIGURED
```

Non-negotiable Git safety:

```text
NO FORCE PUSH
NO BLIND OVERWRITE
NO AUTOMATIC DESTRUCTIVE RESET
NO PUSH BEFORE VALIDATION
NO CLAIM OF SYNC WITHOUT REMOTE VERIFICATION
```

The GitHub repository is the authoritative source for subsequent work. Before modifying `KubeOps_Sentinel.sh`, inspect the latest repository version first and base changes on that version.
