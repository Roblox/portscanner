<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# portscanner-scanner

`portscanner-verify` is a Python 3.12 VERIFY worker that runs Nmap against
exactly one operator-authorized public IPv4 address. It has no target-file,
CIDR-target, hostname, or arbitrary batch mode. Masscan is not installed or
used.

## Build

The image depends on the sibling `contracts` package, so the Docker build
context must be the repository root. From the repository root, run:

```sh
docker build \
  --file scanner/nmap/Dockerfile \
  --tag portscanner-scanner:local \
  .
```

Using `scanner/nmap` as the build context cannot provide the shared package and
is intentionally unsupported.

## Profiles

- `fast-full-tcp` performs bounded TCP connect discovery for ports `1-65535`, then
  service/version enrichment only for ports discovery explicitly reported open.
  An operator may redundantly declare only `1-65535`.
- `targeted-tcp` requires `--ports` (alias `--tcp-ports`) and discovers exactly the normalized
  port/range coverage before enriching only open ports.
- `deep` also requires explicit coverage. It adds only explicitly requested
  scripts from the deployment's safe allowlist.

Port declarations are decimal ports or inclusive ranges separated by commas.
The worker sorts and merges duplicate, adjacent, and overlapping declarations.
For example, `443,80-82,81-90` declares `80-90,443`. The normalized result is
limited to 256 terms, matching the shared result envelope.

The compiled safe-script catalog is:

- `banner`
- `http-title`
- `ssh-hostkey`
- `ssh2-enum-algos`
- `ssl-cert`
- `ssl-enum-ciphers`
- `tls-alpn`

The default deployment allowlist is `banner,http-title,ssh2-enum-algos,ssl-cert,tls-alpn`.
Set `NMAP_SAFE_SCRIPT_ALLOWLIST` to a comma-separated subset to narrow it.
Select scripts with repeated `--deep-script` fields or `NMAP_DEEP_SCRIPTS`.
Script categories, expressions, paths, and script arguments are not accepted.

## Required operator fields

Supply these as CLI fields or their named environment variables:

- `--target` / `TARGET_ADDRESS`
- `--profile` / `SCAN_PROFILE`
- `--event-id` / `TARGET_EVENT_ID`
- `--directive-id` / `SCAN_DIRECTIVE_ID`
- `--trace-id` / `TRACE_ID`
- `--run-id` / `RUN_ID`
- `--attempt-id` / `ATTEMPT_ID`
- `--target-id` / `TARGET_ID`
- `--target-provider` / `TARGET_PROVIDER`
- `--target-scope-id` / `TARGET_SCOPE_ID`
- `--target-location` / `TARGET_LOCATION`
- `--target-resource-id` / `TARGET_RESOURCE_ID`
- `--target-private-address` / `TARGET_PRIVATE_ADDRESS`
- `--target-generation` / `TARGET_GENERATION`
- `--deadline-at` / `SCAN_DEADLINE_AT`
- `--not-after` / `SCAN_NOT_AFTER`
- `--image-version` / `SCANNER_IMAGE_VERSION`
- `--s3-bucket` / `RESULTS_BUCKET`
- `--s3-prefix` / `RESULTS_PREFIX`

Equivalent `PORTSCANNER_*` environment names are accepted for operator
integration. The optional compatibility fields `--scan-mode` and
`--service-detection` are validated against the selected profile; they cannot
enable a different or unbounded scan behavior.

`deadline-at` is generator dispatch metadata and does not stop an already
dispatched scan. `not-after` is the absolute execution cutoff. Before each Nmap
phase, the worker derives the remaining wall-clock budget, reserves 30 seconds
by default for result publication, and clamps both Nmap host and process
timeouts. It fails without starting a phase when less than a usable phase
budget remains. Configure the bounded reserve with
`SCANNER_UPLOAD_RESERVE_SECONDS`.

`SCANNER_IMAGE_VERSION` must be an immutable OCI `sha256` digest (optionally
prefixed by an image reference and `@`) or an immutable `git:<revision>` value.
Mutable tags such as `latest` are rejected.

The event, directive, target, provider, scope, location, resource, private
address, and generation fields construct the exact closed `Target`,
`ScanResult`, and `ScanResultEnvelope` models from `portscanner_contracts`.
`ScanResult` is the normalized evidence record nested inside the published
`ScanResultEnvelope`. Their deterministic SHA-256 identifiers must match those
models; scanner-local replacement identifiers are not generated.

`SCANNER_ALLOWED_CIDRS` and `SCANNER_DENIED_CIDRS` are optional comma-separated
IPv4 deployment controls. They can also be supplied as repeated
`--allowed-cidr` and `--denied-cidr` fields. Denies take precedence. The target
must still be a globally reachable public IPv4 address; private, loopback,
link-local, multicast, reserved, unspecified, special-service, and metadata
addresses are rejected even if an allow CIDR contains them.

Example shape (placeholders are intentional):

```sh
portscanner-verify \
  --target '<public-ipv4>' \
  --profile targeted-tcp \
  --ports '22,80,443,8000-8010' \
  --event-id '<event-sha256>' \
  --directive-id '<directive-sha256>' \
  --trace-id trace-001 \
  --run-id run-001 \
  --attempt-id attempt-001 \
  --target-id '<target-sha256>' \
  --target-provider '<contract-provider>' \
  --target-scope-id '<contract-scope>' \
  --target-location '<contract-location>' \
  --target-resource-id '<contract-resource>' \
  --target-private-address '<private-ipv4>' \
  --target-generation 1 \
  --image-version 'sha256:<64-lowercase-hex-characters>' \
  --s3-bucket '<configured-results-bucket>' \
  --s3-prefix verify-results
```

## Bounds and result integrity

Discovery and enrichment rates, retries, RTT limits, host timeouts, process
timeouts, script timeout, and version intensity have conservative defaults and
bounded CLI/environment overrides. Commands are argv lists executed with
`shell=False`. Persisted command metadata replaces the target and local XML
path with fixed placeholders and never contains environment values, script
arguments, credentials, or subprocess output.

The worker parses XML with `defusedxml` and never rewrites or injects attributes
into Nmap output. A complete discovery result requires all of the following:

- a parseable `nmaprun` document;
- exactly one host matching the authorized envelope target;
- a successful `runstats/finished` marker and one accounted host;
- no host timeout; and
- explicit plus collapsed TCP port counts equal to the exact declared coverage.

A process timeout, nonzero exit, malformed XML, omitted coverage, or incomplete
enrichment produces a nonzero worker exit. Any retained non-open observation is
`UNKNOWN`; partial output never proves that a port is closed.

If discovery and enrichment report different open-port sets, the worker exits
nonzero and publishes a partial envelope without an enrichment artifact
reference. The parser marks observations from that attempt `UNKNOWN`, so the
attempt can be retained without asserting a conflicting state change.

Raw discovery XML is conditionally uploaded first. Enrichment XML, when
present, is uploaded next. Only then is an immutable shared-contract
`ScanResultEnvelope`, containing its normalized `ScanResult`, conditionally
uploaded. Keys are deterministic and immutable:

```text
<prefix>/events/<event-id>/attempts/<attempt-id>/raw/nmap-discovery.xml
<prefix>/events/<event-id>/attempts/<attempt-id>/raw/nmap-enrichment.xml
<prefix>/events/<event-id>/attempts/<attempt-id>/scan-result.json
```

Each raw artifact has a SHA-256 in the envelope. Every S3 write uses
`If-None-Match: *`; an existing attempt is never overwritten. The worker needs
object-scoped conditional `PutObject` access for its configured prefix. It does
not need bucket-wide list or delete permission. On scan failure it best-effort
uploads available raw XML first and then a failed/partial envelope before
exiting nonzero. `SIGTERM`/`SIGINT` requests bounded Nmap child termination and
the same best-effort failure publication. Publication is not guaranteed after
the container runtime sends `SIGKILL`.

Consumers must treat the envelope as the authoritative source for event,
trace, run, attempt, target-generation, profile, and coverage fields. The
included parser validates the shared `ScanResultEnvelope` and nested
`ScanResult`, verifies the XML SHA-256, checks target/coverage consistency, and
ignores correlation-like XML attributes.

## Container runtime

The Dockerfile uses a digest-pinned Python base, dated Debian snapshot, and exact
distribution Nmap version; release automation records and scans the resulting immutable
image digest. It runs as a non-root user and keeps `/tmp` writable. TCP connect scanning
does not require raw sockets, so neither the image nor Kubernetes grants Linux
capabilities:

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

No account, bucket, registry, or target is embedded in the image.
