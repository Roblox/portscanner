<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Scanning safety

Network scanning can disrupt services, trigger abuse controls, violate provider policy,
or reach an address that changed owners. This project does not grant permission to scan.

## Non-negotiable rules

1. Scan only assets you own or for which you have explicit written authorization.
2. Follow the cloud provider's acceptable-use, penetration-testing, and notification
   policies.
3. Never scan third parties, the general Internet, documentation ranges, vendor
   endpoints, shared services, or an address merely because it appeared in an old
   event.
4. Gate dispatch by an explicit authorized account; an empty account scope means no
   access.
5. Revalidate current provider ownership immediately before dispatch.
6. Treat deployment CIDR allowlisting as optional defense-in-depth. Apply CIDR denies
   first; an empty allowlist adds no CIDR restriction.
7. Set conservative packet, concurrency, destination, and time limits.
8. Keep an emergency dispatch-off control that does not depend on a healthy queue or
   cluster rollout.
9. Clean up temporary trust, events, Jobs, data, and infrastructure after a test.

The RFC 5737 ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`, and the RFC
3849 prefix `2001:db8::/32`, are documentation examples only. They are non-routable and
must not be used as canary destinations.

## Authorization record

Before enabling dispatch, record:

- approving owner and change record reference;
- exact accounts, Regions, resource types, and any optional CIDR constraints;
- excluded resources and shared-service boundaries;
- approved source vantage and egress identity;
- transports, ports, scanner features, and maximum Target size;
- global and per-destination packet/concurrency rates;
- start/end time and recurring cadence;
- monitoring and escalation path;
- provider-policy review; and
- stop and cleanup procedure.

Do not put personal names, email addresses, live account numbers, role identifiers, or
real CIDRs in this public repository. Keep the authorization record in the operator's
approved private system.

## Layered scope enforcement

Scope checks must occur when a Target enters inventory, when work is created, and again
at dispatch. The effective set is an intersection with explicit exclusions, never a
union:

```text
supported source
− deployment CIDR denylist
∩ authorized account
∩ authorized resource type
∩ current provider ownership
∩ optional deployment CIDR allowlist (identity when empty)
∩ approved scan profile
∩ available scanner-Pod quota and destination serialization
```

The scanner evaluates denies before the optional allowlist. A CIDR allowlist can provide
a useful second boundary for fixed Elastic IP ranges, but dynamic public addresses make
it impractical in many deployments. Empty CIDR lists do not weaken the mandatory
account and current-ownership gates. Inclusion in a CIDR never authorizes scanning a
third party.

Reject hostnames, address families, ranges, profiles, or free-form arguments that policy
does not explicitly support. Do not resolve a hostname at the worker and scan whatever
it returns.

## Ownership and recycled addresses

Public addresses can be released and reassigned quickly. A discovery-time match is not
enough.

Immediately before dispatch, reread the resource by stable provider identity and verify:

- the resource still exists in the expected account and Region;
- the address is still attached to that resource;
- the observed generation is the queued generation;
- the resource remains in an allowed class and, when configured, CIDR; and
- the verdict is unambiguous and fresh.

Only `ACTIVE` may dispatch. `STALE`, `MOVED`, `INACTIVE`, and `UNKNOWN` suppress the
scan. Ambiguous current state maps to `UNKNOWN`; a retry must repeat the reread.

## Rate and disruption controls

- Start with conservative `scanner_min_rate`, `scanner_max_rate`, and
  `scanner_max_concurrent_pods` values; bound queued/retained Job objects with
  `scanner_max_jobs`.
- Treat `scanner_max_concurrent_pods × scanner_max_rate` as the deployment's configured
  aggregate upper bound. Required destination-hash anti-affinity serializes active Pods
  for one public IPv4 destination.
- Limit Targets and ports per Job.
- Set connect, host, process, and Job deadlines.
- Reserve capacity for periodic reconciliation but cap priority bursts.
- Schedule around sensitive windows and honor destination-owner requests immediately.
- Watch packet loss, destination health, firewall/IDS events, provider abuse notices,
  queue age, and scanner retries during expansion.
- Do not assume a cloud instance type's nominal bandwidth is a safe scan rate.

Service detection, scripts, operating-system detection, UDP, and full-port profiles can
be materially more disruptive than a narrow TCP connect check. Enable each as a
separate reviewed profile.

## Outside-vantage requirement

The worker should test the public path that an untrusted external client would use. It
must not quietly fall back to a private route, cluster-local service, provider metadata
endpoint, or internal DNS answer. Record and monitor the worker's egress identity.

Outside vantage does not relax ownership requirements. Scanning from another provider,
Region, or account can introduce additional acceptable-use and data-transfer rules.

## Canary procedure

1. Keep dispatch globally disabled.
2. Configure one authorized account, one resource, one low-impact profile, and the
   minimum rate. Add a narrow CIDR allowlist when the resource uses a fixed authorized
   range.
3. Verify the current-state ownership response manually through an approved private
   process.
4. Enable one work item with a short deadline.
5. Observe dispatch, packet rate, destination health, evidence, parsing, and cleanup.
6. Replay the same work and confirm idempotency.
7. Change or expire the generation and confirm dispatch is suppressed.
8. Disable dispatch and verify that no Job remains.

Never use an unrelated public host as a “known open” test.

## Emergency stop

The operator must be able to:

1. disable new dispatch;
2. suspend signal and recurring schedules;
3. delete or stop active Jobs;
4. block scanner egress at the network boundary;
5. retain evidence and audit records; and
6. notify the authorization owner and provider if required.

Practice this procedure before broad activation.

`terraform/aws/scripts/emergency-pause.sh <central-root>` performs steps 1 and 2
directly through the AWS APIs after validating the expected account, Region, and exact
controls from Terraform state. It does not plan or refresh Helm and therefore does not
need a reachable Kubernetes API. It intentionally does not terminate Jobs already
running: use an authorized Kubernetes path for step 3, or an independently reviewed AWS
network/node-group control for steps 3 and 4 when the cluster API is unavailable.

## Cleanup

After a test or decommission:

- stop schedules and drain or discard queued work;
- remove temporary account/CIDR grants;
- remove spoke trust and event forwarding;
- delete test Jobs, namespaces, images, object prefixes, and databases according to
  retention policy;
- destroy project-created infrastructure from the correct Terraform state;
- verify shared Config, CloudTrail, VPC, and Kubernetes resources were preserved; and
- review billing and provider notices for delayed effects.
