# Member-account root

This independently deployable module can:

- create a secure local AWS Config recorder and delivery bucket;
- authorize one exact central account/region to aggregate Config;
- create an EC2 inventory role trusted by the exact central snapshot/signal IAM roles plus external ID; and
- forward only the inventory runtime's supported EC2 API calls and EC2 instance state-change hints from the default bus to one exact central bus ARN.

Config recording and EventBridge forwarding are optional. Forwarding defaults disabled,
and no AWS Organizations integration is required. API-call forwarding cannot be enabled
with `cloudtrail_mode = "disabled"`: choose `create` for a project-owned multi-Region
management trail or `existing` with a live-verified member/organization trail ARN. The
collector policy contains only `ec2:Describe*`; its trust policy names only the supplied
central roles, and the forwarding role contains only `events:PutEvents` for the supplied
bus.

Config aggregation authorization does not create or verify a central aggregator and does not guarantee that every desired region/resource is being recorded. Apply member authorization before configuring that account as a source of a central aggregator, and verify recorder health and aggregator freshness operationally. The exact collector role and external ID remain available for direct EC2 snapshots where Config coverage is insufficient. Set one shared `collector_role_name` and external ID across directly collected accounts so the central runtime can derive its account-scoped role template.

Both Config recording and EventBridge rules are regional. The aggregation authorization
runs in this provider Region and authorizes the exact central aggregator Region. The
application's create-mode aggregator includes only its own provider source Region, so
other source Regions need an existing aggregator configured for them or direct EC2
snapshots. The `signal_region` output is the only Region whose API/state hints this
module instance forwards. Deploy separate uniquely named/state roots for additional
hot-path Regions; one multi-Region CloudTrail does not make an EventBridge rule global.

Cost and destruction warning: Config recording, S3 versions, and EventBridge delivery can incur ongoing charges. The Config bucket does not force-delete, so preserve or explicitly empty retained versions before retirement.
