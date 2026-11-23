from datetime import datetime, timedelta, timezone

FINDING = "Policy:S3/BucketPublicAccessGranted"
BLOCK_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def instant(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("A timezone is required")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def required(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError(f"Invalid {label}")
    return value.strip()


def finding(event):
    detail = event["detail"]
    if (event["source"], event["detail-type"], detail["type"]) != (
        "aws.guardduty", "GuardDuty Finding", FINDING
    ):
        raise ValueError("Unsupported finding")
    account, region = detail["accountId"], detail["region"]
    resource = detail["resource"]
    if resource["resourceType"] != "S3Bucket" or len(resource["s3BucketDetails"]) != 1:
        raise ValueError("This playbook requires one affected S3 bucket")
    arn = required(detail["arn"], "finding ARN")
    parts = arn.split(":", 5)
    if (len(parts) != 6 or parts[0] != "arn" or parts[2:5] != ["guardduty", region, account]
            or not parts[5].startswith("detector/") or not parts[5].endswith("/finding/" + detail["id"])):
        raise ValueError("Inconsistent finding identity")
    severity = detail["severity"]
    if type(severity) not in (int, float) or not 0 <= severity <= 10:
        raise ValueError("Invalid severity")
    first_seen = instant(detail["service"]["eventFirstSeen"])
    last_seen = instant(detail["service"]["eventLastSeen"])
    updated = instant(detail["updatedAt"])
    if first_seen > last_seen or last_seen > updated:
        raise ValueError("Finding update precedes its occurrence")
    return {"id": arn, "account": account, "region": region, "type": FINDING,
            "bucket": required(resource["s3BucketDetails"][0]["name"], "bucket"),
            "severity": severity, "first_seen": first_seen, "last_seen": last_seen, "updated": updated}


def ingest(store, event):
    incoming = finding(event)

    def decide(current):
        if current is None:
            return {**incoming, "status": "OPEN", "owner": "unassigned"}, "Finding opened", "GuardDuty", incoming["updated"]
        if current["bucket"] != incoming["bucket"]:
            raise ValueError("Finding changed resource identity")
        if incoming["updated"] <= current["updated"]:
            return None
        state = {**current, **incoming, "last_seen": max(current["last_seen"], incoming["last_seen"])}
        note = "Finding updated"
        if current["status"] in {"REMEDIATED", "CLOSED"} and state["last_seen"] > current["remediated_at"]:
            state["status"] = "OPEN"
            for key in ("remediated_at", "verification", "cloudtrail_event"):
                state.pop(key, None)
            note = "Reopened after a later occurrence"
        return state, note, "GuardDuty", incoming["updated"]

    return store.change(incoming["id"], decide)


def transition(store, key, stage, analyst, when, evidence):
    analyst = required(analyst, "analyst")
    when = instant(when)
    expected = {"TRIAGED": "OPEN", "REMEDIATED": "TRIAGED", "CLOSED": "REMEDIATED"}

    def decide(current):
        if current is None or current["status"] != expected[stage]:
            raise ValueError(f"{stage} requires a case in {expected[stage]} state")
        if when < max(current["last_seen"], current.get("last_action", current["updated"])):
            raise ValueError("Analyst action predates relevant case evidence")
        state = {**current, "status": stage, "last_action": when}
        if stage == "TRIAGED":
            record = evidence
            earliest = datetime.fromisoformat(current["last_seen"]) - timedelta(minutes=5)
            event_time = instant(record["eventTime"])
            if (record["eventSource"] != "s3.amazonaws.com" or record["eventName"] not in {"PutBucketPolicy", "PutBucketAcl"}
                    or record["recipientAccountId"] != current["account"] or record["awsRegion"] != current["region"]
                    or record["requestParameters"]["bucketName"] != current["bucket"] or record.get("errorCode")
                    or not earliest.isoformat(timespec="microseconds") <= event_time <= current["last_seen"]):
                raise ValueError("CloudTrail record does not match this finding")
            state["owner"] = analyst
            state["cloudtrail_event"] = required(record["eventID"], "CloudTrail event ID")
            principal = required(record["userIdentity"]["arn"], "principal ARN")
            note = f"Correlated {record['eventName']} by {principal}, CloudTrail event {state['cloudtrail_event']}"
        elif stage == "REMEDIATED":
            state["remediated_at"] = when
            note = required(evidence, "remediation decision")
        else:
            config = evidence["PublicAccessBlockConfiguration"]
            observed = instant(evidence["observedAt"])
            age = datetime.fromisoformat(when) - datetime.fromisoformat(observed)
            if (evidence["bucket"] != current["bucket"] or evidence["account"] != current["account"]
                    or evidence["PolicyStatus"]["IsPublic"] is not False
                    or any(config.get(flag) is not True for flag in BLOCK_FLAGS)
                    or not current["remediated_at"] <= observed <= when or age > timedelta(minutes=5)):
                raise ValueError("Closure requires fresh, matching evidence of all four block settings and a nonpublic policy")
            state["verification"] = evidence
            note = "Verified all four S3 Block Public Access settings and a nonpublic bucket policy"
        return state, note, analyst, when

    return store.change(key, decide)
