"""Run the offline demonstration or operate a case as an analyst."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.cases import finding, ingest, transition
from app.storage import DynamoStore, LocalStore

ROOT = Path(__file__).resolve().parent


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def now():
    return datetime.now(timezone.utc).isoformat()


def live_evidence(state):
    import boto3
    s3 = boto3.client("s3", region_name=state["region"])
    target = {"Bucket": state["bucket"], "ExpectedBucketOwner": state["account"]}
    block = s3.get_public_access_block(**target)["PublicAccessBlockConfiguration"]
    try:
        policy = s3.get_bucket_policy_status(**target)["PolicyStatus"]
    except s3.exceptions.ClientError as error:
        if error.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
        policy = {"IsPublic": False}
    return {"bucket": target["Bucket"], "account": target["ExpectedBucketOwner"],
            "observedAt": now(), "PublicAccessBlockConfiguration": block, "PolicyStatus": policy}


def demo():
    store = LocalStore(":memory:")
    fixture = ROOT / "fixtures"
    event = read(fixture / "finding.json")
    key = finding(event)["id"]
    first = ingest(store, event)
    replay = ingest(store, event)
    assert first["revision"] == replay["revision"] == 1
    transition(store, key, "TRIAGED", "demo-analyst", "2026-11-01T10:05:00Z", read(fixture / "cloudtrail.json"))
    transition(store, key, "REMEDIATED", "demo-analyst", "2026-11-01T10:12:00Z",
               "Tabletop decision: restore the approved bucket policy and enable all four bucket-level block settings.")
    state = transition(store, key, "CLOSED", "demo-reviewer", "2026-11-01T10:15:00Z", read(fixture / "verification.json"))
    return {"mode": "Offline simulation using synthetic evidence", "deliveries": 2,
            "cases": store.db.execute("SELECT COUNT(*) FROM records WHERE rev=0").fetchone()[0],
            "case": state, "timeline": store.history(key)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--db", default="incidents.sqlite3", help="local SQLite file")
    target.add_argument("--table", help="AWS DynamoDB case table (uses your configured region)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo")
    raw = commands.add_parser("ingest")
    raw.add_argument("file")
    for name in ("show", "triage", "remediate", "close"):
        cmd = commands.add_parser(name)
        cmd.add_argument("case")
        if name != "show":
            cmd.add_argument("--analyst", required=True)
        if name == "triage":
            cmd.add_argument("--cloudtrail", required=True, help="one decoded CloudTrail management event")
        elif name == "remediate":
            cmd.add_argument("--decision", required=True, help="record the mitigation already applied")
        elif name == "close":
            cmd.add_argument("--evidence", help="local mode only: S3 verification fixture")
    args = parser.parse_args()
    if args.command == "demo":
        result = demo()
    else:
        store = DynamoStore(args.table) if args.table else LocalStore(args.db)
        if args.command == "ingest":
            if args.table:
                parser.error("AWS ingestion is handled by the EventBridge rule. Use a local database for fixture replay.")
            result = ingest(store, read(args.file))
        else:
            state = store.get(args.case)
            if state is None:
                parser.error("Unknown case ID")
            if args.command == "show":
                result = {"case": state, "timeline": store.history(args.case)}
            elif args.command == "triage":
                result = transition(store, args.case, "TRIAGED", args.analyst, now(), read(args.cloudtrail))
            elif args.command == "remediate":
                result = transition(store, args.case, "REMEDIATED", args.analyst, now(), args.decision)
            else:
                if bool(args.table) == bool(args.evidence):
                    parser.error("Use --evidence for local closure. AWS closure reads the bucket directly.")
                evidence = live_evidence(state) if args.table else read(args.evidence)
                result = transition(store, args.case, "CLOSED", args.analyst, now(), evidence)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
