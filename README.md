# GuardDuty S3 incident response

A Python tool for investigating S3 buckets flagged for public access. It groups repeat GuardDuty alerts into one case and keeps a timeline of the CloudTrail event, the analyst's decision, and the S3 settings used to close it.

## Try it locally

With Python 3.10 or newer, run:

```sh
python incident.py demo
```

The demo uses SQLite and sample AWS events. It runs offline with the Python standard library. Look for `"deliveries": 2`, `"cases": 1`, and a final status of `CLOSED`. The [sample incident report](docs/incident-report.md) walks through the same case.

## When can a case close?

The analyst records the fix, then checks the affected bucket. All four S3 Block Public Access settings must be on and the bucket policy must be nonpublic. The reading must come from the time of the fix or later and be at most five minutes old when the reviewer closes the case.

A delayed copy of the original alert leaves the case closed. If GuardDuty reports fresh activity after the fix, the case reopens and keeps its earlier history.

## Running on AWS

EventBridge sends matching GuardDuty findings to Lambda. Lambda writes the case and its history to DynamoDB in one transaction. The analyst runs the S3 verification with separate credentials. See the [deployment guide](docs/deployment.md) for the CloudFormation setup.

Run `python -m unittest discover -s tests -v` to check the workflow. Install `boto3` to include the two AWS SDK tests.
