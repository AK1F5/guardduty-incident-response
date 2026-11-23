# GuardDuty S3 incident response

A Python tool for investigating S3 buckets flagged for public access. It groups repeat GuardDuty alerts into one case and keeps a timeline of the CloudTrail event, the analyst's decision, and the S3 settings used to close it.

## Try it locally

With Python 3.10 or newer, run:

```sh
python incident.py demo
```

The demo uses SQLite and sample AWS events. It runs offline with the Python standard library. Look for `"deliveries": 2`, `"cases": 1`, and a final status of `CLOSED`. The [sample incident report](docs/incident-report.md) walks through the same case.

## When can a case close?

Recording the fix is one step. Closing the case requires a separate check of the affected bucket: all four S3 Block Public Access settings must be on, and the bucket policy must be nonpublic. The check must be newer than the fix and no more than five minutes old. If GuardDuty sees the issue again after remediation, the case reopens with its earlier history intact.

## Running on AWS

EventBridge sends matching GuardDuty findings to Lambda. Lambda writes the case and its history to DynamoDB in one transaction. The analyst runs the S3 verification with separate credentials. See the [deployment guide](docs/deployment.md) for the CloudFormation setup.

Run `python -m unittest discover -s tests -v` to check the workflow. Install `boto3` to include the two AWS SDK tests.
