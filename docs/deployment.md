# Deploy to AWS

Use a sandbox account with GuardDuty enabled, an existing **private artifact bucket in the same region**, and an AWS CLI profile. The stack provisions a Lambda, EventBridge rule, on-demand DynamoDB table, log group, SQS failure queue, execution role, and invocation permissions. AWS services can incur charges. Keep the stack and any case data in the sandbox.

Example PowerShell commands, with your own bucket and profile:

```powershell
$env:AWS_PROFILE = "your-sandbox-profile"
$env:AWS_DEFAULT_REGION = "us-east-1"
$artifactBucket = "your-existing-artifact-bucket"
$artifactKey = python package_lambda.py
aws s3 cp build/handler.zip "s3://$artifactBucket/$artifactKey"
aws cloudformation deploy --stack-name guardduty-case-lab --template-file template.yaml --capabilities CAPABILITY_IAM --parameter-overrides "ArtifactBucket=$artifactBucket" "ArtifactKey=$artifactKey"
aws cloudformation describe-stacks --stack-name guardduty-case-lab --query "Stacks[0].Outputs"
```

Generate the single sample finding in a GuardDuty-enabled region using the documented sample-finding API, then inspect the case using its finding ARN and the stack's `CaseTable` output. AWS-generated samples use placeholder resources. Use the offline fixtures to demonstrate closure, or use the read-only verifier on an actual case for a sandbox bucket you control.

```powershell
aws guardduty create-sample-findings --detector-id YOUR_DETECTOR_ID --finding-types Policy:S3/BucketPublicAccessGranted
python incident.py --table TABLE_NAME show FINDING_ARN
python incident.py --table TABLE_NAME triage FINDING_ARN --analyst ANALYST --cloudtrail decoded-event.json
python incident.py --table TABLE_NAME remediate FINDING_ARN --analyst ANALYST --decision "Recorded change reference and mitigation applied"
python incident.py --table TABLE_NAME close FINDING_ARN --analyst REVIEWER
```

The AWS CLI operator needs `boto3` installed for the Python commands. The analyst needs scoped DynamoDB `GetItem`, `Query`, and `PutItem` permissions on the case table and `s3:GetBucketPublicAccessBlock` and `s3:GetBucketPolicyStatus` on the affected bucket. The operator supplies a decoded CloudTrail event object. Keep case exports private. Cloud closure reads S3 directly and rejects fixture input.

**Delivery failures.** EventBridge delivery errors and exhausted Lambda processing retries go to the stack's failure queue. EventBridge carries the original event in its message. Lambda asynchronous failures wrap it in `requestPayload`. Inspect the failure reason, correct it, extract the original event, and retry the ingestion Lambda under an authorized operator identity. Duplicate retries are safe. Queue retention is 14 days.

**Cleanup.** In a disposable sandbox, export any needed case history before deleting the stack. Stack deletion removes the case table, logs, and failure queue. The uploaded zip in the pre-existing artifact bucket has its own lifecycle.

## References

- [GuardDuty findings and EventBridge delivery](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html)
- [GuardDuty S3 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- [Generate GuardDuty sample findings](https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html)
- [S3 policy-status verification](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html)
