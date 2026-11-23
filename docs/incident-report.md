# S3 public access incident

**Bucket:** `example-casefiles-lab`, us-east-1  
**Finding:** `Policy:S3/BucketPublicAccessGranted`  
**Outcome:** Closed after the bucket's public access settings were verified.

This is the synthetic case from `python incident.py demo`. All times are UTC on November 1, 2026.

| Time | What happened |
| --- | --- |
| 10:00 | CloudTrail recorded a successful `PutBucketPolicy` call from the example release role. The bucket, account, region, and time matched the GuardDuty finding. |
| 10:01 | The alert opened a case. A second delivery of the same finding left that case unchanged. |
| 10:05 | The analyst linked CloudTrail event `00000000-0000-4000-8000-000000000002` to the case. |
| 10:12 | The analyst recorded the fix: restore the approved bucket policy and enable all four Block Public Access settings. |
| 10:14 | The sample verification showed all four settings enabled and `IsPublic: false` for the affected bucket. |
| 10:15 | The reviewer closed the case using the 10:14 readings. The journal retained the evidence. |

The evidence supports closing the public access finding. Whether anyone read an object during the exposure window remains unknown. The next records to check would be S3 object-level CloudTrail events or access logs from that period, if available.
