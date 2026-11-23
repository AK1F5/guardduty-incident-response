import unittest
from unittest.mock import patch

from app.handler import handle
from app.storage import DynamoStore
from incident import ROOT, live_evidence, read

try:
    import boto3
    from botocore.stub import ANY, Stubber
except ImportError:
    boto3 = None


@unittest.skipUnless(boto3, "Install boto3 to run AWS SDK contract tests")
class AwsContractTests(unittest.TestCase):
    def client(self, service):
        return boto3.client(service, region_name="us-east-1", aws_access_key_id="offline",
                            aws_secret_access_key="offline")

    def test_lambda_creates_head_and_journal_in_one_transaction(self):
        event = read(ROOT / "fixtures/finding.json")
        case = event["detail"]["arn"]
        client = self.client("dynamodb")
        store = DynamoStore("LabCases", client)
        with Stubber(client) as stub, patch("app.handler.DynamoStore", return_value=store), patch.dict("os.environ", CASE_TABLE="LabCases"):
            stub.add_response("get_item", {}, {"TableName": "LabCases", "Key": store.key(case, "HEAD"), "ConsistentRead": True})
            stub.add_response("transact_write_items", {}, {"TransactItems": [
                {"Put": {"TableName": "LabCases", "Item": {**store.key(case, "HEAD"), "revision": {"N": "1"}, "body": {"S": ANY}},
                         "ConditionExpression": "attribute_not_exists(caseId)"}},
                {"Put": {"TableName": "LabCases", "Item": {**store.key(case, "REV#000000000001"), "body": {"S": ANY}},
                         "ConditionExpression": "attribute_not_exists(caseId)"}}
            ]})
            self.assertEqual(handle(event, None), {"case": case, "status": "OPEN", "revision": 1})
            stub.assert_no_pending_responses()

    def test_live_verifier_checks_bucket_owner_on_both_reads(self):
        client = self.client("s3")
        proof = read(ROOT / "fixtures/verification.json")
        target = {"Bucket": proof["bucket"], "ExpectedBucketOwner": proof["account"]}
        with Stubber(client) as stub, patch("boto3.client", return_value=client):
            stub.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": proof["PublicAccessBlockConfiguration"]}, target)
            stub.add_response("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": False}}, target)
            observed = live_evidence({**proof, "region": "us-east-1"})
            self.assertFalse(observed["PolicyStatus"]["IsPublic"])
            stub.assert_no_pending_responses()
