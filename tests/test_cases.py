from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.cases import BLOCK_FLAGS, ingest, transition
from app.storage import LocalStore
from incident import ROOT, demo, read


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.store = LocalStore(":memory:")
        self.addCleanup(self.store.db.close)
        self.event = read(ROOT / "fixtures/finding.json")
        self.trail = read(ROOT / "fixtures/cloudtrail.json")
        self.proof = read(ROOT / "fixtures/verification.json")
        self.key = ingest(self.store, self.event)["id"]

    def advance(self, status, minute, evidence):
        return transition(self.store, self.key, status, "analyst", f"2026-11-01T10:{minute}:00Z", evidence)

    def mitigated(self):
        self.advance("TRIAGED", "05", self.trail)
        self.advance("REMEDIATED", "12", "Restored the approved policy in the exercise")

    def test_demo(self):
        result = demo()
        self.assertEqual(result["cases"], 1)
        self.assertEqual([e["status"] for e in result["timeline"]], ["OPEN", "TRIAGED", "REMEDIATED", "CLOSED"])

    def test_replay_even_with_new_envelope_id(self):
        self.event["id"] = "new-delivery-id"
        self.assertEqual(ingest(self.store, self.event)["revision"], 1)
        self.assertEqual(len(self.store.history(self.key)), 1)

    def test_out_of_order_update(self):
        self.event["detail"]["updatedAt"] = "2026-11-01T10:00:30Z"
        self.assertEqual(ingest(self.store, self.event)["revision"], 1)

    def test_separate_finding_ids(self):
        detail = self.event["detail"]
        detail["arn"] = detail["arn"].replace(detail["id"], "second")
        detail["id"] = "second"
        self.assertNotEqual(ingest(self.store, self.event)["id"], self.key)

    def test_no_skipping_states(self):
        with self.assertRaises(ValueError):
            self.advance("CLOSED", "15", self.proof)

    def test_triage_requires_matching_trail(self):
        for field, value in (("awsRegion", "us-west-2"), ("recipientAccountId", "000000000000"),
                             ("eventTime", "2025-01-01T10:00:00Z"), ("errorCode", "AccessDenied"),
                             ("requestParameters", {"bucketName": "other-bucket"})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.advance("TRIAGED", "05", {**self.trail, field: value})
        self.assertEqual(len(self.store.history(self.key)), 1)

    def test_close_checks_each_block_setting(self):
        self.mitigated()
        for flag in BLOCK_FLAGS:
            proof = deepcopy(self.proof)
            proof["PublicAccessBlockConfiguration"][flag] = False
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.advance("CLOSED", "15", proof)
        self.assertEqual(len(self.store.history(self.key)), 3)

    def test_close_checks_policy_identity_and_freshness(self):
        self.mitigated()
        for field, value in (("PolicyStatus", {"IsPublic": True}), ("bucket", "different"),
                             ("account", "000000000000"), ("observedAt", "2026-11-01T10:11:00Z"),
                             ("observedAt", "2026-11-01T10:16:00Z")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.advance("CLOSED", "15", {**self.proof, field: value})
        with self.assertRaises(ValueError):
            self.advance("CLOSED", "25", self.proof)
        self.assertEqual(self.store.get(self.key)["status"], "REMEDIATED")

    def test_metadata_refresh_and_recurrence(self):
        self.mitigated()
        self.advance("CLOSED", "15", self.proof)
        self.event["detail"]["updatedAt"] = "2026-11-01T10:17:00Z"
        self.assertEqual(ingest(self.store, self.event)["status"], "CLOSED")
        self.event["detail"]["updatedAt"] = "2026-11-01T10:19:00Z"
        self.event["detail"]["service"]["eventLastSeen"] = "2026-11-01T10:18:00Z"
        state = ingest(self.store, self.event)
        self.assertEqual(state["status"], "OPEN")
        self.assertNotIn("verification", state)
        self.assertEqual(self.store.history(self.key)[3]["verification"], self.proof)
        self.assertEqual(self.store.history(self.key)[-1]["revision"], 6)

    def test_concurrent_duplicate_deliveries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "cases.sqlite3"
            LocalStore(path).db.close()

            def deliver(_):
                store = LocalStore(path)
                try:
                    return ingest(store, self.event)["revision"]
                finally:
                    store.db.close()

            with ThreadPoolExecutor(max_workers=4) as workers:
                self.assertEqual(list(workers.map(deliver, range(12))), [1] * 12)
            reopened = LocalStore(path)
            try:
                self.assertEqual(len(reopened.history(self.key)), 1)
            finally:
                reopened.db.close()
