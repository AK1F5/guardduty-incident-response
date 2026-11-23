import json
import sqlite3


def change(store, key, decide):
    for _ in range(8):
        previous = store.get(key)
        decision = decide(previous)
        if decision is None:
            return previous
        state, note, actor, when = decision
        revision = (previous or {}).get("revision", 0) + 1
        state["revision"] = revision
        entry = {"revision": revision, "status": state["status"], "at": when, "actor": actor, "note": note}
        previous_status = (previous or {}).get("status")
        if state["status"] == "TRIAGED" and previous_status != "TRIAGED":
            entry["cloudtrail_event"] = state["cloudtrail_event"]
        if state["status"] == "CLOSED" and previous_status != "CLOSED":
            entry["verification"] = state["verification"]
        if store.commit(key, revision, state, entry):
            return state
    raise RuntimeError("Concurrent updates prevented a commit. Retry the operation.")


class LocalStore:
    change = change

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS records (id TEXT, rev INTEGER, body TEXT, PRIMARY KEY(id, rev))")

    def get(self, key):
        row = self.db.execute("SELECT body FROM records WHERE id=? AND rev=0", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def commit(self, key, rev, state, entry):
        try:
            with self.db:
                self.db.execute("INSERT INTO records VALUES (?, ?, ?)", (key, rev, json.dumps(entry)))
                self.db.execute("INSERT OR REPLACE INTO records VALUES (?, 0, ?)", (key, json.dumps(state)))
        except sqlite3.IntegrityError:
            return False
        return True

    def history(self, key):
        rows = self.db.execute("SELECT body FROM records WHERE id=? AND rev>0 ORDER BY rev", (key,))
        return [json.loads(row[0]) for row in rows]


class DynamoStore:
    change = change

    def __init__(self, table, client=None):
        if client is None:
            import boto3
            client = boto3.client("dynamodb")
        self.table = table
        self.client = client

    @staticmethod
    def key(case, row):
        return {"caseId": {"S": case}, "rowId": {"S": row}}

    def get(self, key):
        item = self.client.get_item(TableName=self.table, Key=self.key(key, "HEAD"), ConsistentRead=True).get("Item")
        return json.loads(item["body"]["S"]) if item else None

    def commit(self, key, rev, state, entry):
        head = {**self.key(key, "HEAD"), "revision": {"N": str(rev)}, "body": {"S": json.dumps(state)}}
        write = {"TableName": self.table, "Item": head, "ConditionExpression": "attribute_not_exists(caseId)"}
        if rev > 1:
            write.update(ConditionExpression="#rev = :previous", ExpressionAttributeNames={"#rev": "revision"},
                         ExpressionAttributeValues={":previous": {"N": str(rev - 1)}})
        audit = {**self.key(key, f"REV#{rev:012d}"), "body": {"S": json.dumps(entry)}}
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": write}, {"Put": {"TableName": self.table, "Item": audit, "ConditionExpression": "attribute_not_exists(caseId)"}}
            ])
        except self.client.exceptions.TransactionCanceledException as error:
            codes = [reason.get("Code") for reason in error.response.get("CancellationReasons", [])]
            if any(code in ("ConditionalCheckFailed", "TransactionConflict") for code in codes):
                return False
            raise
        return True

    def history(self, key):
        args = {"TableName": self.table, "ConsistentRead": True,
                "KeyConditionExpression": "caseId = :id AND begins_with(rowId, :prefix)",
                "ExpressionAttributeValues": {":id": {"S": key}, ":prefix": {"S": "REV#"}}}
        entries = []
        while True:
            page = self.client.query(**args)
            entries.extend(json.loads(item["body"]["S"]) for item in page["Items"])
            if "LastEvaluatedKey" not in page:
                return entries
            args["ExclusiveStartKey"] = page["LastEvaluatedKey"]
