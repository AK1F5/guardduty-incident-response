import os

from app.cases import ingest
from app.storage import DynamoStore


def handle(event, context):
    state = ingest(DynamoStore(os.environ["CASE_TABLE"]), event)
    return {"case": state["id"], "revision": state["revision"], "status": state["status"]}
