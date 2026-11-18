"""Wormhole rendezvous mailbox.

Runs as an AWS Lambda function (function URL + DynamoDB), or locally for testing:

    python3 mailbox.py --serve 8080        # in-memory store, http://127.0.0.1:8080/

The mailbox only stores, for a few minutes, what each peer posts under a numeric nameplate: its
candidate IP:port addresses and, for browser senders, a WebRTC offer/answer (SDP). It never sees
the secret code words nor any file data.

API (POST JSON):
  {"op":"claim","np":"42","data":"..."}         receiver opens nameplate 42 (409 if taken)
  {"op":"put","np":"42","side":"s","data":"..."} sender posts its addresses (404 if not open)
  {"op":"get","np":"42"}                         -> {"r": "...", "s": "..."} (404 if not open)
  {"op":"release","np":"42"}                     close the nameplate
"""
import base64
import json
import os
import re
import threading
import time

TABLE = os.environ.get("TABLE", "wormhole-mailbox")
TTL_SECONDS = int(os.environ.get("TTL_SECONDS", "1800"))
MAX_DATA = 16384  # room for a WebRTC offer/answer (SDP) next to the addresses
NP_RE = re.compile(r"^[1-9][0-9]{0,5}$")


class HttpError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


class MemoryStore:
    def __init__(self):
        self.items = {}
        self.lock = threading.Lock()

    def claim(self, np, data, now):
        with self.lock:
            it = self.items.get(np)
            if it and it["ttl"] >= now:
                return False
            self.items[np] = {"r": data, "ttl": now + TTL_SECONDS}
            return True

    def put(self, np, side, data, now):
        with self.lock:
            it = self.items.get(np)
            if not it or it["ttl"] < now:
                return False
            it[side] = data
            return True

    def get(self, np, now):
        with self.lock:
            it = self.items.get(np)
            if not it or it["ttl"] < now:
                return None
            return dict(it)

    def release(self, np):
        with self.lock:
            self.items.pop(np, None)


class DynamoStore:
    def __init__(self):
        import boto3

        self.ddb = boto3.client("dynamodb")
        self.cfe = self.ddb.exceptions.ConditionalCheckFailedException

    def claim(self, np, data, now):
        try:
            self.ddb.put_item(
                TableName=TABLE,
                Item={"np": {"S": np}, "r": {"S": data}, "ttl": {"N": str(now + TTL_SECONDS)}},
                ConditionExpression="attribute_not_exists(np) OR #t < :now",
                ExpressionAttributeNames={"#t": "ttl"},
                ExpressionAttributeValues={":now": {"N": str(now)}},
            )
            return True
        except self.cfe:
            return False

    def put(self, np, side, data, now):
        try:
            self.ddb.update_item(
                TableName=TABLE,
                Key={"np": {"S": np}},
                UpdateExpression="SET #s = :d",
                ConditionExpression="attribute_exists(np) AND #t >= :now",
                ExpressionAttributeNames={"#s": side, "#t": "ttl"},
                ExpressionAttributeValues={":d": {"S": data}, ":now": {"N": str(now)}},
            )
            return True
        except self.cfe:
            return False

    def get(self, np, now):
        it = self.ddb.get_item(TableName=TABLE, Key={"np": {"S": np}}).get("Item")
        if not it or int(it["ttl"]["N"]) < now:
            return None
        return {k: v["S"] for k, v in it.items() if k in ("r", "s")}

    def release(self, np):
        self.ddb.delete_item(TableName=TABLE, Key={"np": {"S": np}})


def handle(req, store):
    if not isinstance(req, dict):
        raise HttpError(400, "bad request")
    op = req.get("op")
    np = str(req.get("np", ""))
    if op == "ping":
        return {"ok": True}
    if not NP_RE.match(np):
        raise HttpError(400, "bad nameplate")
    now = int(time.time())
    if op in ("claim", "put"):
        data = req.get("data")
        if not isinstance(data, str) or len(data) > MAX_DATA:
            raise HttpError(400, "bad data")
    if op == "claim":
        if not store.claim(np, data, now):
            raise HttpError(409, "taken")
        return {"ok": True}
    if op == "put":
        if req.get("side") != "s":
            raise HttpError(400, "bad side")
        if not store.put(np, "s", data, now):
            raise HttpError(404, "not found")
        return {"ok": True}
    if op == "get":
        it = store.get(np, now)
        if it is None:
            raise HttpError(404, "not found")
        return {k: it[k] for k in ("r", "s") if k in it}
    if op == "release":
        store.release(np)
        return {"ok": True}
    raise HttpError(400, "bad op")


_store = None


def _respond(status, body):
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}


def handler(event, context):
    """AWS Lambda entry point (function URL, payload format 2.0)."""
    global _store
    if _store is None:
        _store = DynamoStore()
    if event.get("requestContext", {}).get("http", {}).get("method") != "POST":
        return _respond(405, {"error": "POST only"})
    body = event.get("body") or ""
    if len(body) > 65536:
        return _respond(413, {"error": "too large"})
    try:
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode()
        return _respond(200, handle(json.loads(body), _store))
    except HttpError as e:
        return _respond(e.status, {"error": str(e)})
    except (ValueError, UnicodeDecodeError):
        return _respond(400, {"error": "bad json"})


def serve(port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    store = MemoryStore()

    class H(BaseHTTPRequestHandler):
        def cors(self):
            self.send_header("access-control-allow-origin", "*")
            self.send_header("access-control-allow-methods", "POST")
            self.send_header("access-control-allow-headers", "content-type")

        def do_OPTIONS(self):
            self.send_response(204)
            self.cors()
            self.end_headers()

        def do_POST(self):
            n = int(self.headers.get("content-length", "0"))
            try:
                status, body = 200, handle(json.loads(self.rfile.read(n)), store)
            except HttpError as e:
                status, body = e.status, {"error": str(e)}
            except ValueError:
                status, body = 400, {"error": "bad json"}
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.cors()
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt, *args):
            if os.environ.get("MAILBOX_LOG"):
                super().log_message(fmt, *args)

    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve(int(sys.argv[2]))
    else:
        print(__doc__)
