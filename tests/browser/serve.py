"""HTTPS test server: serves web/public and the mailbox API (in-memory) on one origin.
Modern Chromium refuses plain-HTTP pages, so the browser uses TLS with a throwaway cert; the CLI
(which verifies certificates) talks to the same in-memory mailbox over a second, plain-HTTP port.
Usage: python3 serve.py TLS_PORT PLAIN_PORT ROOT CERT KEY"""
import json, os, ssl, sys, threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../aws"))
import mailbox  # noqa: E402

tls_port, plain_port, root, cert, key = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
store = mailbox.MemoryStore()


class H(SimpleHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", "0"))
        try:
            status, body = 200, mailbox.handle(json.loads(self.rfile.read(n)), store)
        except mailbox.HttpError as e:
            status, body = e.status, {"error": str(e)}
        except ValueError:
            status, body = 400, {"error": "bad json"}
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


plain = ThreadingHTTPServer(("0.0.0.0", plain_port), partial(H, directory=root))
threading.Thread(target=plain.serve_forever, daemon=True).start()
srv = ThreadingHTTPServer(("0.0.0.0", tls_port), partial(H, directory=root))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
