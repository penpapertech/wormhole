"""Tiny STUN binding server for tests: python3 stun_server.py 3478 3479 ..."""
import selectors, socket, struct, sys

MAGIC = 0x2112A442
sel = selectors.DefaultSelector()
for p in sys.argv[1:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", int(p)))
    sel.register(s, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        s = key.fileobj
        data, (ip, port) = s.recvfrom(2048)
        if len(data) < 20 or struct.unpack("!HHI", data[:8])[0] != 1:
            continue
        txid = data[8:20]
        ipn = struct.unpack("!I", socket.inet_aton(ip))[0] ^ MAGIC
        attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, port ^ (MAGIC >> 16), ipn)
        s.sendto(struct.pack("!HHI", 0x0101, len(attr), MAGIC) + txid + attr, (ip, port))
