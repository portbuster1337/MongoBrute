#!/usr/bin/env python3
"""
mongobrute - MongoDB User Enumeration Tool
Pure Python, no dependencies. Uses the MongoDB wire protocol directly.
"""

import argparse
import sys
import socket
import struct
import concurrent.futures
import json


VERSION = "1.0.0"
BANNER = f"""
  __  ___           _                        _
 /  |/  /__  ___ __(_)__  ___ _  _  ___ _  _| |_ ___ _ _
 / /|_/ / _ \\/ _ `/ / _ \\/ _ \\ || |/ _ \\ || |  _/ _ \\ '_|
/_/  /_/\\___/\\__, /_\\___/\\___/\\_,_/\\___/\\_,_|\\__\\___/_|
            /____/  v{VERSION}
MongoDB User Enumeration Tool
"""


def _bson_encode(doc):
    """Minimal BSON encoder. Only handles types needed for our commands."""
    buf = bytearray()
    _bson_append_document(buf, doc)
    return bytes(buf)


def _bson_append_element(buf, name, value):
    if value is None:
        buf.extend(b'\x0a')
        _bson_append_cstring(buf, name)
    elif isinstance(value, int):
        buf.extend(b'\x10')
        _bson_append_cstring(buf, name)
        buf.extend(struct.pack('<i', value))
    elif isinstance(value, str):
        buf.extend(b'\x02')
        _bson_append_cstring(buf, name)
        encoded = value.encode('utf-8')
        buf.extend(struct.pack('<i', len(encoded) + 1))
        buf.extend(encoded)
        buf.extend(b'\x00')
    elif isinstance(value, bytes):
        buf.extend(b'\x05')
        _bson_append_cstring(buf, name)
        buf.extend(struct.pack('<i', len(value)))
        buf.extend(value)
    elif isinstance(value, dict):
        buf.extend(b'\x03')
        _bson_append_cstring(buf, name)
        _bson_append_document(buf, value)
    elif isinstance(value, list):
        buf.extend(b'\x04')
        _bson_append_cstring(buf, name)
        _bson_append_document(buf, {str(i): v for i, v in enumerate(value)})
    elif isinstance(value, bool):
        buf.extend(b'\x08')
        _bson_append_cstring(buf, name)
        buf.extend(b'\x01' if value else b'\x00')
    elif isinstance(value, float):
        buf.extend(b'\x01')
        _bson_append_cstring(buf, name)
        buf.extend(struct.pack('<d', value))
    else:
        raise ValueError(f"Unsupported BSON type: {type(value)}")


def _bson_append_cstring(buf, s):
    buf.extend(s.encode('utf-8'))
    buf.extend(b'\x00')


def _bson_append_document(buf, doc):
    start = len(buf)
    buf.extend(b'\x00' * 4)
    for key, value in doc.items():
        _bson_append_element(buf, key, value)
    buf.extend(b'\x00')
    struct.pack_into('<i', buf, start, len(buf) - start)


def _bson_parse(data):
    """Minimal BSON decoder. Returns the first document."""
    view = memoryview(data)
    return _bson_decode_document(view, 0)[0]


def _bson_decode_cstring(view, pos):
    end = view.tobytes().find(b'\x00', pos)
    return view[pos:end].tobytes().decode('utf-8'), end + 1


def _bson_decode_document(view, pos):
    size = struct.unpack_from('<i', view, pos)[0]
    end = pos + size
    pos += 4
    doc = {}
    while pos < end - 1:
        elem_type = view[pos]
        pos += 1
        name, pos = _bson_decode_cstring(view, pos)
        if elem_type == 0x01:
            val = struct.unpack_from('<d', view, pos)[0]; pos += 8
        elif elem_type == 0x02:
            slen = struct.unpack_from('<i', view, pos)[0]; pos += 4
            val = view[pos:pos+slen-1].tobytes().decode('utf-8'); pos += slen
        elif elem_type == 0x03:
            val, pos = _bson_decode_document(view, pos)
        elif elem_type == 0x04:
            arr, pos = _bson_decode_document(view, pos)
            val = [arr[k] for k in sorted(arr, key=lambda x: int(x))]
        elif elem_type == 0x05:
            slen = struct.unpack_from('<i', view, pos)[0]; pos += 4
            val = bytes(view[pos:pos+slen]); pos += slen + 5
        elif elem_type == 0x08:
            val = view[pos] == 1; pos += 1
        elif elem_type == 0x0a:
            val = None
        elif elem_type == 0x10:
            val = struct.unpack_from('<i', view, pos)[0]; pos += 4
        elif elem_type == 0x12:
            val = struct.unpack_from('<q', view, pos)[0]; pos += 8
        else:
            raise ValueError(f"Unknown BSON type: 0x{elem_type:02x}")
        doc[name] = val
    return doc, end


def _make_op_msg(flags, sections, request_id=1):
    """Build an OP_MSG wire protocol message."""
    body = bytearray()
    body.extend(struct.pack('<i', flags))
    for kind, data in sections:
        body.extend(bytes([kind]))
        if kind == 0:
            body.extend(data)
        elif kind == 1:
            body.extend(struct.pack('<i', len(data) + 4))
            body.extend(data)
    msg = bytearray()
    msg.extend(b'\x00' * 4)
    msg.extend(struct.pack('<ii', request_id, 0))
    msg.extend(struct.pack('<i', 2013))
    msg.extend(body)
    struct.pack_into('<i', msg, 0, len(msg))
    return bytes(msg)


def _send_recv(sock, data):
    sock.sendall(data)
    raw = b''
    while len(raw) < 4:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        raw += chunk
    length = struct.unpack_from('<i', raw, 0)[0]
    while len(raw) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        raw += chunk
    return raw


def _connect(host, port, tls, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock)
    return sock


def _db_cmd(sock, db, cmd, request_id=1):
    bson = _bson_encode({**cmd, "$db": db})
    msg = _make_op_msg(0, [(0, bson)], request_id)
    resp = _send_recv(sock, msg)
    return _bson_parse(resp[20:])


def hello(sock, db_user=None):
    cmd = {"hello": 1}
    if db_user:
        cmd["saslSupportedMechs"] = db_user
    return _db_cmd(sock, "admin", cmd)


def authenticate(sock, db, user):
    cmd = {"authenticate": 1, "user": user, "mechanism": "SCRAM-SHA-256", "db": db}
    return _db_cmd(sock, db, cmd)


def user_exists(host, port, tls, timeout, username, db):
    try:
        sock = _connect(host, port, tls, timeout)
    except Exception:
        return None

    try:
        h = hello(sock, f"{db}.{username}")
        if "saslSupportedMechs" in h and h["saslSupportedMechs"]:
            sock.close()
            return True

        try:
            authenticate(sock, db, username)
            sock.close()
            return True
        except Exception as e:
            msg = str(e)
            if "UserNotFound" in msg:
                sock.close()
                return False
            sock.close()
            return True
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


def main():
    parser = argparse.ArgumentParser(description="MongoDB User Enumeration Tool")
    parser.add_argument("-t", "--target", required=True, help="MongoDB host[:port]")
    parser.add_argument("-w", "--wordlist", required=True, help="Username wordlist file")
    parser.add_argument("-d", "--db", default="admin", help="Auth database (default: admin)")
    parser.add_argument("-T", "--threads", type=int, default=16, help="Threads (default: 16)")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout in seconds (default: 5)")
    parser.add_argument("--tls", action="store_true", help="Use TLS")
    parser.add_argument("-o", "--output", help="Save results as JSON")

    args = parser.parse_args()
    print(BANNER)

    host, _, port_str = args.target.partition(":")
    port = int(port_str) if port_str else 27017

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            usernames = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {args.wordlist}")
        sys.exit(1)

    if not usernames:
        print("[-] Wordlist is empty")
        sys.exit(1)

    print(f"[*] Target:   {host}:{port}")
    print(f"[*] DB:       {args.db}")
    print(f"[*] Wordlist: {args.wordlist} ({len(usernames)} entries)")
    print(f"[*] Threads:  {args.threads}")
    print()

    found = []
    total = len(usernames)
    done = 0

    def progress():
        nonlocal done
        done += 1
        if done % 10 == 0 or done == total:
            print(f"\r[*] Progress: {done}/{total} ({done*100//total}%)", end="", file=sys.stderr)
            sys.stderr.flush()

    def work(username):
        result = user_exists(host, port, args.tls, args.timeout, username, args.db)
        progress()
        return username, result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        fs = {ex.submit(work, u): u for u in usernames}
        for f in concurrent.futures.as_completed(fs):
            try:
                username, exists = f.result()
                if exists:
                    found.append(username)
                    print(f"\r{' ' * 60}\r  [+] {username} (EXISTS)")
            except Exception:
                pass

    print(f"\r{' ' * 60}\r")

    if found:
        print(f"[+] Found {len(found)} user(s):")
        for u in found:
            print(f"    {u}")
    else:
        print("[-] No users found")

    if args.output and found:
        with open(args.output, "w") as f:
            json.dump({"target": f"{host}:{port}", "db": args.db, "users": found}, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
