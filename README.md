# mongobrute

MongoDB user enumeration tool. Unauthenticated attackers can determine whether a given user exists on a MongoDB instance through two independent vectors.

> **Disclaimer:** This tool is for educational and authorized security testing purposes only. You must have explicit permission to test any MongoDB instance you target. Misuse of this tool may violate applicable laws. The authors are not responsible for any unauthorized or illegal use.

## Vectors

Both commands declare `requiresAuth: false`, so they work without any prior authentication.

**Important condition:** Both vectors require **authentication to be enabled** on the target server. If auth is disabled (`--noauth`), the server has no user database and no authentication mechanisms registered — neither vector returns useful results.

### `authenticate` command

The legacy `authenticate` command handler in `authentication_commands.cpp` rethrows `ErrorCodes::UserNotFound` directly to the client. The SASL paths (`saslStart`/`saslContinue`) properly mask this, but the `authenticate` codepath does not.

- User exists → `"Authentication failed."`
- User does not exist → `"UserNotFound: Could not find user <username> for db <dbname>"`

**Affects:** All versions from 3.6 to current (8.0). The leak path changed across versions but was never fixed — in 3.6–4.4 all non-auth errors propagate, in 5.0–6.0 there's no catch block at all, and in 7.0+ `UserNotFound` is explicitly rethrown.

**Note:** The `authenticate` command uses a `mechanism` field. If the server doesn't support the requested mechanism (e.g., SCRAM-SHA-256 on older builds), the command fails with a mechanism error and the user's existence cannot be determined via this vector.

### `saslSupportedMechs` in `hello`

Available since MongoDB 4.2. When `saslSupportedMechs: "db.username"` is included in a `hello` command, the server returns the user's supported SASL mechanisms only if the user exists. If the user doesn't exist, the field is absent.

- User exists → `saslSupportedMechs: ["SCRAM-SHA-256", "SCRAM-SHA-1"]`
- User does not exist → field absent from response

**Note:** Some proxies, mongos routers, or non-standard MongoDB implementations may not forward or include `saslSupportedMechs` in the response, making this vector unavailable.

On [HackerOne](https://hackerone.com/mongodb). Both vectors fall under MongoDB's explicitly stated out-of-scope items:

> Rate limiting or bruteforce issues on non-authentication endpoints  
> SCRAM-SHA1 authentication mechanism's login credentials disclosure

User enumeration via authentication responses is also covered by their accepted-risk stance on informational disclosures.

## Checking the Server Version

The `buildInfo` command is accessible without authentication and reliably returns the version:

```javascript
{ buildInfo: 1 }
```

The `hello` response may also include a `version` field on some configurations.

## References

- [`authentication_commands.cpp:132-145`](https://github.com/mongodb/mongo/blob/master/src/mongo/db/commands/authentication_commands.cpp) — `UserNotFound` rethrow
- [`sasl_commands.cpp:79-100`](https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/sasl_commands.cpp) — SASL path masks it correctly (for comparison)
- [`sasl_scram_server_conversation.cpp`](https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/sasl_scram_server_conversation.cpp) — where `UserNotFound` originates from `acquireUser()`
- [MongoDB Bug Bounty Program](https://www.mongodb.com/security-disclosure)
- [HackerOne: MongoDB](https://hackerone.com/mongodb)

## Usage

Zero dependencies — pure Python standard library.

```bash
python mongobrute.py -t 10.0.0.1:27017 -w usernames.txt
python mongobrute.py -t cluster.mongodb.net -w usernames.txt -T 32 --tls
python mongobrute.py -t 10.0.0.1 -w users.txt -o results.json
```

| Flag | Description |
|------|-------------|
| `-t`, `--target` | MongoDB host[:port] |
| `-w`, `--wordlist` | Username wordlist |
| `-d`, `--db` | Auth database (default: admin) |
| `-T`, `--threads` | Threads (default: 16) |
| `--timeout` | Seconds (default: 5) |
| `--tls` | Use TLS |
| `-q`, `--quiet` | Only output found usernames (or "couldn't find any usernames") |
| `-o`, `--output` | Save results as JSON |

