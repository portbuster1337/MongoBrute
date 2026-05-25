# mongobrute

MongoDB user enumeration tool. Unauthenticated attackers can determine whether a given user exists on a MongoDB instance through two independent vectors.

## Vectors

### `authenticate` command

The legacy `authenticate` command handler in `authentication_commands.cpp` rethrows `ErrorCodes::UserNotFound` directly to the client. The SASL paths (`saslStart`/`saslContinue`) properly mask this, but the `authenticate` codepath does not.

- User exists → `"Authentication failed."`
- User does not exist → `"UserNotFound: Could not find user <username> for db <dbname>"`

### `saslSupportedMechs` in `hello`

When `saslSupportedMechs: "db.username"` is included in a `hello` command, the server returns the user's supported SASL mechanisms only if the user exists. If the user doesn't exist, the field is absent.

- User exists → `saslSupportedMechs: ["SCRAM-SHA-256", "SCRAM-SHA-1"]`
- User does not exist → field absent from response

## Bug Bounty Status

Submitted via [HackerOne](https://hackerone.com/mongodb). Both vectors fall under MongoDB's explicitly stated out-of-scope items:

> Rate limiting or bruteforce issues on non-authentication endpoints  
> SCRAM-SHA1 authentication mechanism's login credentials disclosure

User enumeration via authentication responses is also covered by their accepted-risk stance on informational disclosures.

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
| `-o`, `--output` | Save results as JSON |

## License

MIT
