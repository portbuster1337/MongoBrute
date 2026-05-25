# mongobrute

MongoDB User Enumeration Tool

Exploits two information disclosure vectors in MongoDB that allow an unauthenticated attacker to enumerate valid database users.

## Vectors

### Vector 1: `authenticate` Command (UserNotFound Leak)

In `src/mongo/db/commands/authentication_commands.cpp`, the legacy `authenticate` command handler rethrows `ErrorCodes::UserNotFound` directly to the client. This reveals whether a user exists:

- **User does NOT exist** → `"UserNotFound: Could not find user <username> for db <dbname>"`
- **User exists** → `"Authentication failed."` (generic, for wrong password)

The SASL path (`saslStart`/`saslContinue`) correctly masks this, but the legacy `authenticate` command does not.

### Vector 2: `saslSupportedMechs` in `hello`

The `hello` command supports a `saslSupportedMechs` field. When sent with `saslSupportedMechs: "db.username"`, the server returns supported SASL mechanisms only if the user exists:

- **User exists** → Response includes `saslSupportedMechs: ["SCRAM-SHA-256", "SCRAM-SHA-1"]`
- **User does NOT exist** → Field is absent from response

This is considered "by design" by MongoDB but still enables enumeration.

## Usage

```bash
pip install pymongo
```

```bash
python mongobrute.py -t 10.0.0.1:27017 -w usernames.txt
python mongobrute.py -t cluster.mongodb.net -w usernames.txt -T 32 --tls
python mongobrute.py -t 10.0.0.1 -w users.txt --vector sasl -o results.json
```

Arguments:
| Flag | Description |
|------|-------------|
| `-t`, `--target` | MongoDB host\[:port\] |
| `-w`, `--wordlist` | Username wordlist file |
| `-d`, `--db` | Authentication database (default: admin) |
| `-T`, `--threads` | Concurrent threads (default: 16) |
| `--timeout` | Connection timeout in seconds (default: 5) |
| `--vector` | Enumeration vector: `authenticate`, `sasl`, `both` (default: both) |
| `--tls` | Use TLS |
| `--tlsCAFile` | TLS CA certificate file |
| `--tlsAllowInvalidCertificates` | Allow invalid TLS certificates |
| `-o`, `--output` | Output results to JSON file |
| `-q`, `--quiet` | Suppress banner, only show found users |

## References

- [MongoDB Source: authentication_commands.cpp](https://github.com/mongodb/mongo/blob/master/src/mongo/db/commands/authentication_commands.cpp) (lines 132-145, UserNotFound leak)
- [MongoDB Source: sasl_commands.cpp](https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/sasl_commands.cpp) (SASL path masks UserNotFound correctly)
- [MongoDB Source: sasl_scram_server_conversation.cpp](https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/sasl_scram_server_conversation.cpp) (where UserNotFound originates)
- [MongoDB Bug Bounty Program](https://www.mongodb.com/security-disclosure) - User enumeration via `saslSupportedMechs` and legacy `authenticate` command are classified as known/out-of-scope issues

## License

MIT
