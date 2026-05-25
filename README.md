# mongobrute

MongoDB user enumeration tool.

Two vectors let an unauthenticated attacker check if a user exists:

- **`authenticate` command** — returns `UserNotFound` for missing users but `Authentication failed` for existing ones
- **`saslSupportedMechs` in `hello`** — field is present if user exists, absent otherwise

Submitted to MongoDB's bug bounty program. Both vectors were marked **out of scope**.

## Usage

```bash
pip install pymongo
```

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
