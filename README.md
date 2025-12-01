<<<<<<< HEAD
-------------------------------------------------
README.md  (top-level)
-------------------------------------------------
```markdown
# chat-cli
A minimal WhatsApp-like chat system written in **C++17** that currently runs in the terminal and speaks a custom **binary protocol** over TCP.
Everything is engineered step-by-step; each commit is a milestone you can `git checkout` and run.

## Features Today (Stage 3)
- Single-threaded, poll-based server handling many concurrent clients
- Length-prefixed binary protocol (12-byte header + payload)
- Blind relay: server never interprets message content
- Zero-copy frame forwarding, non-blocking I/O, no external runtime deps
- Valgrind-clean, warning-free build (`-Wall -Wextra`)
=======
# chat_app  
A from-scratch, terminal-first chat system that **walks** from raw TCP to Signal-grade crypto.  
Each commit is a working milestone; check out any tag and run it.

---
>>>>>>> eb7d0827fb00ab665ee7fc62a40a325d6faa6b0a

## What Works Today (Stage 4 – auth & multi-client)
| Feature | Status |
|---------|--------|
| TCP multi-client server | ✅ poll-based, non-blocking I/O |
| Custom binary frame protocol | ✅ 12-byte header + ≤64 kB payload |
| User registration / login | ✅ SQLite + bcrypt |
| Concurrent chat | ✅ any client can type at any time |
| Zero-copy relay | ✅ server never sees plaintext (Stage 5) |
| Valgrind-clean build | ✅ `-Wall -Wextra -Wpedantic` |

---

## One-Line Build
```bash
git clone https://github.com/RosarioLC/chat_app && cd chat_app
make                 # builds server + client
./build/server       # tab 1
./build/client       # tab 2, 3, …, n
```

<<<<<<< HEAD
## Testing
```bash
# Run all tests
./run_tests.sh all

# Or run specific categories
make test-unit           # Unit tests only
make test-integration    # Integration tests (requires server)
make test-e2e            # End-to-end tests

# See tests/README.md for details
```

## Protocol v0 (stable)
```
| length (4) | type (2) | sender (2) | unix-ts (4) |  <-- 12 B
| payload (≤ 64 kB)                                 |
```
Type `1` = text. All fields little-endian.

## Road-Map (check `docs/ROADMAP.md` for detail)
- [ ] Stage 5  – ECDH key exchange, end-to-end encryption
- [ ] Stage 6  – offline message store
- [ ] Stage 7  – group chats
- [ ] Stage 8  – ncurses GUI client
- [ ] Stage 9  – file transfer
- [ ] Stage 10 – double-ratchet forward secrecy
=======
---

## Repo Map
```
include/          public headers
src/              implementation
tests/            4-KB frame torture test + valgrind script
docs/             design notes & stage roadmap
Makefile          single command build
db/               runtime SQLite DB (git-ignored)
```

---

## Protocol v0 (Stage 4)
```
| length (4) | type (2) | sender (2) | unix-ts (4) |  <-- 12 B header
| payload (variable, max 64 kB)                          |
```
Type 1 = text; all fields little-endian.

---

## Stage Road-Map
| Stage | Milestone | Status |
|-------|-----------|--------|
| 1 | TCP echo (single client) | ✅ |
| 2 | Multi-client broadcast | ✅ |
| 3 | Binary frame protocol | ✅ |
| 4 | SQLite auth + bcrypt | ✅ |
| 5 | ECDH key exchange + AES-GCM e2ee | 🚧 |
| 6 | Offline message store | ⏳ |
| 7 | Group chats | ⏳ |
| 8 | ncurses GUI | ⏳ |
| 9 | File transfer | ⏳ |
|10 | Double-ratchet forward secrecy | ⏳ |

---
>>>>>>> eb7d0827fb00ab665ee7fc62a40a325d6faa6b0a

## Licence
MIT – do what you want, blame no one.
