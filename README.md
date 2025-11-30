# chat_app  
A from-scratch, terminal-first chat system that **walks** from raw TCP to Signal-grade crypto.  
Each commit is a working milestone; check out any tag and run it.

---

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

## Licence
MIT – do what you want, blame no one.
