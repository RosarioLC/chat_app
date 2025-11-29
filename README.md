Below is a drop-in skeleton you can copy-paste into your repo **right now**.  
It gives future contributors (and recruiters) a crystal-clear picture of what the code does, how to build it, and where it’s heading—without leaking big chunks of source.

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

## Build & Run
```bash
git clone https://github.com/YOU/chat-cli.git
cd chat-cli
make -j
./build/server                 # tab 1
./build/client                 # tab 2, 3, …
```
Type away—every line is broadcast to all connected clients.

## Repo Map
```
include/          public headers (protocol.hpp, client.hpp, server.hpp)
src/              implementation files
tests/            manual test scripts (4-KB line, valgrind, leak-check)
docs/             design notes and stage road-map
Makefile          builds `client` and `server` binaries in `build/`
```

## Protocol v0 (stable)
```
| length (4) | type (2) | sender (2) | unix-ts (4) |  <-- 12 B
| payload (≤ 64 kB)                                 |
```
Type `1` = text. All fields little-endian.

## Road-Map (check `docs/ROADMAP.md` for detail)
- [ ] Stage 4  – user registration / login with SQLite & bcrypt  
- [ ] Stage 5  – ECDH key exchange, end-to-end encryption  
- [ ] Stage 6  – offline message store  
- [ ] Stage 7  – group chats  
- [ ] Stage 8  – ncurses GUI client  
- [ ] Stage 9  – file transfer  
- [ ] Stage 10 – double-ratchet forward secrecy

## Licence
MIT – do what you want, blame no one.
```
