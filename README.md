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
git clone https://github.com/RosarioLC/chat_app.git
cd chat_app
make -j
./server                 # tab 1
./client                 # tab 2, 3, …
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

## Licence
MIT – do what you want, blame no one.
```
