```
# chat-cli Stage Road-Map

Stage 1  TCP echo (single client)  
Stage 2  Multi-client broadcast, poll loop, non-blocking sockets  
Stage 3  Custom binary protocol, frame relay, 64 kB max payload  
Stage 4  SQLite user table, REG/LOGIN handshake, bcrypt password hash  
Stage 5  ECDH key-exchange, per-chat shared secret, AES-GCM envelopes  
Stage 6  Server-side offline queue, message status (sent/delivered/read)  
Stage 7  Group chats (server-managed membership, multicast encryption)  
Stage 8  Terminal UI with ncurses (tabs, contact list, scrollback)  
Stage 9  File transfer inside binary protocol (chunked, encrypted)  
Stage 10 Signal-style double-ratchet for forward secrecy
```
