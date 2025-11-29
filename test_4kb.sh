#!/usr/bin/env bash
# test_4kb.sh  — inject 4 KB line into client-0

# ---- config ----
CLIENT_FIFO="/tmp/chat-client0"   # fifo we’ll create
LINE_LEN=100                     # bytes before \n
# ----------------

# build the line: 4095 ‘x’ + newline
printf -v BIG_LINE '%*s' $((LINE_LEN-1)) ''
BIG_LINE="${BIG_LINE// /x}END"

# create fifo (safe to re-run)
[[ -p $CLIENT_FIFO ]] || mkfifo "$CLIENT_FIFO"

# send the whole line at once
echo "$BIG_LINE" > "$CLIENT_FIFO" &

# start the client, reading from the fifo
./client.o < "$CLIENT_FIFO"
