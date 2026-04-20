#!/usr/bin/env python3
import os, sys, struct, socket

PORT = 6667
CMD_EXEC_LUA = 3

PS5_IP = os.getenv('PS5_IP')
if PS5_IP is None: PS5_IP = sys.argv[1]
lua_path = sys.argv[len(sys.argv) - 1]

sock = socket.create_connection((PS5_IP, PORT))
lua_text = open(lua_path, 'rb').read()
sock.sendall(struct.pack('<II', CMD_EXEC_LUA, len(lua_text)) + lua_text)
