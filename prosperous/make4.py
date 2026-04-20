#!/usr/bin/env python3
import os
import kleipack

SAVE_INPUT    = 'save/SAVE/survival_1'
OUTPUT        = 'build/survival_1_patched'
LUA_CODE_PATH = 'save_hax/code.lua'

os.makedirs('build', exist_ok=True)

with open(SAVE_INPUT, 'rb') as f:
    packed = f.read()

print("[*] Unpacking...")
data = kleipack.unpack(packed)

lua_code = open(LUA_CODE_PATH, 'rb').read()

INJECT_MARKER = b'mods={}'

if INJECT_MARKER not in data:
    print("[!] Could not find 'mods={}' - aborting")
    exit(1)

injection = b'mods=setmetatable({},{__index=function() ' + lua_code + b' end})'

patched = data.replace(INJECT_MARKER, injection, 1)

print("[*] Repacking...")
new_packed = kleipack.pack(patched)

with open(OUTPUT, 'wb') as f:
    f.write(new_packed)

print(f"[+] Done: {OUTPUT}")
print("[!] Replace save/SAVE/survival_1 with this, then re-sign with Garlic.")
