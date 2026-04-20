#!/usr/bin/env python3
import struct

with open('save/SAVE/survival_1', 'rb') as f:
    orig = f.read()

with open('build/survival_1_patched', 'rb') as f:
    patched = f.read()

print("=== ORIGINAL ===")
print("Header hex:", orig[:32].hex())
for offset in range(0, 32, 4):
    val = struct.unpack_from('<I', orig, offset)[0]
    print(f"  offset {offset:2d}: LE uint32 = {val} (0x{val:08x})")

print()
print("=== PATCHED ===")
print("Header hex:", patched[:32].hex())
for offset in range(0, 32, 4):
    val = struct.unpack_from('<I', patched, offset)[0]
    print(f"  offset {offset:2d}: LE uint32 = {val} (0x{val:08x})")

print()
print(f"Original total size:  {len(orig)} bytes")
print(f"Patched total size:   {len(patched)} bytes")
print(f"Difference:           {len(patched) - len(orig)} bytes")
