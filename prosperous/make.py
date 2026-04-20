#!/usr/bin/env python3
"""
prosperous-eu - EU port of the Don't Starve PS4 save exploit
CUSA00327 (EU) port of fail0verflow's prosperous (CUSA00158 US)
Vibecoded with Claude
"""

import os, sys, base64, zlib, struct, shutil

SAVE_DIR  = 'save'
BUILD_DIR = 'build'

SAVE_INPUT    = os.path.join(SAVE_DIR, 'SAVE', 'survival_1')
OUTPUT        = os.path.join(BUILD_DIR, 'survival_1_exploit')
LUA_CODE_PATH = os.path.join('save_hax', 'code.lua')
TEMPLATE_PATH = os.path.join('save_hax', 'survival_1.lua')

MAGIC = b'KLEI     1D'


def unpack(raw):
    assert raw[:11] == MAGIC, "Bad kleipack header"
    decoded = base64.b64decode(raw[11:])
    v1, v2, uncompressed_len, compressed_len = struct.unpack_from('<4I', decoded, 0)
    data = zlib.decompress(decoded[0x10:])
    assert len(data) == uncompressed_len
    return v1, v2, compressed_len, data


def pack(v1, v2, orig_compressed_len, data):
    best, best_lvl = None, -1
    for level in range(1, 10):
        candidate = zlib.compress(data, level)
        if best is None or abs(len(candidate) - orig_compressed_len) < abs(len(best) - orig_compressed_len):
            best, best_lvl = candidate, level
    new_compressed = best
    enc_hdr = struct.pack('<4I', v1, v2, len(data), len(new_compressed))
    return MAGIC + base64.b64encode(enc_hdr + new_compressed)


def build():
    os.makedirs(BUILD_DIR, exist_ok=True)

    print("[*] Reading save...")
    with open(SAVE_INPUT, 'rb') as f:
        raw = f.read()
    v1, v2, orig_compressed_len, _ = unpack(raw)

    print("[*] Reading exploit payload...")
    lua_code = open(LUA_CODE_PATH, 'rb').read()

    # Base64 encode the entire payload to avoid ALL delimiter/escaping issues
    # The [[ ]] sequences in code.lua break naive string embedding
    b64_payload = base64.b64encode(lua_code).decode('ascii')

    # Self-decoding payload - decodes base64 at runtime then runs via loadstring
    cookie = f'''local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function dec(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if x == '=' then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r
    end):gsub('%d%d%d%d%d%d%d%d', function(x)
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end
local code = dec("{b64_payload}")
local func, err = loadstring(code)
if func then
    func()
else
    DisplayError("LOAD ERR: "..tostring(err))
end'''

    print("[*] Building script...")
    template = open(TEMPLATE_PATH, 'rb').read()
    data = template.replace(b'LUA_CODE_COOKIE', cookie.encode('utf-8'))

    print("[*] Packing...")
    output = pack(v1, v2, orig_compressed_len, data)

    with open(OUTPUT, 'wb') as f:
        f.write(output)

    print(f"[+] Done: {OUTPUT}")
    print()
    print("Next steps:")
    print("  1. Copy build/survival_1_exploit -> your Garlic SAVE/survival_1")
    print("  2. Resign + encrypt with Garlic Save (upload SAVE + SAVE.bin pair)")
    print("  3. Export to USB -> copy to PS4/SAVEDATA/<userid>/CUSA00327/")
    print("  4. Load the save slot in-game")
    print("  5. Connect to PS4 on port 6667 to get Lua shell")
    print()
    print("If you see a runtime error, the libc offsets need updating for EU.")
    print("See README.md for details.")


def clean():
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    print("[+] Cleaned build directory")


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else None
    if cmd == 'clean':
        clean()
    else:
        build()
