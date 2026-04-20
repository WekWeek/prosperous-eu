#!/usr/bin/env python3
import sys, base64, zlib, struct

def hdr_parse(hdr):
    if not hdr.startswith(b'KLEI     1'):
        return None
    return hdr[10:11] == b'D'

def hdr_make(encoded):
    return bytes('KLEI%6d%c' % (1, 'D' if encoded else ' '), 'ascii')

def pack(data):
    encode = True
    hdr = hdr_make(encode)
    if encode:
        uncompressed_len = len(data)
        data = zlib.compress(data)
        enc_hdr = struct.pack('<4I', 1, 1, uncompressed_len, len(data))
        data = base64.b64encode(enc_hdr + data)
    return hdr + data

def unpack(data):
    encoded = hdr_parse(data)
    if encoded is None:
        print('bad hdr')
        return None
    data = data[11:]
    if not encoded:
        return data
    data = base64.b64decode(data)
    _, _, uncompressed_len, compressed_len = struct.unpack_from('<4I', data, 0)
    data = data[0x10:]
    assert compressed_len == len(data)
    data = zlib.decompress(data)
    assert uncompressed_len == len(data)
    return data

if __name__ == '__main__':
    cmd = sys.argv[1]
    data_in = open(sys.argv[2], 'rb').read()
    path_out = sys.argv[3] if len(sys.argv) > 3 else None

    output = None
    if cmd == 'p':
        output = pack(data_in)
    elif cmd == 'u':
        output = unpack(data_in)

    if path_out is None:
        print(str(output, 'ascii'))
    else:
        # try to remove our own encoding
        try: output = bytes.fromhex(str(output, 'ascii'))
        except: pass
        open(path_out, 'wb').write(output)
