"""Read the shipped PE and embedded icons without loading or executing the app."""
from pathlib import Path
import hashlib
import struct
import sys
import zlib

path = Path(sys.argv[1]).resolve()
data = path.read_bytes()
u16 = lambda at: struct.unpack_from('<H', data, at)[0]
u32 = lambda at: struct.unpack_from('<I', data, at)[0]
assert data[:2] == b'MZ'
pe = u32(60)
assert data[pe:pe+4] == b'PE\0\0' and u16(pe+4) == 0x8664
optional = pe+24
assert u16(optional) == 0x20b, 'Expected x64 PE32+'
sections = []
for index in range(u16(pe+6)):
    at = optional + u16(pe+20) + 40*index
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, at+8)
    sections.append((rva, max(virtual_size, raw_size), raw))

def offset(rva):
    for base, size, raw in sections:
        if base <= rva < base+size:
            return raw+rva-base
    raise AssertionError(f'RVA outside sections: {rva:x}')

imports = []
table = offset(u32(optional+112+8))
while any(data[table:table+20]):
    at = offset(u32(table+12))
    imports.append(data[at:data.index(b'\0', at)].decode('ascii').lower())
    table += 20
assert 'gdi32.dll' in imports and 'user32.dll' in imports
assert not any(name.startswith(('vcruntime', 'msvcp', 'msvcrt', 'ucrtbase', 'api-ms-win-crt', 'd3d', 'dxgi', 'opengl', 'dokan')) for name in imports), imports
root = offset(u32(optional+112+16))
resources = {}

def walk(relative, keys=()):
    at = root+relative
    count = u16(at+12)+u16(at+14)
    for index in range(count):
        entry = at+16+index*8
        key, value = u32(entry), u32(entry+4)
        if key & 0x80000000:
            string_at = root+(key & 0x7fffffff)
            key = data[string_at+2:string_at+2+u16(string_at)*2].decode('utf-16-le')
        if value & 0x80000000:
            walk(value & 0x7fffffff, keys+(key,))
        else:
            leaf = root+value
            blob_at = offset(u32(leaf))
            resources[keys+(key,)] = data[blob_at:blob_at+u32(leaf+4)]

walk(0)
groups = [(key, blob) for key, blob in resources.items() if key[0] == 14]
assert groups and any(key[1] == 1 for key, _ in groups), 'Missing icon group 1 used by app/tray'
source = (Path(__file__).resolve().parents[1] / 'assets/app.ico').read_bytes()
expected = {}
for index in range(struct.unpack_from('<H', source, 4)[0]):
    at = 6+16*index
    width = source[at] or 256
    length, start = struct.unpack_from('<II', source, at+8)
    expected[width] = source[start:start+length]
checked = set()
for _, group in groups:
    count = struct.unpack_from('<H', group, 4)[0]
    for index in range(count):
        at = 6+14*index
        width = group[at] or 256
        resource_id = struct.unpack_from('<H', group, at+12)[0]
        blobs = [blob for key, blob in resources.items() if key[0] == 3 and key[1] == resource_id]
        assert len(blobs) == 1 and blobs[0] == expected[width], 'Packaged artwork differs from source icon'
        blob = blobs[0]
        assert blob.startswith(b'\x89PNG\r\n\x1a\n')
        assert struct.unpack_from('>II', blob, 16) == (width, width)
        compressed = bytearray()
        position = 8
        while position < len(blob):
            length = struct.unpack_from('>I', blob, position)[0]
            kind = blob[position+4:position+8]
            payload = blob[position+8:position+8+length]
            assert zlib.crc32(kind+payload) & 0xffffffff == struct.unpack_from('>I', blob, position+8+length)[0]
            if kind == b'IDAT':
                compressed.extend(payload)
            position += 12+length
        pixels = zlib.decompress(compressed)
        alpha = []
        for y in range(width):
            row = pixels[y*(1+4*width):(y+1)*(1+4*width)]
            assert row[0] == 0
            alpha.extend(row[4::4])
        assert sum(a > 0 for a in alpha) > width*width//2, 'Blank or excessively padded icon'
        checked.add(width)
assert checked == set(expected), 'Missing icon sizes'
version = [blob for key, blob in resources.items() if key[0] == 16]
assert version and any('Encrypted Vault' in blob.decode('utf-16-le', errors='ignore') for blob in version)
print(f'Verified x64 PE: {path.name}; {len(data):,} bytes; SHA-256 {hashlib.sha256(data).hexdigest()}')
print('Embedded original icons match at sizes: ' + ', '.join(map(str, sorted(checked))))
print('Imports: native GDI/User32; no dynamic MSVC CRT, GPU renderer or Dokany import.')
