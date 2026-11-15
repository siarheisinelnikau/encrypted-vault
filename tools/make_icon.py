"""Reproducible original lock artwork. No imaging dependencies or GUI launch."""
from pathlib import Path
import binascii
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]

def rounded(x, y, left, top, right, bottom, radius):
    dx = max(left + radius - x, 0, x - (right - radius))
    dy = max(top + radius - y, 0, y - (bottom - radius))
    return left <= x <= right and top <= y <= bottom and dx * dx + dy * dy <= radius * radius

def pixel(x, y):
    if not rounded(x, y, .03, .03, .97, .97, .22):
        return (0, 0, 0, 0)
    color = (88, 74, 221, 255)
    shackle = .105 <= ((x-.5)**2 + (y-.35)**2)**.5 <= .19 and y <= .42
    shackle = shackle or (.31 <= x <= .395 or .605 <= x <= .69) and .35 <= y <= .46
    if shackle or rounded(x, y, .235, .385, .765, .815, .065):
        color = (255, 255, 255, 255)
    if (x-.5)**2 + (y-.555)**2 <= .065**2 or (.474 <= x <= .526 and .555 <= y <= .688):
        color = (88, 74, 221, 255)
    return color

def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', binascii.crc32(kind + data) & 0xffffffff)

def png(size):
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            samples = [pixel((x+(sx+.5)/4)/size, (y+(sy+.5)/4)/size) for sy in range(4) for sx in range(4)]
            alpha = sum(p[3] for p in samples)
            rgb = [round(sum(p[c]*p[3] for p in samples)/alpha) if alpha else 0 for c in range(3)]
            rows.extend(rgb + [round(alpha/16)])
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size,size,8,6,0,0,0)) + chunk(b'IDAT', zlib.compress(bytes(rows),9)) + chunk(b'IEND', b'')

if __name__ == '__main__':
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [png(size) for size in sizes]
    offset = 6 + 16 * len(sizes)
    ico = bytearray(struct.pack('<HHH', 0, 1, len(sizes)))
    for size, data in zip(sizes, images):
        ico.extend(struct.pack('<BBBBHHII', size%256, size%256, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
    ico.extend(b''.join(images))
    (ROOT / 'assets').mkdir(exist_ok=True)
    (ROOT / 'assets/app.ico').write_bytes(ico)
    (ROOT / 'assets/app.png').write_bytes(images[-1])
