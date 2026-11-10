#!/usr/bin/env python3
"""Append 4096-byte block SHA-256 tables (<window>.vroot) to a SHNGROOT userdata-root.img in place.

When CONFIG_XNU_SOURCE_STORAGE_TABLES="userdata" is active, the boot image carries only the 544-byte
signed VerifiedRoot policy headers, and NativeUfs reads OS.vroot, SystemOS.vroot and App.vroot from
userdata-root.img as SHNGROOT version 2 data objects (block_size=4096, flags=3).
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

MIB = 1 << 20
CHUNK = 8 * MIB


def parse_header(header):
    if len(header) != 4096 or header[:8] != b'SHNGROOT':
        raise SystemExit('Not a SHNGROOT userdata image')
    if hashlib.sha256(header[:4064]).digest() != header[4064:4096]:
        raise SystemExit('SHNGROOT manifest header SHA-256 mismatch')
    version, count, image_bytes = struct.unpack_from('<IIQ', header, 8)
    windows, objects = [], []
    for index in range(count):
        raw_name, offset, size, block_size, flags, digest, _ = struct.unpack_from(
            '<32sQQII32s40s', header, 24 + 128 * index
        )
        name = raw_name.split(b'\0', 1)[0].decode('ascii')
        entry = {'name': name, 'offset': offset, 'size': size, 'sha256': digest.hex()}
        if block_size == 512 and flags == 1:
            windows.append(entry)
        elif version == 2 and block_size == 4096 and flags == 3:
            objects.append(entry)
        else:
            raise SystemExit(f'Unexpected SHNGROOT entry {name} (block_size={block_size}, flags={flags})')
    return version, image_bytes, windows, objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='Path to userdata-root.img')
    args = parser.parse_args()
    image = args.image.resolve()
    if not image.is_file():
        raise SystemExit(f'Image not found: {image}')

    with image.open('r+b') as f:
        header = f.read(4096)
        version, image_bytes, windows, objects = parse_header(header)
        if objects:
            print(f'{image.name}: already SHNGROOT v{version} with objects {[o["name"] for o in objects]}')
            return
        cursor = (image_bytes + MIB - 1) // MIB * MIB
        for w in windows:
            name = f'{w["name"]}.vroot'
            f.seek(w['offset'])
            rem = w['size']
            table = bytearray()
            while rem > 0:
                chunk = f.read(min(CHUNK, rem))
                if not chunk:
                    raise SystemExit(f'Short read in window {w["name"]}')
                mv = memoryview(chunk)
                for off in range(0, len(mv), 4096):
                    table.extend(hashlib.sha256(mv[off:off + 4096]).digest())
                del mv
                rem -= len(chunk)
            obj_offset = cursor
            obj_size = len(table)
            cursor += (obj_size + MIB - 1) // MIB * MIB
            f.truncate(cursor)
            f.seek(obj_offset)
            f.write(table)
            obj_sha = hashlib.sha256(table).hexdigest()
            objects.append({'name': name, 'offset': obj_offset, 'size': obj_size, 'sha256': obj_sha})
            print(f'{name}: {obj_size} bytes at {obj_offset:#x} sha256 {obj_sha}')

        new_header = bytearray(4096)
        new_header[0:8] = b'SHNGROOT'
        rows = [(w, 512, 1) for w in windows] + [(o, 4096, 3) for o in objects]
        struct.pack_into('<IIQ', new_header, 8, 2, len(rows), cursor)
        for index, (entry, block_size, flags) in enumerate(rows):
            struct.pack_into(
                '<32sQQII32s40s', new_header, 24 + 128 * index,
                entry['name'].encode('ascii'), entry['offset'], entry['size'],
                block_size, flags, bytes.fromhex(entry['sha256']), bytes(40)
            )
        new_header[4064:4096] = hashlib.sha256(bytes(new_header[:4064])).digest()
        f.seek(0)
        f.write(new_header)

    report_path = image.with_suffix('.json')
    if report_path.is_file():
        report = json.loads(report_path.read_text())
    else:
        report = {'windows': windows}
    report['image_bytes'] = cursor
    report['manifest_sha256'] = hashlib.sha256(bytes(new_header)).hexdigest()
    report['objects'] = objects
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Updated {image.name} to SHNGROOT v2 ({cursor} bytes)')


if __name__ == '__main__':
    main()

