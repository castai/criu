#!/usr/bin/env python3
"""Decode CRIU mountpoints images (header + protobuf wire) enough to list
mnt_id / mountpoint / fstype / s_dev, to see which nsid owns which mounts."""
import sys


def read_varint(buf, i):
    v = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return v, i


def walk(buf):
    """Yield (field_no, wire_type, value) entries."""
    i = 0
    while i < len(buf):
        tag, i = read_varint(buf, i)
        fno, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = read_varint(buf, i)
            yield fno, wt, v
        elif wt == 2:
            ln, i = read_varint(buf, i)
            yield fno, wt, buf[i:i + ln]
            i += ln
        elif wt == 5:
            yield fno, wt, buf[i:i + 4]
            i += 4
        elif wt == 1:
            yield fno, wt, buf[i:i + 8]
            i += 8
        else:
            raise ValueError("wire type %d" % wt)


def split_entries(buf):
    """CRIU image payload: repeated (u32 LE size, entry bytes)."""
    entries = []
    i = 0
    while i + 4 <= len(buf):
        ln = int.from_bytes(buf[i:i + 4], 'little')
        i += 4
        if ln == 0 or i + ln > len(buf):
            break
        entries.append(buf[i:i + ln])
        i += ln
    return entries


FIELD_NAMES = {1: 'mnt_id', 2: 'root', 3: 'mountpoint', 4: 'flags', 5: 'fstype',
               6: 'source', 7: 'options', 8: 'sharing', 9: 'parent_id'}


def dump(path):
    data = open(path, 'rb').read()
    # skip image header: u32 magic + u32 size
    payload = data[8:]
    print('== %s (%d bytes, payload %d)' % (path, len(data), len(payload)))
    for e in split_entries(payload):
        vals = {}
        for fno, wt, v in walk(e):
            name = FIELD_NAMES.get(fno, 'f%d' % fno)
            if isinstance(v, bytes):
                try:
                    v = v.decode()
                except UnicodeDecodeError:
                    v = repr(v)
            vals.setdefault(name, v)
        print('  mnt_id=%s parent_id=%s fstype=%s mountpoint=%s root=%s %s' % (
              vals.get('mnt_id'), vals.get('parent_id'), vals.get('fstype'),
              vals.get('mountpoint'), vals.get('root'),
              ' '.join('%s=%s' % kv for kv in vals.items()
                        if kv[0] not in
                        ('mnt_id', 'parent_id', 'fstype', 'mountpoint', 'root'))))


def dump_ids(path):
    data = open(path, 'rb').read()
    payload = data[8:]
    print('== %s (%d bytes)' % (path, len(data)))
    for e in split_entries(payload):
        for fno, wt, v in walk(e):
            if isinstance(v, bytes):
                try:
                    v = v.decode()
                except UnicodeDecodeError:
                    v = repr(v)
            print('  f%d = %s' % (fno, v))


for p in sys.argv[1:]:
    if 'ids-' in p:
        dump_ids(p)
    else:
        dump(p)
