#!/usr/bin/env python3
"""Map the MT1959 OmniDrive patch sites onto the BW-12B1LT 1.03 (MT1939) dump.

Inputs are the decoded ASUS BW-16D1HT 3.02 image used by asm/main.asm and the
MT1939 specimen. Thumb code is compared after masking PC-relative fields
(literal loads, branches, BL); each MT1959 site is scored against every
MT1939 halfword. MT1959 also runs part of its DVD code from a compressed RAM
overlay (flash 0x15c000, loaded at 0x01f72000): it is unpacked here so the
two runtime patches of main.c's ReadDVDTOCHook can be compared as well.
Scores are evidence for review, not a substitute for reading both sites.
"""
import argparse
from pathlib import Path
import re
import struct

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

ROOT = Path(__file__).resolve().parents[3]
OVERLAY_OFFSET = 0x15c000
OVERLAY_BASE = 0x01f72000
# Reviewed counterparts (MT1959 label -> MT1939 address, or None with reason).
MAPPING = {
    'ChangeDiscRWMode': 0x45b8a, 'SetErrorMode': 0x46918,
    'ReadDiscStructMemDWORD': 0xa646a, 'ReadDiscData': 0xcd454, 'SetCDType': 0x1bd8d8,
    'ScrambleHookAddr': 0xa59c6, 'BDScramblePatchAddr': 0xb5888, 'BDScrambleHookAddr': 0xb588c,
    'DVDScrambleHookAddr': 0x1bf410, 'DVDEDCHookAddr': 0x1bf5ae, 'BDEDCHookAddr': 0xb6668,
    'DVDMinusReadCheckHookAddr': 0x1bf3ba, 'BDLeadOutPatchAddr': 0x1bc453,
    'DVDLeadOutPatchAddr0': 0x1bbc63, 'DVDLeadOutPatchAddr1': 0x1bbca0,
    'CDLeadOutPatchAddr0': 0xe4a28, 'CDLeadOutPatchAddr1': 0x1bd770,
    'CDLeadOutPatchAddr5': 0x1bd890, 'CDLeadOutPatchAddr6': 0x1bd8aa,
    'BDIdentifierPatchAddr1': 0x133926, 'BDIdentifierPatchAddr2': 0x13392d,
    'BDIdentifierPatchAddr3': 0x1339d4,
    'BDIdentifierPatchAddr4': None,  # second W/U/R/O check; MT1939 has none
    'DVDScramblePatchAddr1': None,  # MT1939 DVD reader never skips the mode change
    'DVDScramblePatchAddr2': None,
    'ReadSpeedPatchAddr': None,  # MT1959 read-load accumulator; absent on MT1939
    'CDDataSpeedPatchAddr': None,  # subcode-driven CD speed routine; absent on MT1939
}
OVERLAY_MAPPING = {0x01f96daa: 0xcb826,  # DVDCharacteristicsPatch switch (MT1939 hooks 0xcbb50)
                   0x01f976c2: 0xcc16a}  # DVDTOCReadPatch (control data read result)


def normalize(image):
    h = np.frombuffer(image[:len(image) // 2 * 2], dtype='<u2').astype(np.uint32)
    out = h.copy()
    for mask, value, keep in ((0xf800, 0x4800, 0xff00), (0xf800, 0xa000, 0xff00),
                              (0xf800, 0xe000, 0xf800), (0xf000, 0xf000, 0xf800)):
        m = (h & mask) == value
        out[m] = h[m] & keep
    m = ((h & 0xf000) == 0xd000) & ((h & 0x0f00) < 0x0e00)
    out[m] = h[m] & 0xff00
    return out


def best_matches(source, target, address, *, span=32, chunk=8, slack=8, top=3):
    """Chunked comparison tolerating small insertions; returns (address, score)."""
    i, n = address // 2, len(target)
    total = np.zeros(n, dtype=np.int32)
    for c0 in range(-span, span, chunk):
        window = source[i + c0:i + c0 + chunk]
        score = np.zeros(n, dtype=np.int32)
        for k, v in enumerate(window):
            score[:n - chunk] += target[k:k + n - chunk] == v
        shifted = np.zeros(n, dtype=np.int32)
        if c0 >= 0:
            shifted[:n - c0] = score[c0:]
        else:
            shifted[-c0:] = score[:n + c0]
        total += sliding_window_view(np.pad(shifted, slack), 2 * slack + 1).max(axis=1)
    order = np.argsort(total)[::-1][:top]
    return [(int(j) * 2, int(total[j])) for j in order]


class Bits:
    def __init__(self, data, offset):
        self.data, self.bit = data, offset * 8

    def read(self, count=1):
        value = 0
        for _ in range(count):
            byte = self.data[self.bit >> 3]
            value = (value << 1) | ((byte >> (7 - (self.bit & 7))) & 1)
            self.bit += 1
        return value


def canonical(lengths):
    codes, code = {}, 0
    for length in range(1, max(lengths) + 1):
        for symbol, value in enumerate(lengths):
            if value == length:
                codes[(length, code)] = symbol
                code += 1
        code <<= 1
    return codes, max(lengths)


def decode(bits, table):
    codes, longest = table
    code = 0
    for length in range(1, longest + 1):
        code = (code << 1) | bits.read()
        if (length, code) in codes:
            return codes[(length, code)]
    raise ValueError('Invalid Huffman code in MT1959 overlay')


def unpack_overlay(image):
    """MSB-first canonical Huffman LZ77: 288 literal/length + 32 distance codes,
    length = symbol - 253, distance = symbol << 7 | 7 raw bits."""
    size, _ = struct.unpack_from('<II', image, OVERLAY_OFFSET)
    lengths = list(image[OVERLAY_OFFSET + 8:OVERLAY_OFFSET + 8 + 320])
    literal, distance = canonical(lengths[:288]), canonical(lengths[288:])
    bits, out = Bits(image, OVERLAY_OFFSET + 8 + 320), bytearray()
    while len(out) < size:
        symbol = decode(bits, literal)
        if symbol < 256:
            out.append(symbol)
            continue
        back = (decode(bits, distance) << 7) | bits.read(7)
        if not 0 < back <= len(out):
            raise ValueError('Invalid MT1959 overlay back-reference')
        for _ in range(symbol - 253):
            out.append(out[-back])
    return bytes(out[:size])


def labels(profile):
    text = profile.read_text()
    return {m.group(1): int(m.group(2), 16) for m in re.finditer(
        r'\.define(?:thumb|arm|data)label\s+(\w+),\s*(0x[0-9A-Fa-f]+)', text, re.I)}


def compare(mt1959, mt1939):
    source, target = normalize(mt1959), normalize(mt1939)
    rows = []
    for name, address in labels(ROOT / 'asm/ASUS_BW-16D1HT_3.02.asm').items():
        if name not in MAPPING:
            continue
        best = best_matches(source, target, address & ~1)
        rows.append(dict(label=name, mt1959=address, mt1939=MAPPING[name], candidates=best))
    overlay = unpack_overlay(mt1959)
    overlay_source = normalize(overlay)
    for address, counterpart in OVERLAY_MAPPING.items():
        best = best_matches(overlay_source, target, (address - OVERLAY_BASE) & ~1)
        rows.append(dict(label=f'overlay {address:#x}', mt1959=address, mt1939=counterpart,
                         candidates=best))
    return rows, overlay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mt1959', type=Path, help='Decoded ASUS BW-16D1HT 3.02 image')
    parser.add_argument('mt1939', type=Path, help='Decoded ASUS BW-12B1LT 1.03 image')
    parser.add_argument('--overlay', type=Path, help='New path for the unpacked MT1959 overlay')
    args = parser.parse_args()
    rows, overlay = compare(args.mt1959.read_bytes(), args.mt1939.read_bytes())
    for row in rows:
        mapped = 'none' if row['mt1939'] is None else f'{row["mt1939"]:#08x}'
        found = ' '.join(f'{a:#x}({s})' for a, s in row['candidates'])
        print(f'{row["label"]:28s} {row["mt1959"]:#010x} -> {mapped:>9s}   best: {found}')
    if args.overlay:
        with args.overlay.open('xb') as output:
            output.write(overlay)


if __name__ == '__main__':
    main()
