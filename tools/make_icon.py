#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 1024x1024 的 App 图标，纯标准库实现，不依赖 Pillow。"""

import struct
import sys
import zlib

SIZE = 1024
SCAN_Y = 640.0


def in_round_rect(x, y, x0, y0, x1, y1, r):
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False
    if x < x0 + r and y < y0 + r:
        return (x - (x0 + r)) ** 2 + (y - (y0 + r)) ** 2 <= r * r
    if x > x1 - r and y < y0 + r:
        return (x - (x1 - r)) ** 2 + (y - (y0 + r)) ** 2 <= r * r
    if x < x0 + r and y > y1 - r:
        return (x - (x0 + r)) ** 2 + (y - (y1 - r)) ** 2 <= r * r
    if x > x1 - r and y > y1 - r:
        return (x - (x1 - r)) ** 2 + (y - (y1 - r)) ** 2 <= r * r
    return True


def blend(r, g, b, cr, cg, cb, alpha):
    return (
        int(round(r * (1.0 - alpha) + cr * alpha)),
        int(round(g * (1.0 - alpha) + cg * alpha)),
        int(round(b * (1.0 - alpha) + cb * alpha)),
    )


def build():
    buf = bytearray(SIZE * SIZE * 4)
    index = 0

    for y in range(SIZE):
        row_top = 292 + ((y - 292) // 180) * 180 if 292 <= y <= 792 else None

        for x in range(SIZE):
            # 背景斜向渐变
            t = (x / SIZE) * 0.55 + (y / SIZE) * 0.45
            r = int(16 + 46 * t)
            g = int(22 + 20 * t)
            b = int(44 + 78 * t)

            # 卡片底板
            if in_round_rect(x, y, 168, 228, 856, 828, 88):
                r, g, b = blend(r, g, b, 255, 255, 255, 0.085)

            # 三行列表项
            if row_top is not None:
                top = row_top
                if in_round_rect(x, y, 216, top, 356, top + 140, 34):
                    r, g, b = blend(r, g, b, 245, 248, 255, 0.84)
                if in_round_rect(x, y, 392, top + 30, 392 + 254, top + 52, 11):
                    r, g, b = blend(r, g, b, 255, 255, 255, 0.56)
                if in_round_rect(x, y, 392, top + 78, 392 + 168, top + 96, 9):
                    r, g, b = blend(r, g, b, 255, 255, 255, 0.27)

            # 扫描线
            distance = abs(y - SCAN_Y)
            if distance < 78:
                strength = 1.0 - distance / 78.0
                strength = strength * strength
                r, g, b = blend(r, g, b, 34, 211, 238, 0.88 * strength)

            # 扫描线以下压暗，形成"已扫描"效果
            if y > SCAN_Y:
                r, g, b = blend(r, g, b, 6, 10, 26, 0.16)

            buf[index] = r
            buf[index + 1] = g
            buf[index + 2] = b
            buf[index + 3] = 255
            index += 4

    return bytes(buf)


def encode_png(pixels):
    raw = bytearray()
    stride = SIZE * 4
    for y in range(SIZE):
        raw.append(0)  # filter type: None
        raw.extend(pixels[y * stride:(y + 1) * stride])

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    return png


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "icon-1024.png"
    pixels = build()
    png = encode_png(pixels)
    with open(output, "wb") as handle:
        handle.write(png)
    print("icon written: %s (%d bytes)" % (output, len(png)))


if __name__ == "__main__":
    main()
