import struct

__all__ = ["p64", "p64a", "p32", "p32a", "p16", "p16a", "unpack"]

_UNPACK_FMT = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}


def p64(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 64, 8)]


def p64a(*n):
    return p64(n)


def p32(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 32, 8)]


def p32a(*n):
    return p32(n)


def p16(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 16, 8)]


def p16a(*n):
    return p16(n)


def unpack(buf):
    fmt = _UNPACK_FMT.get(len(buf))
    if fmt is not None:
        return struct.unpack(fmt, buf)[0]
    return sum(buf[i] << (i * 8) for i in range(len(buf)))
