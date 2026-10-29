__all__ = ["refbytearray", "refbytes", "get_ref_addr"]


from constants import nogc


BYTES_HEADER_LEN = type(b"").__sizeof__(b"") - 1
_readuint = None
_StructureInstance = None


def refbytearray(data):
    global _readuint
    if _readuint is None:
        from unsafe import readuint

        _readuint = readuint

    # NOTE: take care your object doesn't get GC'd and leave a dangling reference!
    assert isinstance(data, bytearray)
    addr = id(data)
    a = _readuint(addr + 8 * 5, 8)  # read the pointer to the underlying buffer
    return a


def refbytes(data):
    # get the address of the internal buffer of a bytes object
    return id(data) + BYTES_HEADER_LEN


def get_ref_addr(obj):
    global _StructureInstance
    if isinstance(obj, bytearray):
        return refbytearray(obj)
    elif isinstance(obj, int):
        return obj
    elif isinstance(obj, str):
        return refbytes(obj)
    elif isinstance(obj, unicode):
        utf8data = obj.encode("utf-8") + b"\0"
        nogc.append(utf8data)
        return refbytes(utf8data)
    if _StructureInstance is None:
        from structure import StructureInstance

        _StructureInstance = StructureInstance
    if isinstance(obj, _StructureInstance):
        return refbytearray(obj.buf)
    raise Exception("Unsupported object type for get_ref_addr")
