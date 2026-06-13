import struct
from sc import sc
from structure import Structure
from utils.conversion import u64_to_i64
from utils.etc import alloc
from errors.socket import SocketError

__all__ = [
    "create_tcp_socket",
    "create_tcp_server",
    "create_tcp_client",
    "accept_client",
    "read_from_socket",
    "read_all_from_socket",
    "close_socket",
    "get_socket_name",
    "ip_to_int",
    "htonl",
    "is_port_open",
]

def is_port_open(port):
    sockaddr_in = SOCKADDR_IN_STRUCT.create()
    sockaddr_in.sin_family = AF_INET
    sockaddr_in.sin_port = struct.unpack(">H", struct.pack("<H", port))[0]
    sockaddr_in.sin_addr = htonl(ip_to_int("127.0.0.1"))

    try:
        s = create_tcp_socket()
    except Exception:
        return False

    connect = u64_to_i64(sc.syscalls.connect(s, sockaddr_in, 16))
    close_ret = u64_to_i64(sc.syscalls.close(s))
    
    return connect == 0

AF_INET = 2
SOCK_STREAM = 1
SOL_SOCKET = 0xFFFF
SO_REUSEADDR = 4


SOCKADDR_IN_STRUCT = Structure(
    [
        ("sin_len", 1),
        ("sin_family", 1),
        ("sin_port", 2),
        ("sin_addr", 4),
        ("sin_zero", 8),
    ]
)
ENABLE_BUF_STRUCT = Structure(
    [
        ("enable", 4),
    ]
)
LEN_BUF_STRUCT = Structure(
    [
        ("len", 8),
    ]
)


def ip_to_int(ip_str):
    parts = ip_str.split(".")
    return (
        (int(parts[0]) << 24)
        | (int(parts[1]) << 16)
        | (int(parts[2]) << 8)
        | int(parts[3])
    )


def htonl(x):
    return struct.unpack(">I", struct.pack("<I", x))[0]


def create_tcp_socket():
    s = u64_to_i64(sc.syscalls.socket(AF_INET, SOCK_STREAM))
    if s < 0:
        raise SocketError(
            "socket failed with errno %d\n%s"
            % (sc.syscalls.socket.errno, sc.syscalls.socket.get_error_string())
        )
    return s


def get_socket_name(sock):
    sockaddr_in = SOCKADDR_IN_STRUCT.create()
    len_buf = LEN_BUF_STRUCT.create()
    len_buf.len = 16
    getsockname = u64_to_i64(
        sc.syscalls.getsockname(
            sock,
            sockaddr_in,
            len_buf,
        )
    )
    if getsockname != 0:
        raise SocketError(
            "getsockname failed with errno %d\n%s"
            % (
                sc.syscalls.getsockname.errno,
                sc.syscalls.getsockname.get_error_string(),
            )
        )

    ip_int = sockaddr_in.sin_addr
    ip_str = ".".join(
        [
            str(ip_int & 0xFF),
            str((ip_int >> 8) & 0xFF),
            str((ip_int >> 16) & 0xFF),
            str((ip_int >> 24) & 0xFF),
        ]
    )
    port = struct.unpack(">H", struct.pack("<H", sockaddr_in.sin_port))[0]

    return ip_str, port


def create_tcp_server(port, ip="0.0.0.0"):
    enable_buf = ENABLE_BUF_STRUCT.create()
    enable_buf.enable = 1

    sockaddr_in = SOCKADDR_IN_STRUCT.create()
    sockaddr_in.sin_family = AF_INET
    sockaddr_in.sin_port = struct.unpack(">H", struct.pack("<H", port))[0]
    sockaddr_in.sin_addr = htonl(ip_to_int(ip))

    s = create_tcp_socket()

    sc.syscalls.setsockopt(
        s,
        SOL_SOCKET,
        SO_REUSEADDR,
        enable_buf,
        4,
    )

    bind = u64_to_i64(sc.syscalls.bind(s, sockaddr_in, 16))
    if bind != 0:
        raise SocketError(
            "bind failed with errno %d\n%s"
            % (sc.syscalls.bind.errno, sc.syscalls.bind.get_error_string())
        )

    listen = u64_to_i64(sc.syscalls.listen(s, 3))
    if listen != 0:
        raise SocketError(
            "listen failed with errno %d\n%s"
            % (sc.syscalls.listen.errno, sc.syscalls.listen.get_error_string())
        )

    return s, sockaddr_in


def create_tcp_client(ip, port):
    sockaddr_in = SOCKADDR_IN_STRUCT.create()
    sockaddr_in.sin_family = AF_INET
    sockaddr_in.sin_port = struct.unpack(">H", struct.pack("<H", port))[0]
    sockaddr_in.sin_addr = htonl(ip_to_int(ip))

    s = create_tcp_socket()

    connect = u64_to_i64(sc.syscalls.connect(s, sockaddr_in, 16))
    if connect != 0:
        raise SocketError(
            "connect failed with errno %d\n%s"
            % (sc.syscalls.connect.errno, sc.syscalls.connect.get_error_string())
        )

    return s


def accept_client(server_socket):
    sockaddr_in = SOCKADDR_IN_STRUCT.create()
    len_buf = LEN_BUF_STRUCT.create()
    len_buf.len = 16

    client_sock = u64_to_i64(
        sc.syscalls.accept(
            server_socket,
            sockaddr_in,
            len_buf,
        )
    )
    if client_sock < 0:
        raise SocketError(
            "accept failed with errno %d\n%s"
            % (
                sc.syscalls.accept.errno,
                sc.syscalls.accept.get_error_string(),
            )
        )

    return client_sock


def read_from_socket(sock, size=4096):
    payload_data = b""
    buf = alloc(size)
    read_size = u64_to_i64(
        sc.syscalls.read(
            sock,
            buf,
            size,
        )
    )
    payload_data += buf[:read_size]
    if read_size < 0:
        raise SocketError(
            "read failed with errno %d\n%s"
            % (
                sc.syscalls.read.errno,
                sc.syscalls.read.get_error_string(),
            )
        )
    return payload_data


def read_all_from_socket(sock):
    payload_data = b""
    read_size = -1
    while read_size != 0:
        buf = read_from_socket(sock)
        read_size = len(buf)
        payload_data += buf
    return payload_data


def write_to_socket(sock, data):
    total_written = 0
    data_len = len(data)
    while total_written < data_len:
        to_write = data[total_written : total_written + 4096]
        write_size = u64_to_i64(sc.syscalls.write(sock, to_write, len(to_write)))
        if write_size < 0:
            raise Exception(
                "write failed with errno %d\n%s"
                % (sc.syscalls.write.errno, sc.syscalls.write.get_error_string())
            )
        total_written += write_size


def close_socket(sock):
    close_ret = u64_to_i64(sc.syscalls.close(sock))
    if close_ret != 0:
        raise SocketError(
            "close failed with errno %d\n%s"
            % (sc.syscalls.close.errno, sc.syscalls.close.get_error_string())
        )
