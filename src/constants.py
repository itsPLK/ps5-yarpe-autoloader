import renpy
import os
import json
from offsets import GADGET_OFFSETS, LIBC_OFFSETS, EXEC_OFFSETS

VERSION = ""
with open(renpy.config.savedir + "/yarpe/version.txt", "r") as f:
    VERSION = f.read().strip()

FONT_PATH = renpy.config.savedir + "/yarpe/debug_mono.ttf"

with open(renpy.config.savedir + "/yarpe/config.json", "r") as f:
    CONFIG = json.load(f)

CONSOLE_KIND = os.getenv("CONSOLE_KIND", None)
if CONSOLE_KIND is None:
    raise Exception("Cannot determine console kind")

SELECTED_GADGETS = GADGET_OFFSETS.get(renpy.config.name, {}).get(CONSOLE_KIND, {})
SELECTED_LIBC = LIBC_OFFSETS.get(renpy.config.name, {}).get(CONSOLE_KIND, {})
SELECTED_EXEC = EXEC_OFFSETS.get(renpy.config.name, {}).get(CONSOLE_KIND, {})

if not SELECTED_GADGETS or not SELECTED_LIBC or not SELECTED_EXEC:
    raise Exception("Unsupported game / console kind combination")

SYSCALL = {
    "read": 3,
    "write": 4,
    "open": 5,
    "close": 6,
    "getpid": 20,
    "getuid": 24,
    "accept": 30,
    "getsockname": 32,
    "kill": 37,
    "pipe": 42,
    "socket": 97,
    "connect": 98,
    "bind": 104,
    "setsockopt": 105,
    "listen": 106,
    "netgetiflist": 125,
    "stat": 188,
    "sysctl": 202,
    "is_in_sandbox": 585,
}

SHARED_VARS = {}

nogc = []

rp = renpy
