import os
from sc import sc
from utils.rp import log
from utils.fs import file_exists, read_file_data

def run_script(path):
    log("[*] Running " + path)
    if os.path.exists(path) or file_exists(path):
        if path.startswith("/saves/"):
            with open(path, "r") as f:
                exec_str = f.read()
        else:
            exec_str = read_file_data(path).decode("utf-8")
        
        # Merge our local variables into globals so we don't isolate the environment
        scope = dict(globals(), **locals())
        exec(exec_str, scope)
    else:
        log("[!] Script not found: " + path)

def main():
    if sc.platform != "ps5":
        log("This autoloader dispatch is intended for PS5.")
        return

    version_path = "/saves/yarpe/version.txt"
    if file_exists(version_path):
        version = read_file_data(version_path).decode("utf-8").strip()
    else:
        version = "unknown"
    
    log("=== PS5 Yarpe Autoloader v%s ===" % version)


    fw_version = float(sc.version)
    log("[*] Console firmware version: %.2f" % fw_version)

    has_net = sc.get_current_ip() is not None
    log("[*] Network interface active: %s" % has_net)

    relapse_supported = (
        fw_version >= 7.00
        and fw_version <= 13.60
        and sc.version != "9.05"
    )

    needs_elf_loader = False

    if relapse_supported and has_net:
        log("[*] Selected exploit: relapse.py ( network active )")
        sc.send_notification(
            "Selected exploit: relapse.py\n(network active: %s)" % has_net
        )
        run_script("/saves/yarpe/relapse.py")
    elif fw_version <= 10.01:
        log("[*] Selected exploit: lapse.py ( network not active )")
        sc.send_notification(
            "Selected exploit: lapse.py\n(network active: %s)" % has_net
        )
        run_script("/saves/yarpe/lapse.py")
    else:
        log("Unsupported firmware version for kexploit: " + sc.version)
        sc.send_notification(
            "Unsupported firmware version %s\n(network active: %s)"
            % (sc.version, has_net)
        )
        return

    if needs_elf_loader:
        log("[*] Current exploit requires elf_loader.py, loading...")
        run_script("/saves/yarpe/elf_loader.py")
    else:
        log("[*] Skipping elf_loader.py for this firmware...")

    log("[*] Waiting for elfldr to become active on port 9021...")
    from utils.tcp import is_port_open
    import time
    loader_active = False
    for _ in range(50):
        if is_port_open(9021):
            loader_active = True
            break
        time.sleep(0.200)

    if not loader_active:
        log("[!] Error: elfldr on port 9021 did not become active!")
        # If it doesn't become active, autoloader will probably fail when trying to connect.
    else:
        log("[+] elfldr is active on port 9021!")

main()
