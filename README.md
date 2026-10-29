<h1 align="center">ps5 yarpe autoloader</h1>
<h3 align="center">Fork of <a href="https://github.com/Helloyunho/yarpe">yarpe</a></h3>
&nbsp;
<p align="center">Automatically loads your .elf payloads.<br>Supports PS5 firmwares up to 13.60.</p>

<p align="center">
    <b>Other Autoloaders:</b><br>
    <a href="https://github.com/itsPLK/ps5-y2jb-autoloader">Y2JB</a> | 
    <a href="https://github.com/itsPLK/ps5-bdjb-autoloader">BD-JB</a> | 
    <a href="https://github.com/itsPLK/ps5-webkit-autoloader">WebKit</a>
</p>

## How to use

There are two ways to use the autoloader:

### 🟢 Option 1: Payload Manager

If no `autoload.txt` config is found, the autoloader will automatically launch **[Payload Manager](https://github.com/itsPLK/ps5-payload-manager)** — a fully-featured PS5 payload manager with a web UI. This lets you configure and send payloads directly from your browser, without needing to manually set up config files or transfer ELF files ahead of time.

Just run the autoloader — if there's nothing configured, Payload Manager starts automatically.

> **Note:** Payload Manager also has its own built-in autoload feature, which lets you configure payloads to load automatically on startup — all managed through its web UI. This is separate from the `autoload.txt` mechanism described below.

---

### ⚙️ Option 2: Manual Config (`autoload.txt`)

For a fixed, automated payload chain, you can configure payloads manually:

* Create a directory named `ps5_autoloader`.
* Inside this directory, place your `.elf` files, and an `autoload.txt` file.
    * In autoload.txt, list the files you want to load (one per line).
    * Filenames are case-sensitive - make sure the names exactly match your files.
    * You can add lines like `!1000` to make the loader wait 1000ms before sending the next payload.
* Put the `ps5_autoloader` directory in one of these locations:
    * In the root of a USB drive
    * In the internal drive at `/data/ps5_autoloader`
* Import savedata to your game:  
  Follow the steps in [SETUP.md](SETUP.md) to import the savedata for your Ren'Py-compatible game.

> **Note:** When an `autoload.txt` config is found, Payload Manager is **not** launched automatically. If you also want Payload Manager available, place `pldmgr.elf` in your `ps5_autoloader` directory and add it to `autoload.txt`.

> [!NOTE]
> **Exploit Selection & Network Requirements:**
> - **Relapse (FW 7.00–13.60)** requires an active network interface (Wi-Fi or Ethernet connected to a local network; Internet access is not required).
> - On FW 7.00–13.60 (except 9.05), Relapse is used when an active network interface is detected.
> - If offline, the autoloader automatically falls back to **Lapse** (FW ≤ 10.01). On FW 10.20–13.60, an active network interface is required.

---

### Installation

Requirements:
1. A **jailbroken** PS5. There are plenty of jailbreak methods on firmwares up to 13.60, so this shouldn't be an issue.
2. A game from the [Game Compatibility](#game-compatibility) table, with save data already created in the game.

Steps:
1. Download the savedata `.zip` from the [Releases](https://github.com/itsPLK/yarpe_autoloader/releases) page and unzip it.
2. Use [garlic-savemgr](https://github.com/earthonion/garlic-savemgr) to replace the game's savedata files with the files from the unzipped folder.
3. Run the game. The savedata triggers the exploit, the kernel exploit runs, `elfldr` starts, and the autoloader loads your payloads — from `autoload.txt` if configured, otherwise Payload Manager launches in the browser.

Detailed steps are in [SETUP.md](SETUP.md).

## Game Compatibility

Currently this autoloader is compatible with the following games:

| Game Title                                   | TITLE ID                        |
|----------------------------------------------|---------------------------------|
| A YEAR OF SPRINGS (PS4)                      | CUSA30428, CUSA30429, CUSA30430, CUSA30431 |
| Arcade Spirits: The New Challengers (PS4)    | CUSA32096, CUSA32097            |
| Arcade Spirits: The New Challengers (PS5)    | PPSA06409, PPSA06410            |

## Updating Savedata

If you have the savedata setup and want to update the files, please refer to [UPDATE.md](UPDATE.md).

## Building from source

The `ps5-elfldr`, `ps5-kexp` and `ps5-unified-autoloader` binaries are git submodules under `third_party/`, pinned to specific commits. They are built or downloaded at build time and are never committed here.

1. Clone with submodules: `git clone --recursive` (or run `git submodule update --init --recursive` in an existing clone).
2. Run `./build.sh`:
   - `--dev` / `--stable` select the release versioning style.
   - `--download-deps` (`-d`) downloads prebuilt release binaries matching the pinned submodule versions.
   - `--build-deps` (`-b`) builds `third_party/ps5-elfldr`, `third_party/ps5-kexp` and `third_party/ps5-unified-autoloader` from their sources (each needs its own toolchain/Docker SDK).
   - With no dep flag, existing binaries are kept, submodules are used to build if checked out, otherwise deps are downloaded.
3. The result is `ps5-yarpe-autoloader-<version>.zip` containing:
   - `save.zip`: all individual files (pickled savedata).
   - `1-1-LT1.save`: unified unzipper that extracts all files automatically.

The build script stages `payloads/` scripts into `src/`, bakes the versioned dependency filenames (`elfldr-ps5-<ver>.elf`, `kexp-<ver>.bin`) into them, generates `autoload.txt`, then runs `pack_savegame.py` and `pack_unzipper.py` via `make`.

## Additional Info

- The full Python API reference for writing payloads is in [API.md](API.md).
- `payloads/force_persistent.py` loads the save file automatically on game start; `pack_savegame.py` writes a `persistent` trigger that re-arms itself, so the autostart survives closing and reopening the game.

## Credits

* Helloyunho – creator of the original [yarpe](https://github.com/Helloyunho/yarpe)
* shahrilnet – creator and maintainer of [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
* DavidBuchanan314 – [unsafe-python](https://github.com/DavidBuchanan314/unsafe-python)
* [@Gezine](https://github.com/Gezine)
* [@DrYenyen](https://github.com/DrYenyen) – testing yarpe
* and everyone else who helped!

## Disclaimer

This tool is provided as-is for research and development purposes only. Use at your own risk. The developers are not responsible for any damage, data loss, or consequences resulting from the use of this software.

## License

This project is licensed under the **Apache-2.0 License** (the license of the original yarpe).

## Donate
- [donate to PLK](DONATE.md)
