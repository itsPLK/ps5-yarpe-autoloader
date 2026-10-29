### Installation on jailbroken PS5

#### Requirements:
1. A **jailbroken** PS5. There are plenty of jailbreak methods on firmwares up to 13.60, so this shouldn't be an issue.
2. A game from the [Game Compatibility](README.md#game-compatibility) table, with save data already created in the game.

#### Steps:

1. Download the savedata `.zip` from the [Releases](https://github.com/itsPLK/yarpe_autoloader/releases) page and unzip it.
2. Run the game once, create a save file in the game, then close the game.
3. Jailbreak the console and send [garlic-savemgr](https://github.com/earthonion/garlic-savemgr) to elfldr.
4. Open `http://<ps5-ip>:8082` in your PC browser.
5. Go to the **Browser** tab and select the game.
6. Drag and drop all the files from the unzipped folder into the garlic page, replacing the existing savedata files.
7. Click **Unmount** on the garlic page.
8. Run the game and check if the autoloader popup shows up.
    - The autoloader picks **Relapse** (FW 7.00–13.60, except 9.05) when a network interface is active, otherwise it falls back to **Lapse** (FW ≤ 10.01). `elfldr` is started by `kexp.bin`, and your payloads are loaded — from `autoload.txt` if configured, otherwise Payload Manager launches.
