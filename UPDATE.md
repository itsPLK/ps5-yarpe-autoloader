### Update your existing savedata

Since installation already requires a jailbroken console, updating savedata is done with [garlic-savemgr](https://github.com/earthonion/garlic-savemgr):

1. Jailbreak the console and send garlic-savemgr to elfldr.
2. Open `http://<ps5-ip>:8082` in your PC browser, go to the **Browser** tab and select the game.
3. Delete the old savedata files you want to replace, then drag and drop the new files from the release zip.
4. Click **Unmount** on the garlic page, then run the game.

> [!WARNING]
> Do not delete the `sce_sys` directory. Any other file or directory is fine to replace.
> Always unmount the save in garlic-savemgr before launching the game, otherwise the save can be corrupted.
