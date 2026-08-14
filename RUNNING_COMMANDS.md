# Running the commands — and fixing what trips students up

Every lab in this kit is written as **Read → Do → Check**: a **Read** tells you *why*, each **Do** is *one action* (either **⌨ Type** a command or **🖱 Click** a menu path), and the **Check** tells you what you should see. This page is how to actually *run* the Do steps — and what to do when something doesn't work.

## The one thing that removes copy‑paste: the `lab` runner

The curriculum's terminal steps each have a short token. **You type the token; it prints the real command, runs it, and shows the expected output.** No copy‑paste, and you still learn the command.

> **Do · Type** — see every step, then run one:
>
> ```bash
> lab list        # all tokens, grouped by level
> lab l1          # runs Level 1's first command (or just type: l1)
> lab reset       # restart the loopback lab if traffic stops
> lab open        # print the Learning Path + noVNC URLs
> ```

`l1` is a shortcut for `lab l1`. If a bare `l1` ever says *command not found* (a brand‑new shell that didn't load the aliases), use the full `lab l1`, or run `source lab/aliases.sh` once. `lab` works from anywhere in the repo.

## Two terminals, two jobs

There are two places to type, and they behave differently — use the right one:

| | Use it for | Paste |
|---|---|---|
| **VS Code terminal** (the panel at the bottom of the editor) | Every `⌨ Type` command — `lab l1`, `tshark …`, `docker compose …` | **Ctrl/Cmd + Shift + V** (the browser asks for clipboard permission the first time — allow it) |
| **noVNC desktop** (port **6080**) | The **Wireshark GUI** — the `🖱 Click` steps (menus, filters, columns) | Don't paste here — the remote desktop can't take your clipboard. Type short filters (`mqtt`, `dnp3`) directly, and run *commands* in the VS Code terminal instead |

Because the `lab` tokens are two keystrokes, you never need to paste a long command into either terminal.

## The noVNC desktop (port 6080)

Open the forwarded port **6080** from the Ports panel. It opens **straight to the desktop — there is no password prompt** — and **Wireshark is already running and capturing on `lo`**, pre‑filtered to the lab's ports (1883 / 20000). Apply a display filter (`mqtt`, then `dnp3`) in the green bar to watch each protocol.

*(The desktop feature does set a VNC password of `vscode` under the hood, but the browser connects for you, so you won't be asked. If a prompt ever does appear, the password is `vscode`.)*

## When something's wrong

- **No packets / Wireshark looks frozen** → the loopback services may have stopped. Run `lab reset` (restarts the broker, outstation, and telemetry), then re‑apply your filter.
- **`l1: command not found`** → use `lab l1`, or run `source lab/aliases.sh` in that terminal once.
- **A `tshark` command prints nothing** → check you're at the repo root (`/workspaces/ics_lab`) so the `pcaps/…` paths resolve, and that the filter is spelled exactly as shown in the step.
- **Port didn't forward** → open the **Ports** tab in VS Code; the labelled ports are **▶ Learning Path (8080)**, **noVNC Desktop (6080)**, **MQTT broker (1883)**, **DNP3 outstation (20000)**. The three twin ports (1881 / 3000 / 8088) only appear once you launch the digital twin.
- **The digital twin** uses plain `docker compose` / `bash lab/twin/launch-twin.sh` (there's no `lab` token for it). Those commands *do* need the Copy button or **Ctrl/Cmd+Shift+V**, run from `lab/twin/`.

## What the step labels mean

- **📖 Read** — background. Nothing to do; just understand it before you act.
- **⌨ Do · Type** — type the short token (or the shown command) in the **VS Code terminal**.
- **🖱 Do · Click** — click the exact path shown, in **Wireshark** (noVNC desktop) or VS Code.
- **✓ Check** — the result you should see. If you don't see it, the Check tells you the fix (usually `lab reset`).
