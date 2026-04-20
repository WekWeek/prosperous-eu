# prosperous-eu
*⚠️ This is vibecoded — developed with AI assistance (Claude). It works, but treat it as a research starting point, not a polished tool.*

EU port of fail0verflow's prosperous PS4 save exploit, targeting Don't Starve Console Edition EU (CUSA00327).
The original exploit targets the US version (CUSA00158). This port adapts the injection method to work with the EU save format, which is structurally different.

Status

->Lua code execution confirmed on EU
-> "HELLO WORLD" proof of concept working
x Full kernel chain untested — EU binary likely has different libc offsets
x Requires PSN-connected account for Garlic Save resign


What's Different (US vs EU)
The US and EU versions have a fundamentally different save format:
US (CUSA00158)EU (CUSA00327)survival_1 formatLua script (executed directly)Lua data table (return {...})Injection methodOffset 0x158000 into containerReplace file with US-format scriptTemplatesurvival_1.lua with LUA_CODE_COOKIESame template, different deliveryps5tool neededYes (decrypt/encrypt/repair)No — Garlic Save handles it
Key discovery: the EU game engine will execute a US-format script file if you replace survival_1 entirely. The EU engine doesn't strictly enforce the table format — it just happens to ship saves in that format.

Requirements

Don't Starve Console Edition EU (CUSA00327) on PS4/PS5
Garlic Save account (PSN-connected for resign)
Python 3
kleipack.py from the original prosperous repo
A USB drive formatted for PS4 saves


Setup
prosperous-eu/
 ├─ make_eu.py          ← main script (this repo)
 ├─ kleipack.py         ← from original prosperous repo
 ├─ save_hax/
 │   ├─ survival_1.lua  ← from original prosperous repo
 │   └─ code.lua        ← from original prosperous repo
 └─ save/
     └─ SAVE/
         ├─ survival_1  ← decrypted EU save (from Garlic)
         ├─ saveindex
         ├─ profile
         └─ sce_sys/

Usage
Step 1 — Export your EU save
On your PS4/PS5:

Go to Settings → Application Saved Data Management
Copy Don't Starve (CUSA00327) save to USB
The USB will have: PS4/SAVEDATA/<userid>/CUSA00327/SAVE and SAVE.bin

Step 2 — Decrypt with Garlic Save

Go to garlicsave.com
Upload both SAVE and SAVE.bin together
Download the decrypted output
Extract into save/SAVE/

Step 3 — Build the exploit
bashpython3 make_eu.py
Output: build/survival_1_exploit
Step 4 — Resign and encrypt

Replace save/SAVE/survival_1 with build/survival_1_exploit
Upload the modified SAVE + original SAVE.bin to Garlic Save
Resign and encrypt
Download the result

Step 5 — Install and run

Copy the resigned save back to USB at PS4/SAVEDATA/<userid>/CUSA00327/SAVE
On PS4/PS5: Settings → Application Saved Data Management → Copy from USB
Launch Don't Starve and load your save slot
The exploit runs automatically on save load
Connect from your PC:

bashnc <PS4_IP> 6667

Troubleshooting
GetPersistentString error on load

Make sure you resigned with Garlic after replacing survival_1
Upload SAVE + SAVE.bin as a pair, not a zip

LOAD ERR message on screen

The base64 decoder failed — open an issue with the error text

Game crashes immediately

The exploit setup code ran but a primitive failed
The EU binary likely has different libc offsets (see below)

Game loads normally, nothing happens

The exploit ran but tcp_server() failed silently
Check your network connection and try port 6667


EU Binary Offsets (needs updating)
The code.lua payload uses hardcoded offsets for the US binary:
lualocal libc = get_file_ptr(io.stderr) - 0xCCE30
local libc_magic_str_ptr = 0xc9e98
local libc_magic_str = 0x9F004
These are almost certainly wrong for the EU binary. If the exploit crashes at runtime, these need to be found for the EU version of libkernel / libc.
To find them:

Get a memory dump from the EU binary
Search for the string "inappropriate io control operation"
Find the pointer to it (str_ptr)
Calculate offsets relative to io.stderr

If you find the correct EU offsets, please open a PR.

How It Works

The EU save (survival_1) is a kleipack-compressed Lua data table
We replace it entirely with a US-format kleipack-compressed Lua script
The EU game engine executes the script when loading the save slot
The script base64-decodes and runs code.lua via loadstring()
code.lua builds read/write primitives using Lua type confusion
A TCP server opens on port 6667 for remote Lua execution
From there, the full kernel chain from the original prosperous applies

For full technical details on the exploit primitives, see the original prosperous writeup.

Credits

fail0verflow — original prosperous exploit, all the hard work
This repo — EU format research and injection method, vibecoded with Claude


Disclaimer
For educational and research purposes only. Use on hardware you own.

Tested on digital copy of Dont Starve Console Edition. PS5 version 12.70
