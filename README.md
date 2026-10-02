[![Build status](https://github.com/dioxtra/SniffCraft-Wireshark/actions/workflows/automatic_release.yml/badge.svg)](https://github.com/dioxtra/SniffCraft-Wireshark/actions/workflows/automatic_release.yml)
[![Download](https://img.shields.io/badge/download-latest%20release-blue)](https://github.com/dioxtra/SniffCraft-Wireshark/releases/tag/latest)
[![Minecraft](https://img.shields.io/badge/Minecraft-1.8%20%E2%86%92%2026.3-62B47A)](#choosing-the-minecraft-version)
[![Wireshark](https://img.shields.io/badge/Wireshark-4.3%2B-1679A7)](https://www.wireshark.org/)
[![License](https://img.shields.io/badge/license-GPL--3.0-lightgrey)](LICENSE)

# SniffCraft-Wireshark

**See Minecraft Java Edition packets in Wireshark, live, from 1.8 to 26.3, online-mode servers included.**

This is a fork of [SniffCraft](https://github.com/adepierre/SniffCraft) by [adepierre](https://github.com/adepierre), a proxy that sits between a Minecraft client and a server and decodes everything they exchange (encryption, compression, every packet field). This fork plugs it into [Wireshark](https://www.wireshark.org/): SniffCraft becomes a capture interface, and Minecraft dissectors let you filter, search, color and inspect the packets byte by byte with all the Wireshark tools.

![Chat packets of a live capture in Wireshark, with the fields parsed by SniffCraft and by minecraft-data](docs/wireshark.png)

```
    ┌────────┐       ┌──────────────┐       ┌────────┐
    │ Client ├───────►  SniffCraft  ├───────► Server │
    │        ◄───────┤   (extcap)   ◄───────┤        │
    └────────┘       └──────┬───────┘       └────────┘
                            │ decrypted, decompressed and parsed packets
                            ▼
                ┌──────────────────────┐
                │      Wireshark       │
                │ sniffcraft.lua       │
                │ minecraft.lua        │
                └──────────────────────┘
```

## Features

- **Live capture interface**: *SniffCraft Minecraft proxy* appears in the Wireshark interface list, start it and connect your client to it
- **28 Minecraft versions in one install**, from 1.8.9 to 26.3, chosen in the capture options
- **Online-mode servers** work: SniffCraft logs in with your Microsoft account, so even encrypted traffic is readable
- **Every field decoded** and filterable (``sniffcraft.field contains "diamond"``), with the matching bytes highlighted in the packet bytes pane
- **A second, independent parser** based on [minecraft-data](https://github.com/PrismarineJS/minecraft-data) shown next to SniffCraft's, which also decodes raw TCP captures of offline-mode and LAN servers without any proxy
- **``.pcapng`` export** of SniffCraft sessions, to share them or open them later
- Packets SniffCraft fails to parse are kept with their raw bytes instead of being dropped

![Every packet containing "diamond": recipes with their nested ingredients, and the matching bytes](docs/wireshark-fields.png)

## Quick start

### Windows

1. Download ``sniffcraft-wireshark-windows.zip`` from the [latest release](https://github.com/dioxtra/SniffCraft-Wireshark/releases/tag/latest) and extract it.
2. Run ``install.ps1`` (right click > *Run with PowerShell*, or ``powershell -ExecutionPolicy Bypass -File install.ps1``). It copies SniffCraft to your personal Wireshark extcap folder and the dissectors to your personal Lua plugins folder.
3. Restart Wireshark, click on the gear icon next to **SniffCraft Minecraft proxy**, choose your Minecraft version and the server address, then start the capture and connect your client to ``localhost:25555``.

### Linux and other platforms

Download ``sniffcraft-wireshark-linux.zip`` (Linux) or ``sniffcraft-wireshark.zip`` (dissectors only, with the SniffCraft binary of your platform from the same release) and copy the files in the folders listed in Wireshark ``Help > About Wireshark > Folders``:
- ``sniffcraft`` and the ``sniffcraft_versions`` folder go in *Personal Extcap path*
- ``sniffcraft.lua``, ``minecraft.lua`` and the ``minecraft_mcdata`` folder go in *Personal Lua Plugins*

## Usage

### Live capture

The capture options (gear icon) contain the Minecraft version, the server address, the local port SniffCraft listens on (default 25555) and a few logging options. Starting the capture starts the proxy, stopping it stops the proxy.

<img src="docs/capture-options.png" alt="SniffCraft capture options in Wireshark" width="500">

**Tip:** write the server address with its port (``play.example.com:25565``). Without a port SniffCraft first looks for a DNS SRV record, which can take a while if the DNS server doesn't answer.

### Online-mode servers

Enable the ``Online mode`` option and log in once with your Microsoft account by running the SniffCraft copy that is in the extcap folder from a terminal:

```
"%APPDATA%\Wireshark\extcap\sniffcraft.exe" --extcap-login
```

The credentials are cached next to it and reused by every capture. Your client can then connect to SniffCraft with any account, see [Encryption](#encryption) for the details and the 1.19 - 1.19.2 exception.

### Choosing the Minecraft version

SniffCraft is compiled for one protocol version at a time. The version list contains the version of the ``sniffcraft`` executable in the extcap folder plus every ``sniffcraft-<version>`` build of the ``sniffcraft_versions`` folder next to it. Each build covers all the game versions sharing its protocol, for example the 1.21.10 build also works with 1.21.9. Pick the version of your client: on servers translating between versions (ViaVersion), that is the one that matters.

### Capture files

Set ``LogToPcapng`` to true in the SniffCraft conf file to also save each session in a ``XXXX.pcapng`` file. ``PcapngIncludeJson`` adds the full json of each packet (bigger files, enables ``json.*`` filters) and ``PcapngRespectFilters`` applies the ignored lists of the conf file to the capture (by default every packet is saved and filtering is done in Wireshark). The live capture has the same options.

### Display filters

```
sniffcraft.name == "System Chat"
sniffcraft.direction == "serverbound" && sniffcraft.state == 3
sniffcraft.name contains "Custom Payload"
sniffcraft.field.path == "change.position[0]"
sniffcraft.field contains "diamond"
sniffcraft.flags.parse_error == True
minecraft.packet_name == "map_chunk"
```

Movement, entity and chunk packets are most of the traffic, hiding them makes the interesting ones stand out:

```
!(sniffcraft.name in {"Set Entity Motion", "Move Entity Pos", "Move Entity PosRot", "Move Entity Rot", "Rotate Head", "Entity Position Sync", "Teleport Entity", "Set Entity Data", "Update Attributes", "Level Chunk With Light", "Light Update", "Bundle", "Set Time", "Keep Alive", "Move Player Pos", "Move Player PosRot", "Move Player Rot", "Move Player Status Only"})
```

### Raw TCP traffic

``minecraft.lua`` decodes unencrypted Minecraft traffic on TCP ports 25565 and 25555 (configurable in the *Minecraft Java* protocol preferences): offline-mode and LAN servers, or the client side of a SniffCraft session captured on the loopback interface. Online-mode traffic is encrypted after the login and can only be read through SniffCraft.

## How it works

- SniffCraft writes each packet as a pcapng record (``LINKTYPE_WIRESHARK_UPPER_PDU``) with its connection state, direction, raw bytes and parsed fields. The format is documented at the top of [sniffcraft.lua](wireshark/sniffcraft.lua).
- When Wireshark starts a capture, it runs SniffCraft as an [extcap](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html) program which streams these records through a pipe. If another Minecraft version is selected, the matching build of ``sniffcraft_versions`` is started instead.
- [minecraft.lua](wireshark/minecraft.lua) is a generic interpreter of the minecraft-data protocol definitions, converted to Lua tables by [tools/gen_mcdata.py](tools/gen_mcdata.py).

## Building from source

```
git clone --recursive https://github.com/dioxtra/SniffCraft-Wireshark.git
cd SniffCraft-Wireshark
cmake -B build -DGAME_VERSION=1.21.10 -DSNIFFCRAFT_WITH_ENCRYPTION=ON
cmake --build build --config Release
```

Then:
- ``python tools/build_versions.py`` builds SniffCraft for all the supported versions in ``dist/sniffcraft_versions`` (or only the versions given as arguments, about two minutes each)
- ``powershell -ExecutionPolicy Bypass -File wireshark\install.ps1`` installs ``bin\sniffcraft.exe``, these builds and the dissectors
- ``python tools/gen_mcdata.py --ref master`` regenerates the minecraft-data definitions, for example after a new Minecraft release

Bug reports and ideas about the Wireshark integration are welcome in the [issues](https://github.com/dioxtra/SniffCraft-Wireshark/issues) of this repository.

## Standalone SniffCraft

Everything from the original SniffCraft still works without Wireshark: GUI, text and binary logs, replay mod captures. The rest of this page is the original documentation.

<img width="750" src="https://github.com/user-attachments/assets/49d46827-2001-4607-8b6b-b496c73f95bc" alt="Sniffcraft GUI" align="center">

### Proxy features

- Supported minecraft versions: all official releases from 1.8 to 26.3
- GUI mode
- Packet logging with different levels of details (ignore packet, log packet name only, log full packet content)
- Detailed network usage recap
- Compression is supported
- Byte level packet inspection
- Offline ("cracked") mode and online mode (with Microsoft account) are supported
- Secure chat is supported
- Logging raw packets at byte level
- Configuration (which packet to log/ignore) can be changed on-the-fly without restarting
- Automatically create a session file to log information, can also optionally log to console at the same time
- Save full session to binary file and reopen them later in the GUI
- Creating a [replay mod](https://github.com/ReplayMod/ReplayMod) capture of the session is also possible, see [Replay Mod section](#replay-mod) for more details
- No log at all is possible, in this case, SniffCraft becomes a pure proxy that you can adapt to block/modify any packet you want
- 1.20.5+ transfer packets are supported

### Encryption

Encryption is supported by moving the authentication step from the client to Sniffcraft. This means that all the traffic from the client to Sniffcraft is not encrypted, but the traffic between Sniffcraft and the server is.

There are two options in the conf file regarding authentication. ``Online`` must be true to connect to a server with authentication activated. SniffCraft will prompt you instructions on the console to log in with a Microsoft account (only the first time, will use cached credentials for the next ones, you can cache multiple Microsoft accounts using different ``MicrosoftAccountCacheKey``).

Depending on the version you are using, there are additional restrictions regarding authentication:
- for versions up to 1.18.2 and 1.19.3+, you can use any client you want ("cracked" or regular with any account) as long as you are authenticated with a valid account in sniffcraft.
- for versions 1.19 to 1.19.2, there are two subcases:
    - if the server has the option `enforce-secure-profile` set to false, then it's the same as for the other versions, you can use any client you want.
    - if the server has the option `enforce-secure-profile` set to true, then you **must** use a client authenticated with the **same** account you are using in Sniffcraft. Otherwise you will be kicked out for signing key mismatch as soon as you try to send a chat message.

If you want to be sure Sniffcraft is using the latest certificates for your account (for 1.19+ versions), you can set botcraft_cached_credentials\["TheMicrosoftAccountCacheKeyYouSet"\]\["certificates"\]\["expires_date"\] to 0 and Sniffcraft will then retreive the latest ones from Mojang server.

### Mod support

Sniffcraft has been confirmed to work with heavily modded client/server using Forge. It is however not regularly tested against all possible modded environments and some adjustments might be required in some cases.

If you want to print the content of Custom Payload packets (both from client and server), you need to use protocolCraft plugins to extend the protocol knowledge with mod-specific packets. See the [protocolCraft-plugin](https://github.com/adepierre/protocolcraft-plugin) repo for details.

### GUI support

If compiled with the cmake option SNIFFCRAFT_WITH_GUI, a GUI will appear when starting SniffCraft. This can be disabled by launching it with the ``--headless`` command line argument. In GUI mode, packets data are kept in memory while the session is displayed in GUI. This is usually not really an issue for regular usecase. However, if you plan to do some multi-hours long capture sessions or have a lot of sessions running simultaneously, it is recommended to use the ``--headless`` argument (or SniffCraft compiled without GUI enabled). This way, all data will only be stored in files and not in the RAM. SniffCraft binary files (**NOT** text files) can be reimported later in the GUI by simply dragging them onto SniffCraft window.

### Dependencies

You don't have to install any dependency to build SniffCraft, everything that is not already on your system will be automatically downloaded and locally built during the build process.

- [asio](https://think-async.com/Asio/)
- [zlib](https://github.com/madler/zlib)
- [openssl](https://www.openssl.org/) (optional, only if cmake option SNIFFCRAFT_WITH_ENCRYPTION is set)
- [botcraft](https://github.com/adepierre/botcraft)

GUI dependencies (only if cmake option SNIFFCRAFT_WITH_GUI is set)
- [glad](https://github.com/Dav1dde/glad)
- [glfw](https://github.com/glfw/glfw)
- [Dear ImGui](https://github.com/ocornut/imgui)

### Build and launch

Precompiled binaries for the latest game version with encryption and GUI support can be found in the [latest release](https://github.com/dioxtra/SniffCraft-Wireshark/releases/tag/latest). To build it yourself, see [Building from source](#building-from-source).

Once built, you can start SniffCraft by double clicking the executable (by default, compiled executable file can be found in ``bin`` folder next to the source code), or with the following command line:

```
sniffcraft <optional:--headless> <optional:conf/file/path>
```

conf/file/path is the path to a json file, and can be used to set authentication information and filter out the packets. Examples can be found in the [conf](conf/) directory. If no path is given, a default conf.json file will be created. With the default configuration, only the names of the packets are logged. When a packet is added to an ignored list, it won't appear in the logs, when it's in a detail list, its full content will be logged. Packets can be added either by id or by name (as registered in protocolCraft), but as id can vary from one version to another, using names is safer.

ServerAddress should match the address of the server you want to connect to, with the same format as in a regular minecraft client. Custom URL with DNS SRV records are supported (like MyServer.Example.net for example). You can then connect your official minecraft client to SniffCraft as if it were a regular server using <your computer IP:LocalPort>. If you are running SniffCraft on the same computer as your client, something like 127.0.0.1:LocalPort should work.

### Replay Mod

If ``LogToReplay`` is present and set to true in the configuration file when the session starts, all packets will also be logged in a format compatible with [replay mod](https://github.com/ReplayMod/ReplayMod). When the capture stops, you'll get a ``XXXX.mcpr`` file that can be opened by the replay mod viewer inside minecraft. Note that this is a compressed format. It may take a few seconds after the connection is closed for this file to be created correctly. Make sure you don't close SniffCraft during this time.

The current player will **not** appear on this capture, as the replay mod artificially adds some packets to display it.

## Credits and license

- [SniffCraft](https://github.com/adepierre/SniffCraft), [Botcraft and protocolCraft](https://github.com/adepierre/Botcraft) by adepierre. The original project has a [community Discord server](https://discord.gg/wECVsTbjA9) and a [video tutorial](https://youtu.be/wXOD41jI_Rg) about SniffCraft itself, please report issues with the Wireshark integration here rather than there.
- The protocol definitions used by ``minecraft.lua`` are generated from [PrismarineJS/minecraft-data](https://github.com/PrismarineJS/minecraft-data) (MIT), see [wireshark/minecraft_mcdata](wireshark/minecraft_mcdata/README.md).
- This project is licensed under the GPL v3, like the original SniffCraft.

Not an official Minecraft product. Not approved by or associated with Mojang or Microsoft.
