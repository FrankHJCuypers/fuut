[![maintainer](https://img.shields.io/badge/maintainer-Frank%20HJ%20Cuypers-green?style=for-the-badge&logo=github)](https://github.com/frankhjcuypers)
[![GitHub Discussions](https://img.shields.io/github/discussions/FrankHJCuypers/fuut?style=for-the-badge&logo=github)](https://github.com/FrankHJCuypers/fuut/discussions)
[![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/FrankHJCuypers/fuut?style=for-the-badge&logo=github)](https://github.com/FrankHJCuypers/fuut/issues)

[![Lua](https://img.shields.io/badge/Lua-2C2D72?style=for-the-badge&logo=lua)](https://www.lua.org/)
[![Static Badge](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark)](https://www.wireshark.org/)

[![experimental](https://img.shields.io/badge/version-experimental-red)](https://kotlinlang.org/docs/components-stability.html#stability-levels-explained)

[![GitHub Release](https://img.shields.io/github/v/release/FrankHJCuypers/fuut?include_prereleases&display_name=tag&logo=github)](https://github.com/FrankHJCuypers/fuut/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date-pre/FrankHJCuypers/fuut?logo=github)](https://github.com/FrankHJCuypers/fuut/releases)
[![GitHub License](https://img.shields.io/github/license/FrankHJCuypers/fuut?logo=github)](LICENSE)

[![GitHub last commit](https://img.shields.io/github/last-commit/FrankHJCuypers/fuut?logo=github)](https://github.com/FrankHJCuypers/fuut/commits)
[![GitHub contributors](https://img.shields.io/github/contributors/FrankHJCuypers/fuut?logo=github)](https://github.com/FrankHJCuypers/fuut/graphs/contributors)
[![GitHub commit activity (master)](https://img.shields.io/github/commit-activity/y/FrankHJCuypers/fuut/master?logo=github)](https://github.com/FrankHJCuypers/fuut/commits/master)


# Wireshark Dissector in Lua for Nexxtender charger BLE

The goal of this dissector is to dissect the specific BLE GATT messages that are exchanged,
according to 
[Nexxtender Charger Information](https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information).
It was developed based on the [Gaai app project](https://frankhjcuypers.github.io/Gaai/)

## Fuut?

Choosing a short distinctive name for a project is always difficult.
A bird name was chosen.
[Fuut](https://nl.wikipedia.org/wiki/Fuut) is Dutch for the
[Great crested grebe](https://en.wikipedia.org/wiki/Great_crested_grebe).

# Features

- Only requires [Wireshark](https://www.wireshark.org/)
- No build required.

# Installing 
Make sure that Wireshark is already installed.
Copy the `fuut.lua` file to one of Wiresharks lua script directories.
In Wireshark, open Help->About->Folders.
Any of the directories that includes *Lua scrips* in the *Typical files* directory will do.
I use the *Personal Lua Plugins* directory thyat expands to 
`C:\Users\Frank\AppData\Roaming\Wireshark\plugins` on my PC.

It also helps to configure The BLE names and characteristics as explained in 
[Wireshark: add Nexxtender Home BLE UUIDs](https://github.com/FrankHJCuypers/Gaai/wiki/Analyzing-Bluetooth-Low-Energy-Traffic#add-nexxtender-home-ble-uuids).

# Usage

The `fuut.lua` dissector parses all Wireshark BT ATT messages that are linked to the Nexxtender charger
and adds the parsed result to the Wireshark Packet Details view.

The following messages are already parsed by `fuut.lua`:

| Protocol  | Service  | Characteristic         | Type                    |
| --------- | -------- | ---------------------- | ----------------------- |
| NEXXT_CBD | CHARGING | CHARGING_BASIC_DATA    | NA                      |
| NEXXT_CGD | CHARGING | CHARGING_GRID_DATA     | NA                      |
| NEXXT_CCD | CHARGING | CHARGING_CAR_DATA      | NA                      |
| NEXXT_CAD | CHARGING | CHARGING_ADVANCED_DATA | NA                      |
| NEXXT_GC  | GENERIC  | COMMAND                |                         |
| NEXXT_GCL | GENERIC  | COMMAND                | Loader                  |
| NEXXT_GCE | GENERIC  | COMMAND                | Event                   |
| NEXXT_GCM | GENERIC  | COMMAND                | Metric                  |
| NEXXT_GCB | GENERIC  | COMMAND                | Badge                   |
| NEXXT_GCT | GENERIC  | COMMAND                | Time                    |
| NEXXT_GCC | GENERIC  | COMMAND                | Config                  |
| NEXXT_GS  | GENERIC  | STATUS                 |                         |
| NEXXT_GSL | GENERIC  | STATUS                 | Loader                  |
| NEXXT_GSE | GENERIC  | STATUS                 | Event                   |
| NEXXT_GSM | GENERIC  | STATUS                 | Metric                  |
| NEXXT_GSB | GENERIC  | STATUS                 | Badge                   |
| NEXXT_GST | GENERIC  | STATUS                 | Time                    |
| NEXXT_GSC | GENERIC  | STATUS                 | Config                  |
| NEXXT_GD  | GENERIC  | DATA                   |                         |
| NEXXT_GDL | GENERIC  | DATA                   | Loader                  |
| NEXXT_GDE | GENERIC  | DATA                   | Event                   |
| NEXXT_GDM | GENERIC  | DATA                   | Metric                  |
| NEXXT_GDB | GENERIC  | DATA                   | Badge                   |
| NEXXT_GDT | GENERIC  | DATA                   | Time                    |
| NEXXT_GDC | GENERIC  | DATA                   | Config 1.0, 1.1 and CBOR|

The following messages are not yet parsed by `fuut.lua`:

| Protocol  | Service  | Characteristic         | Type        |
| --------- | ---------| ---------------------- | ----------- |
| NEXXT_GDC | GENERIC  | DATA                   | Config CBOR |
| NEXXT_CC  | CDR      | COMMAND                | NA          |
| NEXXT_CS  | CDR      | STATUS                 | NA          |
| NEXXT_CR  | CDR      | RECORD                 | NA          |
| NEXXT_DC  | CCDT     | COMMAND                | NA          |
| NEXXT_DS  | CCDT     | STATUS                 | NA          |
| NEXXT_DR  | CCDT     | RECORD                 | NA          |
| NEXXT_FC  | FIRMWARE | COMMAND                | NA          |
| NEXXT_FS  | FIRMWARE | STATUS                 | NA          |
| NEXXT_FW  | FIRMWARE | WANTED_CHUNK           | NA          |
| NEXXT_FD  | FIRMWARE | DATA_CHUNK             | NA          |

The type of message is shown in the *Protocol* column of the Wireshark Packet List view.

The values parsed by the `fuut.lua` dissector are shown in the Wireshark Packet Details view,
under the node *Bluetooth Attribute Protocol*, 
under the subnode that starts with *Nexxtender*.

For messages with a CRC, the CRC is verified and flagged as an error when wrong;
the CRC line will show red and a message is attached stating that the CRC is wrong, 
inlcuding the correct CRC.

The NEXXT-\* protocol messages can be filtered out in Wireshark by the following view filter: `_ws.col.protocol contains "NEXXT_"`

For more information on the Nexxtender BLE protocol, see 
[Nexxtender Charger Information, Frank HJ Cuypers](https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information).
The `fuut.lua` dissector uses the names and values from that document.

# Internals

`fuut.lua` extends the Wireshark btgatt dissector from
[packet-btatt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-btatt.c?ref_type=heads).
It adds dissectors to the *bluetooth.uid* table defined in *proto_reg_handoff_btgatt()*.



# Links

Useful information can be found at

- [Nexxtender Charger Information, Frank HJ Cuypers](https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information)
- [Wireshark](https://www.wireshark.org/)
- [Creating a Wireshark dissector in Lua](https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
- [Gaai app project](https://frankhjcuypers.github.io/Gaai/)
- [Gaai app github](https://github.com/FrankHJCuypers/Gaai)
# License

This project is licensed under the GNU AGPLv3 License. See the [LICENSE](LICENSE) file for details.



